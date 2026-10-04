//! Client authentication, code exchange and replay revocation.
use super::*;

#[cfg(target_arch = "wasm32")]
pub(super) fn decode_basic_component(input: &str) -> Option<String> {
    let mut result = Vec::with_capacity(input.len());
    let mut bytes = input.bytes();
    while let Some(byte) = bytes.next() {
        match byte {
            b'+' => result.push(b' '),
            b'%' => {
                let digit = |value: u8| match value {
                    b'0'..=b'9' => Some(value - b'0'),
                    b'a'..=b'f' => Some(value - b'a' + 10),
                    b'A'..=b'F' => Some(value - b'A' + 10),
                    _ => None,
                };
                let high = digit(bytes.next()?)?;
                let low = digit(bytes.next()?)?;
                result.push(high * 16 + low);
            }
            _ => result.push(byte),
        }
    }
    String::from_utf8(result).ok()
}

#[cfg(target_arch = "wasm32")]
pub(super) fn basic_credentials(header: &str) -> worker::Result<(String, String)> {
    let (scheme, encoded) = header
        .split_once(' ')
        .ok_or_else(|| worker::Error::RustError("invalid_client".into()))?;
    if !scheme.eq_ignore_ascii_case("Basic") || encoded.len() > 1024 {
        return Err(worker::Error::RustError("invalid_client".into()));
    }
    let decoded = STANDARD
        .decode(encoded)
        .map_err(|_| worker::Error::RustError("invalid_client".into()))?;
    let decoded = std::str::from_utf8(&decoded)
        .map_err(|_| worker::Error::RustError("invalid_client".into()))?;
    let (id, secret) = decoded
        .split_once(':')
        .ok_or_else(|| worker::Error::RustError("invalid_client".into()))?;
    let id = decode_basic_component(id)
        .ok_or_else(|| worker::Error::RustError("invalid_client".into()))?;
    let secret = decode_basic_component(secret)
        .ok_or_else(|| worker::Error::RustError("invalid_client".into()))?;
    Ok((id, secret))
}

#[cfg(target_arch = "wasm32")]
pub(super) fn secret_form(body: &str) -> worker::Result<SecretTokenForm> {
    serde_urlencoded::from_str(body).map_err(|_| worker::Error::RustError("invalid_request".into()))
}

#[cfg(target_arch = "wasm32")]
pub(super) async fn authenticate_secret_token_request(
    db: &worker::d1::D1Database,
    form: SecretTokenForm,
    header: Option<&str>,
    token_endpoint: &str,
    now: u64,
    policy: &WorkerRuntimePolicy,
    random: &mut impl mikaki_oidc::CryptographicRandom,
) -> worker::Result<AuthenticatedTokenRequest> {
    use wasm_bindgen::JsValue;

    let (client_id, secret, method) = if let Some(header) = header {
        if form.client_secret.is_some() {
            return Err(worker::Error::RustError("invalid_request".into()));
        }
        let (id, secret) = basic_credentials(header)?;
        if form
            .client_id
            .as_deref()
            .is_some_and(|body_id| body_id != id)
        {
            return Err(worker::Error::RustError("invalid_client".into()));
        }
        (id, secret, "client_secret_basic")
    } else {
        let id = form
            .client_id
            .ok_or_else(|| worker::Error::RustError("invalid_client".into()))?;
        let secret = form
            .client_secret
            .ok_or_else(|| worker::Error::RustError("invalid_client".into()))?;
        (id, secret, "client_secret_post")
    };
    if client_id.is_empty()
        || client_id.len() > 128
        || client_id.bytes().any(|byte| byte.is_ascii_control())
        || !(32..=256).contains(&secret.len())
    {
        return Err(worker::Error::RustError("invalid_client".into()));
    }
    let row = db
        .prepare(
            "SELECT c.revision AS client_revision,s.revision AS secret_revision,c.auth_method,s.secret_hash,c.allow_missing_pkce \
             FROM client c JOIN client_secret s ON s.client_id=c.client_id \
             WHERE c.client_id=?1 AND c.active=1 AND s.active=1 LIMIT 1",
        )
        .bind(&[JsValue::from_str(&client_id)])?
        .first::<ClientSecretRow>(None)
        .await?
        .ok_or_else(|| worker::Error::RustError("invalid_client".into()))?;
    if row.auth_method != method {
        return Err(worker::Error::RustError("invalid_client".into()));
    }
    let now = i64::try_from(now).map_err(|_| worker::Error::RustError("server_error".into()))?;
    db.prepare(
        "INSERT INTO client_secret_attempt(client_id,window_start,attempts) VALUES(?1,?2,1) \
         ON CONFLICT(client_id) DO UPDATE SET \
         window_start=CASE WHEN window_start<=?2-?3 THEN ?2 ELSE window_start END, \
         attempts=CASE WHEN window_start<=?2-?3 THEN 1 ELSE MIN(attempts+1,1000) END",
    )
    .bind(&[
        JsValue::from_str(&client_id),
        JsValue::from_f64(now as f64),
        JsValue::from_f64(policy.token_rate_window_seconds as f64),
    ])?
    .run()
    .await?;
    #[derive(Deserialize)]
    struct AttemptCount {
        attempts: u64,
    }
    let count = db
        .prepare("SELECT attempts FROM client_secret_attempt WHERE client_id=?1")
        .bind(&[JsValue::from_str(&client_id)])?
        .first::<AttemptCount>(None)
        .await?
        .ok_or_else(|| worker::Error::RustError("server_error".into()))?;
    if count.attempts > policy.token_attempts_per_client {
        return Err(worker::Error::RustError("invalid_client".into()));
    }
    let expected = URL_SAFE_NO_PAD
        .decode(&row.secret_hash)
        .map_err(|_| worker::Error::RustError("invalid_client".into()))?;
    let actual = Sha256::digest(secret.as_bytes());
    if expected.len() != 32 || actual.as_slice().ct_eq(expected.as_slice()).unwrap_u8() != 1 {
        return Err(worker::Error::RustError("invalid_client".into()));
    }
    if form.grant_type != "authorization_code" {
        return Err(worker::Error::RustError("unsupported_grant_type".into()));
    }
    let allow_missing_pkce = row.allow_missing_pkce == 1;
    let code_verifier = match form.code_verifier {
        Some(value) if !value.is_empty() => value,
        None if allow_missing_pkce => String::new(),
        _ => return Err(worker::Error::RustError("invalid_request".into())),
    };
    let exchange = mikaki_oidc::CodeExchangeInput {
        grant_type: form.grant_type,
        code: form.code,
        redirect_uri: form.redirect_uri,
        code_verifier,
    }
    .validate_with_optional_pkce(allow_missing_pkce)
    .map_err(|_| worker::Error::RustError("invalid_request".into()))?;
    let mut operation = [0u8; 32];
    random
        .fill(&mut operation)
        .map_err(|_| worker::Error::RustError("server_error".into()))?;
    let reservation_id = URL_SAFE_NO_PAD.encode(operation);
    let retain_until = now + 300;
    db.batch(vec![
        db.prepare(
            "INSERT INTO client_auth_use(accepted_by,client_id,method,endpoint,credential_id,client_revision,credential_revision,retain_until) \
             SELECT ?1,?2,?3,?7,'',?4,?5,?6 FROM client c JOIN client_secret s ON s.client_id=c.client_id \
             WHERE c.client_id=?2 AND c.active=1 AND c.revision=?4 AND c.auth_method=?3 \
             AND s.active=1 AND s.revision=?5",
        )
        .bind(&[
            JsValue::from_str(&reservation_id),
            JsValue::from_str(&client_id),
            JsValue::from_str(method),
            JsValue::from_f64(row.client_revision as f64),
            JsValue::from_f64(row.secret_revision as f64),
            JsValue::from_f64(retain_until as f64),
            JsValue::from_str(token_endpoint),
        ])?,
        db.prepare(
            "INSERT INTO atomic_guard(operation_id,passed) VALUES(?1,CASE WHEN EXISTS ( \
             SELECT 1 FROM client_auth_use WHERE accepted_by=?1 AND client_id=?2 \
             ) THEN 1 ELSE 0 END)",
        )
        .bind(&[JsValue::from_str(&reservation_id), JsValue::from_str(&client_id)])?,
        db.prepare("DELETE FROM atomic_guard WHERE operation_id=?1")
            .bind(&[JsValue::from_str(&reservation_id)])?,
    ])
    .await?;
    Ok(AuthenticatedTokenRequest {
        client_id,
        exchange,
        client_revision: row.client_revision,
        method,
        endpoint: token_endpoint.to_owned(),
        credential_id: String::new(),
        credential_revision: row.secret_revision,
        reservation_id,
        retain_until: retain_until as u64,
        requested_resource: None,
    })
}

#[cfg(target_arch = "wasm32")]
impl mikaki_oidc::CryptographicRandom for WorkersCryptoRandom {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), mikaki_oidc::CodeEntropyError> {
        let global = js_sys::global();
        let crypto = js_sys::Reflect::get(&global, &"crypto".into())
            .map_err(|_| mikaki_oidc::CodeEntropyError)?
            .dyn_into::<web_sys::Crypto>()
            .map_err(|_| mikaki_oidc::CodeEntropyError)?;
        crypto
            .get_random_values_with_u8_array(output)
            .map(|_| ())
            .map_err(|_| mikaki_oidc::CodeEntropyError)
    }
}

/// Atomically reserve a signature-verified private_key_jwt `jti` and recheck
/// its client/key revisions. A D1 constraint failure rolls back the assertion
/// insert, so callers must reject the assertion and must not continue the grant.
#[cfg(target_arch = "wasm32")]
pub(super) async fn accept_client_assertion(
    db: &worker::d1::D1Database,
    assertion: &mikaki_oidc::VerifiedClientAssertion,
    audience: &str,
    endpoint: &str,
    random: &mut impl mikaki_oidc::CryptographicRandom,
) -> worker::Result<String> {
    use wasm_bindgen::JsValue;

    if endpoint.is_empty() || assertion.audience() != audience {
        return Err(worker::Error::RustError(
            "client assertion endpoint mismatch".into(),
        ));
    }
    let retain_until = assertion.retain_until();
    if retain_until > i64::MAX as u64
        || assertion.client_revision() > i64::MAX as u64
        || assertion.key_revision() > i64::MAX as u64
    {
        return Err(worker::Error::RustError(
            "client assertion revision or expiry is out of range".into(),
        ));
    }
    let mut operation = [0u8; 32];
    random
        .fill(&mut operation)
        .map_err(|_| worker::Error::RustError("secure randomness unavailable".into()))?;
    let operation_id = URL_SAFE_NO_PAD.encode(operation);
    let values = [
        JsValue::from_str(assertion.client_id()),
        JsValue::from_str(assertion.jti()),
        JsValue::from_str(endpoint),
        JsValue::from_str(&operation_id),
        JsValue::from_str(&retain_until.to_string()),
        JsValue::from_str(assertion.key_id()),
        JsValue::from_str(&assertion.client_revision().to_string()),
        JsValue::from_str(&assertion.key_revision().to_string()),
    ];
    db.batch(vec![
        db.prepare(
            "INSERT INTO assertion_use(client_id,jti,endpoint,accepted_by,retain_until) \
             SELECT ?1,?2,?3,?4,?5 FROM client c JOIN client_key k ON k.client_id=c.client_id \
             WHERE c.client_id=?1 AND c.active=1 AND c.revision=?7 \
             AND k.kid=?6 AND k.revision=?8 AND k.active=1 AND ?5 > CAST(strftime('%s','now') AS INTEGER)",
        )
        .bind(&values)?,
        db.prepare(
            "INSERT INTO client_auth_use(accepted_by,client_id,method,endpoint,credential_id,client_revision,credential_revision,retain_until) \
             SELECT ?4,?1,'private_key_jwt',?3,?6,?7,?8,?5 FROM client c JOIN client_key k ON k.client_id=c.client_id \
             WHERE c.client_id=?1 AND c.active=1 AND c.auth_method='private_key_jwt' AND c.revision=?7 \
             AND k.kid=?6 AND k.revision=?8 AND k.active=1",
        )
        .bind(&values)?,
        db.prepare(
            "INSERT INTO atomic_guard(operation_id,passed) VALUES(?1,CASE WHEN EXISTS ( \
             SELECT 1 FROM assertion_use a JOIN client_auth_use u ON u.accepted_by=a.accepted_by \
             WHERE a.accepted_by=?1 AND a.client_id=?2 AND a.jti=?3 AND a.endpoint=?4 \
             ) THEN 1 ELSE 0 END)",
        )
        .bind(&[
            values[3].clone(),
            values[0].clone(),
            values[1].clone(),
            values[2].clone(),
        ])?,
        db.prepare("DELETE FROM atomic_guard WHERE operation_id=?1")
            .bind(&[JsValue::from_str(&operation_id)])?,
    ])
    .await?;
    Ok(operation_id)
}

/// Load one registered key, verify a private_key_jwt in the Rust core, and
/// atomically reserve its jti after rechecking the same registration revisions.
#[cfg(target_arch = "wasm32")]
#[allow(clippy::too_many_arguments)]
pub(super) async fn verify_and_accept_client_assertion(
    db: &worker::d1::D1Database,
    client_id: &str,
    compact: &str,
    audience: &str,
    endpoint: &str,
    fapi: bool,
    now: u64,
    policy: &WorkerRuntimePolicy,
    random: &mut impl mikaki_oidc::CryptographicRandom,
) -> worker::Result<(mikaki_oidc::VerifiedClientAssertion, String)> {
    use wasm_bindgen::JsValue;

    if client_id.is_empty() || client_id.len() > 128 {
        return Err(worker::Error::RustError("invalid_client".into()));
    }
    let kid = mikaki_oidc::client_assertion_key_id(compact, policy.jwt_bytes)
        .map_err(|_| worker::Error::RustError("invalid_client".into()))?;
    let values = [JsValue::from_str(client_id), JsValue::from_str(&kid)];
    let row = db
        .prepare(
            "SELECT c.client_id, k.kid, c.revision AS client_revision, c.auth_method, \
             k.revision AS key_revision, c.active AS client_active, \
             k.active AS key_active, k.algorithm, k.public_key_sec1 \
             FROM client c JOIN client_key k ON k.client_id=c.client_id \
             WHERE c.client_id=?1 AND k.kid=?2 LIMIT 1",
        )
        .bind(&values)?
        .first::<ClientAssertionKeyRow>(None)
        .await?
        .ok_or_else(|| worker::Error::RustError("invalid_client".into()))?;
    if row.client_id != client_id
        || row.kid != kid
        || row.client_active != 1
        || row.key_active != 1
        || row.auth_method != "private_key_jwt"
        || row.algorithm != "ES256"
    {
        return Err(worker::Error::RustError("invalid_client".into()));
    }
    let key = mikaki_oidc::ClientAssertionKey::new(
        row.client_id,
        row.kid,
        row.client_revision,
        row.key_revision,
        true,
        row.public_key_sec1,
    );
    let assertion = if fapi {
        key.verify_fapi_private_key_jwt(compact, audience, now, policy.jwt_bytes)
    } else {
        key.verify_private_key_jwt(compact, audience, now, policy.assertion, policy.jwt_bytes)
    }
    .map_err(|_| worker::Error::RustError("invalid_client".into()))?;
    let reservation_id =
        accept_client_assertion(db, &assertion, audience, endpoint, random).await?;
    Ok((assertion, reservation_id))
}

#[cfg(target_arch = "wasm32")]
#[allow(clippy::too_many_arguments)]
pub async fn authenticate_token_request(
    db: &worker::d1::D1Database,
    input: mikaki_oidc::ValidatedTokenEndpointInput,
    token_endpoint: &str,
    issuer: &str,
    fapi: bool,
    now: u64,
    policy: &WorkerRuntimePolicy,
    random: &mut impl mikaki_oidc::CryptographicRandom,
) -> worker::Result<AuthenticatedTokenRequest> {
    let (assertion, assertion_reservation_id) = verify_and_accept_client_assertion(
        db,
        input.client_id(),
        input.assertion().as_str(),
        if fapi { issuer } else { token_endpoint },
        token_endpoint,
        fapi,
        now,
        policy,
        random,
    )
    .await?;
    let request = input
        .authenticate(assertion, if fapi { issuer } else { token_endpoint })
        .map_err(|_| worker::Error::RustError("invalid_client".into()))?;
    Ok(AuthenticatedTokenRequest {
        client_id: request.client_id().to_owned(),
        exchange: request.exchange().clone(),
        client_revision: request.assertion().client_revision(),
        method: "private_key_jwt",
        endpoint: token_endpoint.to_owned(),
        credential_id: request.assertion().key_id().to_owned(),
        credential_revision: request.assertion().key_revision(),
        reservation_id: assertion_reservation_id,
        retain_until: request.assertion().retain_until(),
        requested_resource: None,
    })
}

/// A public native request proves possession of the PKCE verifier, not a
/// shared application secret. Registration and the one-use code are checked
/// before recording a short-lived exchange receipt.
#[cfg(target_arch = "wasm32")]
pub(super) async fn accept_native_token_request(
    db: &worker::d1::D1Database,
    body: &str,
    token_endpoint: &str,
    now: u64,
    random: &mut impl mikaki_oidc::CryptographicRandom,
) -> worker::Result<AuthenticatedTokenRequest> {
    use wasm_bindgen::JsValue;

    let form: mikaki_oidc::PublicTokenEndpointInput = serde_urlencoded::from_str(body)
        .map_err(|_| worker::Error::RustError("invalid_request".into()))?;
    let input = form.validate().map_err(|error| {
        let code = match error {
            mikaki_oidc::TokenEndpointInputError::UnsupportedGrantType => "unsupported_grant_type",
            mikaki_oidc::TokenEndpointInputError::InvalidClient => "invalid_client",
            _ => "invalid_request",
        };
        worker::Error::RustError(code.into())
    })?;
    let exchange = input.exchange();
    let loopback_template = loopback_redirect_template(exchange.redirect_uri());
    let registered_redirect_uri = loopback_template
        .as_deref()
        .unwrap_or(exchange.redirect_uri());
    if exchange.redirect_uri().starts_with("http:") && loopback_template.is_none() {
        return Err(worker::Error::RustError("invalid_grant".into()));
    }
    let row = db
        .prepare(
            "SELECT c.revision AS client_revision FROM client c \
             JOIN client_redirect_uri r ON r.client_id=c.client_id \
             JOIN authorization_code ac ON ac.client_id=c.client_id \
             WHERE c.client_id=?1 AND c.client_type='native' AND c.auth_method='none' \
             AND c.active=1 AND r.redirect_uri=?5 AND r.active=1 \
             AND ac.code_hash=?3 AND ac.redirect_uri=?5 \
             AND ac.redirect_uri_actual=CASE WHEN ?2=?5 THEN '' ELSE ?2 END \
             AND ac.pkce_challenge=?4 AND ac.client_revision=c.revision \
             AND ac.expires_at>CAST(strftime('%s','now') AS INTEGER) \
             LIMIT 1",
        )
        .bind(&[
            JsValue::from_str(input.client_id()),
            JsValue::from_str(exchange.redirect_uri()),
            JsValue::from_str(exchange.code_digest()),
            JsValue::from_str(exchange.pkce_challenge()),
            JsValue::from_str(registered_redirect_uri),
        ])?
        .first::<NativeClientTokenRow>(None)
        .await?
        .ok_or_else(|| worker::Error::RustError("invalid_grant".into()))?;
    let mut receipt = [0u8; 32];
    random
        .fill(&mut receipt)
        .map_err(|_| worker::Error::RustError("server_error".into()))?;
    let receipt = URL_SAFE_NO_PAD.encode(receipt);
    let retain_until = now.saturating_add(60);
    let values = [
        JsValue::from_str(&receipt),
        JsValue::from_str(input.client_id()),
        JsValue::from_str(token_endpoint),
        JsValue::from_str(&row.client_revision.to_string()),
        JsValue::from_str(&retain_until.to_string()),
        JsValue::from_str(exchange.code_digest()),
        JsValue::from_str(exchange.redirect_uri()),
        JsValue::from_str(exchange.pkce_challenge()),
        JsValue::from_str(registered_redirect_uri),
    ];
    db.batch(vec![
        db.prepare(
            "INSERT INTO client_auth_use(accepted_by,client_id,method,endpoint,credential_id,client_revision,credential_revision,retain_until) \
             SELECT ?1,c.client_id,'none',?3,'',c.revision,0,?5 FROM client c \
             JOIN client_redirect_uri r ON r.client_id=c.client_id AND r.redirect_uri=?9 \
             JOIN authorization_code ac ON ac.client_id=c.client_id AND ac.code_hash=?6 \
             WHERE c.client_id=?2 AND c.client_type='native' AND c.auth_method='none' \
             AND c.active=1 AND c.revision=?4 AND r.active=1 \
             AND ac.redirect_uri=?9 AND ac.redirect_uri_actual=CASE WHEN ?7=?9 THEN '' ELSE ?7 END \
             AND ac.pkce_challenge=?8 AND ac.client_revision=c.revision \
             AND ac.expires_at>CAST(strftime('%s','now') AS INTEGER) \
             AND ?5>CAST(strftime('%s','now') AS INTEGER)",
        )
        .bind(&values)?,
        db.prepare(
            "INSERT INTO atomic_guard(operation_id,passed) VALUES(?1,CASE WHEN EXISTS ( \
             SELECT 1 FROM client_auth_use WHERE accepted_by=?1 AND client_id=?2 \
             AND method='none' AND client_revision=?4 AND endpoint=?3 AND retain_until=?5 \
             ) THEN 1 ELSE 0 END)",
        )
        .bind(&values[..5])?,
        db.prepare("DELETE FROM atomic_guard WHERE operation_id=?1")
            .bind(&values[..1])?,
    ])
    .await?;
    Ok(AuthenticatedTokenRequest {
        client_id: input.client_id().to_owned(),
        exchange: exchange.clone(),
        client_revision: row.client_revision,
        method: "none",
        endpoint: token_endpoint.to_owned(),
        credential_id: String::new(),
        credential_revision: 0,
        reservation_id: receipt,
        retain_until,
        requested_resource: input.resource().map(str::to_owned),
    })
}

/// Read the one-use code's immutable claims and current eligibility facts
/// before signing. The commit step must repeat the conditional predicates.
#[cfg(target_arch = "wasm32")]
pub(super) async fn load_authorization_code_context(
    db: &worker::d1::D1Database,
    input: &AuthenticatedTokenRequest,
    signer: &WorkerTokenSigner,
    fapi: bool,
    vault_preview: bool,
    dpop_proof: Option<&mikaki_oidc::VerifiedDpopProof>,
    random: &mut impl mikaki_oidc::CryptographicRandom,
) -> worker::Result<AuthorizationCodeContext> {
    use wasm_bindgen::JsValue;

    let exchange = input.exchange();
    let values = [
        JsValue::from_str(input.client_id()),
        JsValue::from_str(exchange.code_digest()),
        JsValue::from_str(exchange.redirect_uri()),
        JsValue::from_str(exchange.pkce_challenge()),
        JsValue::from_str(&input.client_revision.to_string()),
        JsValue::from_str(&input.credential_id),
        JsValue::from_str(&input.credential_revision.to_string()),
        JsValue::from_str(input.method),
        JsValue::from_str(&input.endpoint),
        JsValue::from_str(input.reservation_id()),
        JsValue::from_str(&input.retain_until.to_string()),
        JsValue::from_str(signer.kid()),
        JsValue::from_str(signer.algorithm()),
        JsValue::from_f64(if fapi { 1.0 } else { 0.0 }),
    ];
    let row = db
        .prepare(
            "SELECT ac.client_id, ac.dpop_jkt, cs.sid, v.sub, cc.nonce, cc.scope, sx.auth_time, \
             v.expires_at AS parent_expires_at, sk.generation AS signing_generation, \
             sk.algorithm AS signing_algorithm, \
             sk.public_jwk AS public_jwk \
             FROM authorization_code ac \
             JOIN eligible_client_session v ON v.client_id=ac.client_id AND v.sid=ac.sid \
             JOIN client_session cs ON cs.client_id=ac.client_id AND cs.sid=ac.sid \
             JOIN sso_context sx ON sx.sso_id=cs.sso_id \
             JOIN code_context cc ON cc.code_hash=ac.code_hash \
             JOIN client c ON c.client_id=ac.client_id \
             JOIN client_auth_use au ON au.client_id=c.client_id \
             JOIN signing_key sk ON sk.kid=?12 \
             WHERE c.client_id=?1 AND c.active=1 AND c.revision=?5 \
             AND ac.code_hash=?2 AND ac.client_id=?1 AND ac.consumed_by IS NULL \
             AND (?14=0 OR EXISTS (SELECT 1 FROM par_request p \
               WHERE p.consumed_by=ac.code_hash AND p.client_id=ac.client_id)) \
             AND (CASE WHEN ac.redirect_uri_actual='' THEN ac.redirect_uri ELSE ac.redirect_uri_actual END)=?3 \
             AND ac.pkce_challenge=?4 \
             AND ac.expires_at > CAST(strftime('%s','now') AS INTEGER) \
             AND c.auth_method=?8 \
             AND au.method=?8 AND au.credential_id=?6 AND au.client_revision=?5 \
             AND au.credential_revision=?7 AND au.endpoint=?9 AND au.accepted_by=?10 \
             AND au.retain_until=?11 AND au.retain_until > CAST(strftime('%s','now') AS INTEGER) \
             AND ((?8='private_key_jwt' AND EXISTS (SELECT 1 FROM client_key ck WHERE ck.client_id=c.client_id \
               AND ck.kid=?6 AND ck.revision=?7 AND ck.active=1)) \
               OR (?8 IN ('client_secret_basic','client_secret_post') AND EXISTS (SELECT 1 FROM client_secret s \
               WHERE s.client_id=c.client_id AND s.revision=?7 AND s.active=1)) \
               OR (?8='none' AND c.client_type='native' AND ?6='' AND CAST(?7 AS INTEGER)=0)) \
             AND sk.active=1 AND sk.algorithm=?13 LIMIT 1",
        )
        .bind(&values)?
        .first::<AuthorizationCodeContextRow>(None)
        .await?;
    let Some(row) = row else {
        revoke_reused_code(db, input, dpop_proof, random).await?;
        return Err(worker::Error::RustError("invalid_grant".into()));
    };
    if row.client_id != input.client_id() || !signer.matches_public_jwk(&row.public_jwk) {
        return Err(worker::Error::RustError("server_error".into()));
    }
    let auth_time = u64::try_from(row.auth_time)
        .map_err(|_| worker::Error::RustError("invalid_grant".into()))?;
    let parent_expires_at = u64::try_from(row.parent_expires_at)
        .map_err(|_| worker::Error::RustError("invalid_grant".into()))?;
    let signing_generation = u64::try_from(row.signing_generation)
        .map_err(|_| worker::Error::RustError("invalid_grant".into()))?;
    let scope = match row.scope.as_str() {
        "openid" => "openid",
        "openid profile" | "profile openid" => "openid profile",
        "openid vault.read" | "vault.read openid" if vault_preview => "openid vault.read",
        _ => return Err(worker::Error::RustError("invalid_grant".into())),
    };
    let vault = if scope == "openid vault.read" {
        if input.requested_resource.as_deref() != Some(mikaki_oidc::VAULT_RESOURCE) {
            return Err(worker::Error::RustError("invalid_target".into()));
        }
        let grant = db
            .prepare(
                "SELECT g.grant_id,g.version AS grant_version,g.resource,g.attribute_id,g.expires_at \
                 FROM vault_oauth_code_context vc \
                 JOIN vault_oauth_grant g ON g.grant_id=vc.grant_id \
                 JOIN authorization_code ac ON ac.code_hash=vc.code_hash \
                 JOIN eligible_client_session s ON s.client_id=ac.client_id AND s.sid=ac.sid \
                 JOIN client c ON c.client_id=ac.client_id \
                 WHERE vc.code_hash=?1 AND vc.grant_version=g.version \
                 AND vc.resource=g.resource AND vc.attribute_id=g.attribute_id \
                 AND g.account_id=s.account_id AND g.client_id=ac.client_id \
                 AND g.client_revision=ac.client_revision AND g.revoked=0 \
                 AND g.expires_at>unixepoch() AND c.client_type='native' \
                 AND c.auth_method='none' AND c.active=1 AND c.revision=ac.client_revision",
            )
            .bind(&[JsValue::from_str(exchange.code_digest())])?
            .first::<VaultCodeGrantRow>(None)
            .await?
            .ok_or_else(|| worker::Error::RustError("invalid_grant".into()))?;
        Some(VaultCodeGrant {
            grant_id: grant.grant_id,
            grant_version: grant.grant_version,
            resource: grant.resource,
            attribute_id: grant.attribute_id,
            expires_at: u64::try_from(grant.expires_at)
                .map_err(|_| worker::Error::RustError("invalid_grant".into()))?,
        })
    } else {
        if input.requested_resource.is_some() {
            return Err(worker::Error::RustError("invalid_target".into()));
        }
        None
    };
    Ok(AuthorizationCodeContext {
        client_id: row.client_id,
        dpop_jkt: row.dpop_jkt,
        sid: row.sid,
        sub: row.sub,
        nonce: row.nonce,
        scope,
        auth_time,
        parent_expires_at,
        signing_kid: signer.kid().to_owned(),
        signing_algorithm: row.signing_algorithm,
        signing_generation,
        public_jwk: row.public_jwk,
        vault,
    })
}

#[cfg(target_arch = "wasm32")]
pub(super) async fn revoke_reused_code(
    db: &worker::d1::D1Database,
    input: &AuthenticatedTokenRequest,
    dpop_proof: Option<&mikaki_oidc::VerifiedDpopProof>,
    random: &mut impl mikaki_oidc::CryptographicRandom,
) -> worker::Result<()> {
    use wasm_bindgen::JsValue;

    let exchange = input.exchange();
    let mut operation = [0u8; 32];
    random
        .fill(&mut operation)
        .map_err(|_| worker::Error::RustError("server_error".into()))?;
    let operation_id = URL_SAFE_NO_PAD.encode(operation);
    let values = [
        JsValue::from_str(exchange.code_digest()),
        JsValue::from_str(input.client_id()),
        JsValue::from_str(exchange.redirect_uri()),
        JsValue::from_str(exchange.pkce_challenge()),
        JsValue::from_str(&input.client_revision.to_string()),
        JsValue::from_str(&input.credential_id),
        JsValue::from_str(&input.credential_revision.to_string()),
        JsValue::from_str(input.method),
        JsValue::from_str(&input.endpoint),
        JsValue::from_str(input.reservation_id()),
        JsValue::from_str(&input.retain_until.to_string()),
        JsValue::from_str(&operation_id),
        dpop_proof.map_or(JsValue::NULL, |proof| JsValue::from_str(proof.thumbprint())),
    ];
    db.batch(vec![
        db.prepare(
            "UPDATE token_issue SET revoked=1 WHERE code_hash=?1 AND revoked=0 \
             AND (dpop_jkt IS NULL OR dpop_jkt=?13) \
             AND EXISTS (SELECT 1 FROM authorization_code ac \
               JOIN client c ON c.client_id=ac.client_id \
               JOIN client_auth_use au ON au.client_id=c.client_id \
               WHERE ac.code_hash=?1 AND ac.client_id=?2 \
                 AND (CASE WHEN ac.redirect_uri_actual='' THEN ac.redirect_uri ELSE ac.redirect_uri_actual END)=?3 \
                 AND ac.pkce_challenge=?4 AND ac.consumed_by IS NOT NULL \
                 AND ac.client_revision=c.revision \
                 AND c.active=1 AND c.revision=?5 AND c.auth_method=?8 \
                 AND au.method=?8 AND au.credential_id=?6 AND au.credential_revision=?7 \
                 AND au.client_revision=?5 AND au.endpoint=?9 AND au.accepted_by=?10 \
                 AND ((?8='private_key_jwt' AND EXISTS (SELECT 1 FROM client_key ck WHERE ck.client_id=c.client_id \
                   AND ck.kid=?6 AND ck.revision=?7 AND ck.active=1)) \
                   OR (?8 IN ('client_secret_basic','client_secret_post') AND EXISTS (SELECT 1 FROM client_secret s \
                   WHERE s.client_id=c.client_id AND s.revision=?7 AND s.active=1)) \
                   OR (?8='none' AND c.client_type='native' AND ?6='' AND CAST(?7 AS INTEGER)=0)) \
                 AND au.retain_until=?11 AND au.retain_until > CAST(strftime('%s','now') AS INTEGER))",
        )
        .bind(&values)?,
        db.prepare(
            "INSERT INTO atomic_guard(operation_id,passed) VALUES(?12,CASE WHEN NOT EXISTS ( \
             SELECT 1 FROM token_issue ti \
             JOIN authorization_code ac ON ac.code_hash=ti.code_hash \
             JOIN client c ON c.client_id=ac.client_id \
             JOIN client_auth_use au ON au.client_id=c.client_id \
             WHERE ti.code_hash=?1 AND ti.revoked=0 AND ac.client_id=?2 \
               AND (ti.dpop_jkt IS NULL OR ti.dpop_jkt=?13) \
               AND ac.client_revision=c.revision \
               AND (CASE WHEN ac.redirect_uri_actual='' THEN ac.redirect_uri ELSE ac.redirect_uri_actual END)=?3 \
               AND ac.pkce_challenge=?4 \
               AND ac.consumed_by IS NOT NULL AND c.active=1 AND c.revision=?5 AND c.auth_method=?8 \
               AND au.method=?8 AND au.credential_id=?6 AND au.credential_revision=?7 \
               AND au.client_revision=?5 AND au.endpoint=?9 AND au.accepted_by=?10 \
               AND ((?8='private_key_jwt' AND EXISTS (SELECT 1 FROM client_key ck WHERE ck.client_id=c.client_id \
                 AND ck.kid=?6 AND ck.revision=?7 AND ck.active=1)) \
                 OR (?8 IN ('client_secret_basic','client_secret_post') AND EXISTS (SELECT 1 FROM client_secret s \
                 WHERE s.client_id=c.client_id AND s.revision=?7 AND s.active=1)) \
                 OR (?8='none' AND c.client_type='native' AND ?6='' AND CAST(?7 AS INTEGER)=0)) \
               AND au.retain_until=?11 AND au.retain_until > CAST(strftime('%s','now') AS INTEGER) \
             ) THEN 1 ELSE 0 END)",
        )
        .bind(&values)?,
        db.prepare("DELETE FROM atomic_guard WHERE operation_id=?12").bind(&values[..12])?,
    ])
    .await?;
    Ok(())
}

/// Sign the response first, then consume the code and persist the opaque token
/// in a single D1 batch guarded by all authorization and key revisions.
#[cfg(target_arch = "wasm32")]
#[allow(clippy::too_many_arguments)]
pub(super) async fn commit_authorization_code_exchange(
    db: &worker::d1::D1Database,
    input: &AuthenticatedTokenRequest,
    context: &AuthorizationCodeContext,
    signer: &WorkerTokenSigner,
    issuer: &str,
    now: u64,
    access_ttl_seconds: u64,
    id_token_ttl_seconds: u64,
    response_bytes: usize,
    random: &mut impl mikaki_oidc::CryptographicRandom,
    dpop_proof: Option<(&mikaki_oidc::VerifiedDpopProof, &str)>,
    fapi: bool,
) -> worker::Result<TokenEndpointSuccess> {
    use wasm_bindgen::JsValue;

    if context.client_id() != input.client_id()
        || context.signing_kid() != signer.kid()
        || context.signing_algorithm != signer.algorithm()
        || context
            .dpop_jkt
            .as_deref()
            .is_some_and(|jkt| dpop_proof.is_none_or(|(proof, _)| proof.thumbprint() != jkt))
        || (context.vault.is_some() && dpop_proof.is_none())
        || now > i64::MAX as u64
    {
        return Err(worker::Error::RustError("invalid_grant".into()));
    }
    let access_expires_at = now
        .checked_add(access_ttl_seconds)
        .ok_or_else(|| worker::Error::RustError("invalid_grant".into()))?
        .min(context.parent_expires_at())
        .min(
            context
                .vault
                .as_ref()
                .map_or(u64::MAX, |grant| grant.expires_at),
        );
    let id_token_expires_at = now
        .checked_add(id_token_ttl_seconds)
        .ok_or_else(|| worker::Error::RustError("invalid_grant".into()))?
        .min(context.parent_expires_at());
    if access_expires_at <= now || id_token_expires_at <= now {
        return Err(worker::Error::RustError("invalid_grant".into()));
    }
    let id_token = signer
        .sign_id_token(
            issuer,
            context.subject(),
            context.client_id(),
            context.sid(),
            context.nonce(),
            context.auth_time(),
            now,
            id_token_expires_at,
        )
        .await?;

    let mut access_secret = [0u8; 32];
    random
        .fill(&mut access_secret)
        .map_err(|_| worker::Error::RustError("server_error".into()))?;
    let access_token = URL_SAFE_NO_PAD.encode(access_secret);
    let access_hash = URL_SAFE_NO_PAD.encode(Sha256::digest(access_token.as_bytes()));
    access_secret.fill(0);
    let mut operation = [0u8; 32];
    random
        .fill(&mut operation)
        .map_err(|_| worker::Error::RustError("server_error".into()))?;
    let operation_id = URL_SAFE_NO_PAD.encode(operation);
    let response = TokenEndpointSuccess {
        access_token,
        token_type: if dpop_proof.is_some() {
            "DPoP"
        } else {
            "Bearer"
        },
        expires_in: access_expires_at - now,
        scope: context.scope,
        id_token,
        authorization_details: context.vault.as_ref().map(|grant| {
            serde_json::json!([{
                "type": mikaki_oidc::VAULT_READ_DETAIL_TYPE,
                "locations": [grant.resource],
                "actions": ["read_ciphertext"],
                "attribute": grant.attribute_id,
            }])
        }),
    };
    let id_token_hash = URL_SAFE_NO_PAD.encode(Sha256::digest(response.id_token.as_bytes()));
    if serde_json::to_vec(&response)
        .map_err(worker::Error::from)?
        .len()
        > response_bytes
    {
        return Err(worker::Error::RustError("server_error".into()));
    }

    let exchange = input.exchange();
    let values = [
        JsValue::from_str(exchange.code_digest()),
        JsValue::from_str(input.client_id()),
        JsValue::from_str(exchange.redirect_uri()),
        JsValue::from_str(exchange.pkce_challenge()),
        JsValue::from_str(&input.client_revision.to_string()),
        JsValue::from_str(&input.credential_id),
        JsValue::from_str(&input.credential_revision.to_string()),
        JsValue::from_str(input.method),
        JsValue::from_str(&input.endpoint),
        JsValue::from_str(input.reservation_id()),
        JsValue::from_str(&input.retain_until.to_string()),
        JsValue::from_str(context.signing_kid()),
        JsValue::from_str(&context.signing_generation().to_string()),
        JsValue::from_str(context.sid()),
        JsValue::from_str(context.subject()),
        context
            .nonce()
            .map(JsValue::from_str)
            .unwrap_or(JsValue::NULL),
        JsValue::from_str(&context.auth_time().to_string()),
        JsValue::from_str(&context.parent_expires_at().to_string()),
        JsValue::from_str(&operation_id),
        JsValue::from_str(&access_expires_at.to_string()),
        JsValue::from_str(&id_token_expires_at.to_string()),
        JsValue::from_str(&access_hash),
        JsValue::from_str(&context.public_jwk),
        JsValue::from_str(&context.signing_algorithm),
        dpop_proof
            .map(|(proof, _)| JsValue::from_str(proof.thumbprint()))
            .unwrap_or(JsValue::NULL),
        dpop_proof
            .map(|(proof, _)| JsValue::from_str(proof.jti_hash()))
            .unwrap_or(JsValue::NULL),
        dpop_proof
            .map(|(_, receipt)| JsValue::from_str(receipt))
            .unwrap_or(JsValue::NULL),
        JsValue::from_f64(if fapi { 1.0 } else { 0.0 }),
        JsValue::from_str(context.scope),
    ];
    let mut issue_values = values[..22].to_vec();
    issue_values.push(JsValue::from_str(&id_token_hash));
    issue_values.push(values[24].clone());
    let mut statements = vec![
        db.prepare(
            "UPDATE authorization_code SET consumed_by=?19, \
             consumed_at=CAST(strftime('%s','now') AS INTEGER) \
             WHERE code_hash=?1 AND client_id=?2 \
             AND (CASE WHEN redirect_uri_actual='' THEN redirect_uri ELSE redirect_uri_actual END)=?3 \
             AND pkce_challenge=?4 AND consumed_by IS NULL \
             AND (?28=0 OR EXISTS (SELECT 1 FROM par_request p \
               WHERE p.consumed_by=authorization_code.code_hash AND p.client_id=?2)) \
             AND (dpop_jkt IS NULL OR dpop_jkt=?25) \
             AND expires_at > CAST(strftime('%s','now') AS INTEGER) \
             AND EXISTS (SELECT 1 FROM client c WHERE c.client_id=?2 \
               AND c.active=1 AND c.revision=?5 AND c.auth_method=?8) \
             AND EXISTS (SELECT 1 FROM eligible_client_session v \
               WHERE v.client_id=?2 AND v.sid=?14 AND v.sub=?15 AND v.expires_at=?18) \
             AND EXISTS (SELECT 1 FROM client_session cs \
               JOIN sso_context sx ON sx.sso_id=cs.sso_id \
               JOIN code_context cc ON cc.code_hash=?1 \
               WHERE cs.client_id=?2 AND cs.sid=?14 AND sx.auth_time=?17 AND cc.nonce IS ?16 \
               AND (cc.scope=?29 OR (?29='openid profile' AND cc.scope='profile openid') \
                 OR (?29='openid vault.read' AND cc.scope='vault.read openid'))) \
             AND ((?29='openid vault.read' AND EXISTS (SELECT 1 FROM vault_oauth_code_context vc \
               WHERE vc.code_hash=?1)) OR (?29!='openid vault.read' AND NOT EXISTS ( \
               SELECT 1 FROM vault_oauth_code_context vc WHERE vc.code_hash=?1))) \
             AND EXISTS (SELECT 1 FROM client_auth_use au WHERE au.client_id=?2 \
               AND au.method=?8 AND au.credential_id=?6 AND au.client_revision=?5 \
               AND au.credential_revision=?7 AND au.endpoint=?9 AND au.accepted_by=?10 \
               AND au.retain_until=?11 AND au.retain_until > CAST(strftime('%s','now') AS INTEGER)) \
             AND ((?8='private_key_jwt' AND EXISTS (SELECT 1 FROM client_key ck WHERE ck.client_id=?2 \
               AND ck.kid=?6 AND ck.revision=?7 AND ck.active=1)) \
               OR (?8 IN ('client_secret_basic','client_secret_post') AND EXISTS (SELECT 1 FROM client_secret s \
               WHERE s.client_id=?2 AND s.revision=?7 AND s.active=1)) \
               OR (?8='none' AND ?6='' AND CAST(?7 AS INTEGER)=0 AND EXISTS (SELECT 1 FROM client nc \
                 WHERE nc.client_id=?2 AND nc.client_type='native' AND nc.auth_method='none'))) \
             AND EXISTS (SELECT 1 FROM signing_key sk WHERE sk.kid=?12 \
               AND sk.generation=?13 AND sk.active=1 AND sk.public_jwk=?23 \
               AND sk.algorithm=?24) \
             AND (?25 IS NULL OR EXISTS (SELECT 1 FROM dpop_proof_use p \
               WHERE p.jkt=?25 AND p.jti_hash=?26 AND p.accepted_by=?27 \
               AND p.retain_until>=CAST(strftime('%s','now') AS INTEGER))) \
             AND CAST(?20 AS INTEGER) > CAST(strftime('%s','now') AS INTEGER) AND CAST(?20 AS INTEGER) <= CAST(?18 AS INTEGER) \
             AND CAST(?21 AS INTEGER) > CAST(strftime('%s','now') AS INTEGER) AND CAST(?21 AS INTEGER) <= CAST(?18 AS INTEGER)",
        )
        .bind(&values)?,
        db.prepare(
            "INSERT INTO token_issue(code_hash,operation_id,access_hash,access_expires_at,signing_kid,issued_at,revoked,id_token_hash,dpop_jkt) \
             SELECT ac.code_hash,?19,?22,?20,?12,ac.consumed_at,0,?23,?24 \
             FROM authorization_code ac JOIN eligible_client_session v \
               ON v.client_id=ac.client_id AND v.sid=ac.sid \
             WHERE ac.code_hash=?1 AND ac.consumed_by=?19 \
               AND CAST(?20 AS INTEGER) > CAST(strftime('%s','now') AS INTEGER)",
        )
        .bind(&issue_values)?,
        db.prepare(
            "INSERT INTO atomic_guard(operation_id,passed) VALUES(?19,CASE WHEN EXISTS ( \
             SELECT 1 FROM authorization_code ac JOIN token_issue ti ON ti.code_hash=ac.code_hash \
             JOIN valid_client_session v ON v.client_id=ac.client_id AND v.sid=ac.sid \
             WHERE ac.code_hash=?1 AND ac.client_id=?2 AND ac.sid=?14 \
               AND ac.consumed_by=?19 AND ti.operation_id=?19 AND ti.access_hash=?22 \
               AND (ac.dpop_jkt IS NULL OR ac.dpop_jkt=?24) \
               AND ti.id_token_hash=?23 \
               AND ti.dpop_jkt IS ?24 \
               AND ti.access_expires_at=?20 AND ac.expires_at > CAST(strftime('%s','now') AS INTEGER) \
               AND CAST(?21 AS INTEGER) > CAST(strftime('%s','now') AS INTEGER) AND CAST(?21 AS INTEGER) <= CAST(?18 AS INTEGER) \
             ) THEN 1 ELSE 0 END)",
        )
        .bind(&issue_values)?,
    ];
    if let Some(vault) = &context.vault {
        let vault_values = [
            JsValue::from_str(&access_hash),
            JsValue::from_str(&vault.grant_id),
            JsValue::from_f64(vault.grant_version as f64),
            JsValue::from_str(&vault.resource),
            JsValue::from_str(&vault.attribute_id),
            JsValue::from_str(exchange.code_digest()),
        ];
        statements.push(
            db.prepare(
                "INSERT INTO vault_oauth_token_context \
                 (access_hash,grant_id,grant_version,resource,attribute_id) \
                 SELECT ?1,?2,?3,?4,?5 FROM token_issue ti \
                 JOIN vault_oauth_code_context vc ON vc.code_hash=ti.code_hash \
                 JOIN vault_oauth_grant g ON g.grant_id=vc.grant_id \
                 WHERE ti.access_hash=?1 AND ti.code_hash=?6 AND ti.revoked=0 \
                 AND ti.dpop_jkt IS NOT NULL AND vc.grant_id=?2 \
                 AND vc.grant_version=?3 AND vc.resource=?4 AND vc.attribute_id=?5 \
                 AND g.version=?3 AND g.revoked=0 AND g.expires_at>=ti.access_expires_at",
            )
            .bind(&vault_values)?,
        );
        statements.push(
            db.prepare(
                "INSERT INTO atomic_guard(operation_id,passed) \
                 VALUES(?1,CASE WHEN EXISTS (SELECT 1 FROM vault_oauth_token_context \
                 WHERE access_hash=?1 AND grant_id=?2 AND grant_version=?3 \
                 AND resource=?4 AND attribute_id=?5) THEN 1 ELSE 0 END)",
            )
            .bind(&vault_values[..5])?,
        );
    }
    statements.push(
        db.prepare("DELETE FROM atomic_guard WHERE operation_id=?19")
            .bind(&values[..19])?,
    );
    if context.vault.is_some() {
        statements.push(
            db.prepare("DELETE FROM atomic_guard WHERE operation_id=?1")
                .bind(&[JsValue::from_str(&access_hash)])?,
        );
    }
    let commit = db.batch(statements).await;
    if let Err(error) = commit {
        let consumed = db
            .prepare("SELECT consumed_by FROM authorization_code WHERE code_hash=?1")
            .bind(&[JsValue::from_str(exchange.code_digest())])?
            .first::<ConsumedCodeRow>(None)
            .await;
        if consumed
            .ok()
            .flatten()
            .and_then(|row| row.consumed_by)
            .is_some_and(|winner| winner != operation_id)
        {
            revoke_reused_code(db, input, dpop_proof.map(|(proof, _)| proof), random).await?;
            return Err(worker::Error::RustError("invalid_grant".into()));
        }
        return Err(error);
    }

    Ok(response)
}

#[cfg(target_arch = "wasm32")]
pub(super) async fn read_bounded_body(
    request: &mut worker::Request,
    maximum_bytes: usize,
) -> worker::Result<String> {
    use futures_util::StreamExt;

    let mut stream = request.stream()?;
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if body.len().saturating_add(chunk.len()) > maximum_bytes {
            return Err(worker::Error::RustError("invalid_request".into()));
        }
        body.extend_from_slice(&chunk);
    }
    String::from_utf8(body).map_err(|_| worker::Error::RustError("invalid_request".into()))
}

#[cfg(target_arch = "wasm32")]
pub(super) fn oauth_error_response(
    code: &str,
    status: u16,
    basic_challenge: bool,
) -> worker::Result<worker::Response> {
    let body = TokenEndpointErrorBody {
        error: code.to_owned(),
    };
    let builder = worker::Response::builder()
        .with_status(status)
        .with_header("Cache-Control", "no-store")?
        .with_header("Pragma", "no-cache")?;
    let builder = if basic_challenge && status == 401 {
        builder.with_header("WWW-Authenticate", "Basic realm=\"mikaki-token\"")?
    } else {
        builder
    };
    builder.from_json(&body)
}

#[cfg(target_arch = "wasm32")]
pub(super) fn oauth_error_from_worker(error: worker::Error) -> (&'static str, u16) {
    match error {
        worker::Error::RustError(code) if code == "invalid_request" => ("invalid_request", 400),
        worker::Error::RustError(code) if code == "unsupported_grant_type" => {
            ("unsupported_grant_type", 400)
        }
        worker::Error::RustError(code) if code == "invalid_client" => ("invalid_client", 401),
        worker::Error::RustError(code) if code == "invalid_grant" => ("invalid_grant", 400),
        worker::Error::RustError(code) if code == "invalid_target" => ("invalid_target", 400),
        worker::Error::RustError(code) if code == "invalid_dpop_proof" => {
            ("invalid_dpop_proof", 400)
        }
        worker::Error::RustError(code) if code == "use_dpop_nonce" => ("use_dpop_nonce", 400),
        _ => ("server_error", 500),
    }
}

#[cfg(target_arch = "wasm32")]
pub(super) fn configured_issuer(input: &str) -> Option<String> {
    if input.len() < 9
        || input.len() > 2048
        || !input.starts_with("https://")
        || input.ends_with('/')
        || input
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        || input.contains(['?', '#'])
    {
        return None;
    }
    let remainder = input.strip_prefix("https://")?;
    let authority = remainder.split('/').next()?;
    if authority.is_empty() || authority.contains('@') || authority != remainder {
        return None;
    }
    Some(input.to_owned())
}

#[cfg(target_arch = "wasm32")]
pub(super) fn conformance_deployment(env: &worker::Env) -> worker::Result<bool> {
    match env.var("MIKAKI_DEPLOYMENT_PROFILE") {
        Err(_) => Ok(false),
        Ok(value) if value.to_string() == "normal" => Ok(false),
        Ok(value) if value.to_string() == "fapi2" => Ok(false),
        Ok(value) if value.to_string() == "conformance" => Ok(true),
        _ => Err(worker::Error::RustError(
            "invalid deployment profile".into(),
        )),
    }
}

#[cfg(target_arch = "wasm32")]
pub(super) fn fapi2_deployment(env: &worker::Env) -> worker::Result<bool> {
    match env.var("MIKAKI_DEPLOYMENT_PROFILE") {
        Err(_) => Ok(false),
        Ok(value) if value.to_string() == "normal" || value.to_string() == "conformance" => {
            Ok(false)
        }
        Ok(value) if value.to_string() == "fapi2" => Ok(true),
        _ => Err(worker::Error::RustError(
            "invalid deployment profile".into(),
        )),
    }
}

#[cfg(target_arch = "wasm32")]
pub(super) fn dpop_nonce_required(env: &worker::Env) -> worker::Result<bool> {
    if fapi2_deployment(env)? {
        return Ok(true);
    }
    match env.var("MIKAKI_DPOP_NONCE_MODE") {
        Err(_) => Ok(false),
        Ok(value) if value.to_string() == "off" => Ok(false),
        Ok(value) if value.to_string() == "required" => Ok(true),
        _ => Err(worker::Error::RustError("invalid DPoP nonce mode".into())),
    }
}

#[cfg(target_arch = "wasm32")]
pub(super) fn dpop_nonce_error_response(
    nonce: &str,
    resource: bool,
) -> worker::Result<worker::Response> {
    let builder = worker::Response::builder()
        .with_status(if resource { 401 } else { 400 })
        .with_header("Cache-Control", "no-store")?
        .with_header("Pragma", "no-cache")?
        .with_header("DPoP-Nonce", nonce)?;
    let builder = if resource {
        builder.with_header("WWW-Authenticate", "DPoP error=\"use_dpop_nonce\"")?
    } else {
        builder
    };
    builder.from_json(&TokenEndpointErrorBody {
        error: "use_dpop_nonce".into(),
    })
}

#[cfg(target_arch = "wasm32")]
pub(super) async fn issue_token_response(
    request: &mut worker::Request,
    env: &worker::Env,
) -> worker::Result<TokenEndpointSuccess> {
    let db = env.d1("DB")?;
    let policy = WorkerRuntimePolicy::from_db(&db).await?;
    let issuer = env
        .var("MIKAKI_ISSUER")
        .map_err(|_| worker::Error::RustError("server_error".into()))?
        .to_string();
    let issuer = configured_issuer(&issuer)
        .ok_or_else(|| worker::Error::RustError("server_error".into()))?;
    let token_endpoint = format!("{issuer}/token");
    if request.url()?.to_string() != token_endpoint {
        return Err(worker::Error::RustError("invalid_client".into()));
    }
    let content_type = request
        .headers()
        .get("content-type")?
        .ok_or_else(|| worker::Error::RustError("invalid_request".into()))?;
    if !content_type.split(';').next().is_some_and(|value| {
        value
            .trim()
            .eq_ignore_ascii_case("application/x-www-form-urlencoded")
    }) {
        return Err(worker::Error::RustError("invalid_request".into()));
    }
    let body = read_bounded_body(request, policy.form_body_bytes).await?;
    let authorization = request.headers().get("authorization")?;
    let conformance = conformance_deployment(env)?;
    let fapi = fapi2_deployment(env)?;
    let now_ms = js_sys::Date::now();
    if !now_ms.is_finite() || now_ms < 0.0 {
        return Err(worker::Error::RustError("server_error".into()));
    }
    let now = (now_ms / 1000.0).floor() as u64;
    let mut random = WorkersCryptoRandom;
    let dpop_proof = request
        .headers()
        .get("dpop")?
        .map(|compact| {
            mikaki_oidc::verify_dpop_proof(
                &compact,
                "POST",
                &token_endpoint,
                mikaki_oidc::DpopTarget::Token,
                now,
            )
            .map_err(|_| worker::Error::RustError("invalid_dpop_proof".into()))
        })
        .transpose()?;
    if fapi && dpop_proof.is_none() {
        return Err(worker::Error::RustError("invalid_dpop_proof".into()));
    }
    let require_nonce = dpop_nonce_required(env)?;
    if require_nonce && let Some(proof) = &dpop_proof {
        let _ =
            dpop::current_nonce(&db, dpop::NonceScope::AuthorizationServer, &mut random).await?;
        if !dpop::accepts_nonce(&db, dpop::NonceScope::AuthorizationServer, proof.nonce()).await? {
            return Err(worker::Error::RustError("use_dpop_nonce".into()));
        }
    }
    let authenticated = if let Some(header) = authorization.as_deref() {
        if !conformance {
            return Err(worker::Error::RustError("invalid_client".into()));
        }
        authenticate_secret_token_request(
            &db,
            secret_form(&body)?,
            Some(header),
            &token_endpoint,
            now,
            &policy,
            &mut random,
        )
        .await?
    } else if conformance
        && let Ok(form) = secret_form(&body)
        && form.client_secret.is_some()
    {
        authenticate_secret_token_request(
            &db,
            form,
            None,
            &token_endpoint,
            now,
            &policy,
            &mut random,
        )
        .await?
    } else if !conformance
        && !fapi
        && serde_urlencoded::from_str::<mikaki_oidc::PublicTokenEndpointInput>(&body).is_ok()
    {
        accept_native_token_request(&db, &body, &token_endpoint, now, &mut random).await?
    } else {
        let input = parse_token_endpoint_form(&body, &policy, fapi)?;
        authenticate_token_request(
            &db,
            input,
            &token_endpoint,
            &issuer,
            fapi,
            now,
            &policy,
            &mut random,
        )
        .await?
    };
    let dpop_receipt = if let Some(proof) = &dpop_proof {
        let mut receipt = [0u8; 32];
        mikaki_oidc::CryptographicRandom::fill(&mut random, &mut receipt)
            .map_err(|_| worker::Error::RustError("server_error".into()))?;
        let receipt = URL_SAFE_NO_PAD.encode(receipt);
        dpop::accept_token_proof(&db, proof, &receipt, require_nonce).await?;
        Some(receipt)
    } else {
        None
    };
    let private_jwk = env
        .secret("OP_PRIVATE_JWK")
        .map_err(|_| worker::Error::RustError("server_error".into()))?
        .to_string();
    let signer = WorkerTokenSigner::from_secret(&private_jwk).await?;
    let vault_preview = env
        .var("MIKAKI_NATIVE_VAULT_OAUTH")
        .ok()
        .is_some_and(|value| value.to_string() == "preview");
    let context = load_authorization_code_context(
        &db,
        &authenticated,
        &signer,
        fapi,
        vault_preview,
        dpop_proof.as_ref(),
        &mut random,
    )
    .await?;
    if context.vault.is_some() && dpop_proof.is_none() {
        return Err(worker::Error::RustError("invalid_dpop_proof".into()));
    }
    let response = commit_authorization_code_exchange(
        &db,
        &authenticated,
        &context,
        &signer,
        &issuer,
        now,
        policy.access_token_ttl_seconds(),
        policy.id_token_ttl_seconds(),
        policy.response_bytes(),
        &mut random,
        dpop_proof.as_ref().zip(dpop_receipt.as_deref()),
        fapi,
    )
    .await?;
    Ok(response)
}

#[cfg(target_arch = "wasm32")]
pub(super) async fn token_route(
    mut request: worker::Request,
    context: worker::RouteContext<()>,
) -> worker::Result<worker::Response> {
    let basic_challenge = request
        .headers()
        .get("authorization")?
        .and_then(|header| header.split_once(' ').map(|(scheme, _)| scheme.to_owned()))
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("Basic"));
    match issue_token_response(&mut request, &context.env).await {
        Ok(body) => worker::Response::builder()
            .with_header("Cache-Control", "no-store")?
            .with_header("Pragma", "no-cache")?
            .from_json(&body),
        Err(error) => {
            let (code, status) = oauth_error_from_worker(error);
            if code == "use_dpop_nonce" {
                let db = context.env.d1("DB")?;
                let nonce = dpop::current_nonce(
                    &db,
                    dpop::NonceScope::AuthorizationServer,
                    &mut WorkersCryptoRandom,
                )
                .await?;
                return dpop_nonce_error_response(&nonce, false);
            }
            oauth_error_response(code, status, basic_challenge)
        }
    }
}
