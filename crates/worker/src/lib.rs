//! Cloudflare Workers platform adapter. Protocol decisions remain in `sakimori-oidc`.

#[cfg(target_arch = "wasm32")]
use serde::{Deserialize, Serialize};

#[cfg(target_arch = "wasm32")]
use sha2::{Digest, Sha256};

#[cfg(target_arch = "wasm32")]
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::JsCast;

#[cfg(target_arch = "wasm32")]
pub struct WorkersCryptoRandom;

/// Token request whose assertion replay reservation is tied to this request.
/// The reservation ID is persisted by D1 and must be reused by code exchange.
#[cfg(target_arch = "wasm32")]
#[must_use = "use the assertion reservation receipt in the final code exchange"]
pub struct AuthenticatedTokenRequest {
    request: sakimori_oidc::AuthenticatedTokenEndpointInput,
    assertion_reservation_id: String,
}

#[cfg(target_arch = "wasm32")]
impl AuthenticatedTokenRequest {
    pub fn request(&self) -> &sakimori_oidc::AuthenticatedTokenEndpointInput {
        &self.request
    }

    pub fn assertion_reservation_id(&self) -> &str {
        &self.assertion_reservation_id
    }
}

#[cfg(target_arch = "wasm32")]
#[derive(Deserialize)]
struct ClientAssertionKeyRow {
    client_id: String,
    kid: String,
    client_revision: u64,
    key_revision: u64,
    client_active: i64,
    key_active: i64,
    algorithm: String,
    public_key_sec1: Vec<u8>,
}

#[cfg(target_arch = "wasm32")]
#[derive(Deserialize)]
struct AuthorizationCodeContextRow {
    client_id: String,
    sid: String,
    sub: String,
    nonce: String,
    auth_time: i64,
    parent_expires_at: i64,
    signing_generation: i64,
    public_jwk: String,
}

#[cfg(target_arch = "wasm32")]
#[derive(Deserialize)]
struct SigningPublicKeyRow {
    public_jwk: String,
}

#[cfg(target_arch = "wasm32")]
#[derive(Deserialize)]
struct UserInfoRow {
    sub: String,
}

#[cfg(target_arch = "wasm32")]
#[derive(Serialize)]
struct JwksResponse {
    keys: Vec<serde_json::Value>,
}

#[cfg(target_arch = "wasm32")]
#[derive(Serialize)]
struct UserInfoResponse {
    sub: String,
}

/// Current authorization and session facts needed to create the signed token
/// response. The final D1 exchange must recheck every fact before consuming the
/// code because this read is only a preflight for signing.
#[cfg(target_arch = "wasm32")]
#[must_use = "use this snapshot only to prepare tokens for a conditional D1 exchange"]
pub struct AuthorizationCodeContext {
    client_id: String,
    sid: String,
    sub: String,
    nonce: String,
    auth_time: u64,
    parent_expires_at: u64,
    signing_kid: String,
    signing_generation: u64,
    public_jwk: String,
}

#[cfg(target_arch = "wasm32")]
impl AuthorizationCodeContext {
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    pub fn sid(&self) -> &str {
        &self.sid
    }

    pub fn subject(&self) -> &str {
        &self.sub
    }

    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    pub fn auth_time(&self) -> u64 {
        self.auth_time
    }

    pub fn parent_expires_at(&self) -> u64 {
        self.parent_expires_at
    }

    pub fn signing_kid(&self) -> &str {
        &self.signing_kid
    }

    pub fn signing_generation(&self) -> u64 {
        self.signing_generation
    }
}

#[cfg(target_arch = "wasm32")]
#[derive(Serialize)]
struct TokenEndpointSuccess {
    access_token: String,
    token_type: &'static str,
    expires_in: u64,
    scope: &'static str,
    id_token: String,
}

#[cfg(target_arch = "wasm32")]
#[derive(Serialize)]
struct TokenEndpointErrorBody {
    error: String,
}

#[cfg(target_arch = "wasm32")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CompiledWorkerPolicy {
    schema_version: u32,
    policy_revision: String,
    projection_revision: String,
    assertion_ttl_seconds: u64,
    clock_skew_seconds: u64,
    access_token_ttl_seconds: u64,
    id_token_ttl_seconds: u64,
    response_bytes: u64,
    jwt_bytes: u64,
    form_body_bytes: u64,
}

#[cfg(target_arch = "wasm32")]
pub struct WorkerRuntimePolicy {
    assertion: sakimori_oidc::ClientAssertionPolicy,
    jwt_bytes: usize,
    form_body_bytes: usize,
    access_token_ttl_seconds: u64,
    id_token_ttl_seconds: u64,
    response_bytes: usize,
    policy_revision: String,
}

#[cfg(target_arch = "wasm32")]
impl WorkerRuntimePolicy {
    pub fn from_env(env: &worker::Env) -> worker::Result<Self> {
        let json = env
            .var("SAKIMORI_WORKER_POLICY")
            .map_err(|_| worker::Error::RustError("runtime policy is unavailable".into()))?
            .to_string();
        Self::from_compiled_json(&json)
    }

    pub fn from_compiled_json(json: &str) -> worker::Result<Self> {
        let compiled: CompiledWorkerPolicy = serde_json::from_str(json)
            .map_err(|_| worker::Error::RustError("invalid runtime policy".into()))?;
        if compiled.schema_version != 2
            || compiled.policy_revision.len() != 64
            || compiled.projection_revision.len() != 64
            || !compiled
                .policy_revision
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || compiled.jwt_bytes == 0
            || compiled.jwt_bytes > 1_048_576
            || compiled.form_body_bytes == 0
            || compiled.form_body_bytes > 1_048_576
            || compiled.jwt_bytes.saturating_add(4096) > compiled.form_body_bytes
            || compiled.access_token_ttl_seconds == 0
            || compiled.id_token_ttl_seconds == 0
            || compiled.access_token_ttl_seconds > i32::MAX as u64
            || compiled.id_token_ttl_seconds > i32::MAX as u64
            || compiled.response_bytes == 0
            || compiled.response_bytes > 1_048_576
        {
            return Err(worker::Error::RustError("invalid runtime policy".into()));
        }
        let canonical = serde_json::json!({
            "assertion_ttl_seconds": compiled.assertion_ttl_seconds,
            "clock_skew_seconds": compiled.clock_skew_seconds,
            "access_token_ttl_seconds": compiled.access_token_ttl_seconds,
            "form_body_bytes": compiled.form_body_bytes,
            "id_token_ttl_seconds": compiled.id_token_ttl_seconds,
            "response_bytes": compiled.response_bytes,
            "jwt_bytes": compiled.jwt_bytes,
            "policy_revision": compiled.policy_revision,
            "schema_version": compiled.schema_version,
        });
        let canonical = serde_json::to_vec(&canonical)
            .map_err(|_| worker::Error::RustError("invalid runtime policy".into()))?;
        let digest = Sha256::digest(canonical);
        let actual_projection_revision: String =
            digest.iter().map(|byte| format!("{byte:02x}")).collect();
        if actual_projection_revision != compiled.projection_revision {
            return Err(worker::Error::RustError("invalid runtime policy".into()));
        }
        let valid_revision = |revision: &str| {
            revision.len() == 64
                && revision
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        };
        if !valid_revision(&compiled.policy_revision)
            || !valid_revision(&compiled.projection_revision)
            || compiled.assertion_ttl_seconds > i32::MAX as u64
            || compiled.clock_skew_seconds > i32::MAX as u64
        {
            return Err(worker::Error::RustError("invalid runtime policy".into()));
        }
        let jwt_bytes = usize::try_from(compiled.jwt_bytes)
            .map_err(|_| worker::Error::RustError("invalid runtime policy".into()))?;
        let form_body_bytes = usize::try_from(compiled.form_body_bytes)
            .map_err(|_| worker::Error::RustError("invalid runtime policy".into()))?;
        let response_bytes = usize::try_from(compiled.response_bytes)
            .map_err(|_| worker::Error::RustError("invalid runtime policy".into()))?;
        let assertion = sakimori_oidc::ClientAssertionPolicy::from_seconds(
            compiled.assertion_ttl_seconds,
            compiled.clock_skew_seconds,
        )
        .map_err(|_| worker::Error::RustError("invalid runtime policy".into()))?;
        Ok(Self {
            assertion,
            jwt_bytes,
            form_body_bytes,
            access_token_ttl_seconds: compiled.access_token_ttl_seconds,
            id_token_ttl_seconds: compiled.id_token_ttl_seconds,
            response_bytes,
            policy_revision: compiled.policy_revision,
        })
    }

    pub fn policy_revision(&self) -> &str {
        &self.policy_revision
    }

    pub fn access_token_ttl_seconds(&self) -> u64 {
        self.access_token_ttl_seconds
    }

    pub fn id_token_ttl_seconds(&self) -> u64 {
        self.id_token_ttl_seconds
    }

    pub fn response_bytes(&self) -> usize {
        self.response_bytes
    }
}

#[cfg(target_arch = "wasm32")]
pub fn parse_token_endpoint_form(
    body: &str,
    policy: &WorkerRuntimePolicy,
) -> worker::Result<sakimori_oidc::ValidatedTokenEndpointInput> {
    if body.len() > policy.form_body_bytes {
        return Err(worker::Error::RustError("invalid_request".into()));
    }
    let input: sakimori_oidc::TokenEndpointInput = serde_urlencoded::from_str(body)
        .map_err(|_| worker::Error::RustError("invalid_request".into()))?;
    input.validate(policy.jwt_bytes).map_err(|error| {
        let code = match error {
            sakimori_oidc::TokenEndpointInputError::UnsupportedGrantType => {
                "unsupported_grant_type"
            }
            sakimori_oidc::TokenEndpointInputError::InvalidClient => "invalid_client",
            sakimori_oidc::TokenEndpointInputError::InvalidRequest => "invalid_request",
        };
        worker::Error::RustError(code.into())
    })
}

#[cfg(target_arch = "wasm32")]
impl sakimori_oidc::CryptographicRandom for WorkersCryptoRandom {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), sakimori_oidc::CodeEntropyError> {
        let global = js_sys::global();
        let crypto = js_sys::Reflect::get(&global, &"crypto".into())
            .map_err(|_| sakimori_oidc::CodeEntropyError)?
            .dyn_into::<web_sys::Crypto>()
            .map_err(|_| sakimori_oidc::CodeEntropyError)?;
        crypto
            .get_random_values_with_u8_array(output)
            .map(|_| ())
            .map_err(|_| sakimori_oidc::CodeEntropyError)
    }
}

/// Atomically reserve a signature-verified private_key_jwt `jti` and recheck
/// its client/key revisions. A D1 constraint failure rolls back the assertion
/// insert, so callers must reject the assertion and must not continue the grant.
#[cfg(target_arch = "wasm32")]
async fn accept_client_assertion(
    db: &worker::d1::D1Database,
    assertion: &sakimori_oidc::VerifiedClientAssertion,
    endpoint: &str,
    random: &mut impl sakimori_oidc::CryptographicRandom,
) -> worker::Result<String> {
    use wasm_bindgen::JsValue;

    if endpoint.is_empty() || assertion.audience() != endpoint {
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
            "INSERT INTO atomic_guard(operation_id,passed) VALUES(?1,CASE WHEN EXISTS ( \
             SELECT 1 FROM assertion_use WHERE accepted_by=?1 AND client_id=?2 AND jti=?3 AND endpoint=?4 \
             ) THEN 1 ELSE 0 END)",
        )
        .bind(&values[..4])?,
        db.prepare("DELETE FROM atomic_guard WHERE operation_id=?1")
            .bind(&[JsValue::from_str(&operation_id)])?,
    ])
    .await?;
    Ok(operation_id)
}

/// Load one registered key, verify a private_key_jwt in the Rust core, and
/// atomically reserve its jti after rechecking the same registration revisions.
#[cfg(target_arch = "wasm32")]
async fn verify_and_accept_client_assertion(
    db: &worker::d1::D1Database,
    client_id: &str,
    compact: &str,
    audience: &str,
    endpoint: &str,
    now: u64,
    policy: &WorkerRuntimePolicy,
    random: &mut impl sakimori_oidc::CryptographicRandom,
) -> worker::Result<(sakimori_oidc::VerifiedClientAssertion, String)> {
    use wasm_bindgen::JsValue;

    if client_id.is_empty() || client_id.len() > 128 {
        return Err(worker::Error::RustError("invalid_client".into()));
    }
    let kid = sakimori_oidc::client_assertion_key_id(compact, policy.jwt_bytes)
        .map_err(|_| worker::Error::RustError("invalid_client".into()))?;
    let values = [JsValue::from_str(client_id), JsValue::from_str(&kid)];
    let row = db
        .prepare(
            "SELECT c.client_id, k.kid, c.revision AS client_revision, \
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
        || row.algorithm != "ES256"
    {
        return Err(worker::Error::RustError("invalid_client".into()));
    }
    let key = sakimori_oidc::ClientAssertionKey::new(
        row.client_id,
        row.kid,
        row.client_revision,
        row.key_revision,
        true,
        row.public_key_sec1,
    );
    let assertion = key
        .verify_private_key_jwt(compact, audience, now, policy.assertion, policy.jwt_bytes)
        .map_err(|_| worker::Error::RustError("invalid_client".into()))?;
    let reservation_id = accept_client_assertion(db, &assertion, endpoint, random).await?;
    Ok((assertion, reservation_id))
}

#[cfg(target_arch = "wasm32")]
pub async fn authenticate_token_request(
    db: &worker::d1::D1Database,
    input: sakimori_oidc::ValidatedTokenEndpointInput,
    token_endpoint: &str,
    now: u64,
    policy: &WorkerRuntimePolicy,
    random: &mut impl sakimori_oidc::CryptographicRandom,
) -> worker::Result<AuthenticatedTokenRequest> {
    let (assertion, assertion_reservation_id) = verify_and_accept_client_assertion(
        db,
        input.client_id(),
        input.assertion().as_str(),
        token_endpoint,
        token_endpoint,
        now,
        policy,
        random,
    )
    .await?;
    let request = input
        .authenticate(assertion, token_endpoint)
        .map_err(|_| worker::Error::RustError("invalid_client".into()))?;
    Ok(AuthenticatedTokenRequest {
        request,
        assertion_reservation_id,
    })
}

/// Read the one-use code's immutable claims and current eligibility facts
/// before signing. The commit step must repeat the conditional predicates.
#[cfg(target_arch = "wasm32")]
pub async fn load_authorization_code_context(
    db: &worker::d1::D1Database,
    input: &AuthenticatedTokenRequest,
    signer: &sakimori_oidc::P256TokenSigner,
    random: &mut impl sakimori_oidc::CryptographicRandom,
) -> worker::Result<AuthorizationCodeContext> {
    use wasm_bindgen::JsValue;

    let request = input.request();
    let assertion = request.assertion();
    let exchange = request.exchange();
    let values = [
        JsValue::from_str(request.client_id()),
        JsValue::from_str(exchange.code_digest()),
        JsValue::from_str(exchange.redirect_uri()),
        JsValue::from_str(exchange.pkce_challenge()),
        JsValue::from_str(&assertion.client_revision().to_string()),
        JsValue::from_str(assertion.key_id()),
        JsValue::from_str(&assertion.key_revision().to_string()),
        JsValue::from_str(assertion.jti()),
        JsValue::from_str(assertion.audience()),
        JsValue::from_str(input.assertion_reservation_id()),
        JsValue::from_str(&assertion.retain_until().to_string()),
        JsValue::from_str(signer.kid()),
    ];
    let row = db
        .prepare(
            "SELECT ac.client_id, cs.sid, v.sub, cc.nonce, sx.auth_time, \
             v.expires_at AS parent_expires_at, sk.generation AS signing_generation, \
             sk.public_jwk AS public_jwk \
             FROM authorization_code ac \
             JOIN eligible_client_session v ON v.client_id=ac.client_id AND v.sid=ac.sid \
             JOIN client_session cs ON cs.client_id=ac.client_id AND cs.sid=ac.sid \
             JOIN sso_context sx ON sx.sso_id=cs.sso_id \
             JOIN code_context cc ON cc.code_hash=ac.code_hash \
             JOIN client c ON c.client_id=ac.client_id \
             JOIN client_key ck ON ck.client_id=c.client_id \
             JOIN assertion_use au ON au.client_id=c.client_id \
             JOIN signing_key sk ON sk.kid=?12 \
             WHERE c.client_id=?1 AND c.active=1 AND c.revision=?5 \
             AND ac.code_hash=?2 AND ac.client_id=?1 AND ac.consumed_by IS NULL \
             AND ac.redirect_uri=?3 AND ac.pkce_challenge=?4 \
             AND ac.expires_at > CAST(strftime('%s','now') AS INTEGER) \
             AND ck.kid=?6 AND ck.revision=?7 AND ck.active=1 \
             AND au.jti=?8 AND au.endpoint=?9 AND au.accepted_by=?10 \
             AND au.retain_until=?11 AND au.retain_until > CAST(strftime('%s','now') AS INTEGER) \
             AND sk.active=1 LIMIT 1",
        )
        .bind(&values)?
        .first::<AuthorizationCodeContextRow>(None)
        .await?;
    let Some(row) = row else {
        revoke_reused_code(db, input, random).await?;
        return Err(worker::Error::RustError("invalid_grant".into()));
    };
    if row.client_id != request.client_id() || !signer.matches_public_jwk(&row.public_jwk) {
        return Err(worker::Error::RustError("server_error".into()));
    }
    let auth_time = u64::try_from(row.auth_time)
        .map_err(|_| worker::Error::RustError("invalid_grant".into()))?;
    let parent_expires_at = u64::try_from(row.parent_expires_at)
        .map_err(|_| worker::Error::RustError("invalid_grant".into()))?;
    let signing_generation = u64::try_from(row.signing_generation)
        .map_err(|_| worker::Error::RustError("invalid_grant".into()))?;
    Ok(AuthorizationCodeContext {
        client_id: row.client_id,
        sid: row.sid,
        sub: row.sub,
        nonce: row.nonce,
        auth_time,
        parent_expires_at,
        signing_kid: signer.kid().to_owned(),
        signing_generation,
        public_jwk: row.public_jwk,
    })
}

#[cfg(target_arch = "wasm32")]
async fn revoke_reused_code(
    db: &worker::d1::D1Database,
    input: &AuthenticatedTokenRequest,
    random: &mut impl sakimori_oidc::CryptographicRandom,
) -> worker::Result<()> {
    use wasm_bindgen::JsValue;

    let request = input.request();
    let assertion = request.assertion();
    let exchange = request.exchange();
    let mut operation = [0u8; 32];
    random
        .fill(&mut operation)
        .map_err(|_| worker::Error::RustError("server_error".into()))?;
    let operation_id = URL_SAFE_NO_PAD.encode(operation);
    let values = [
        JsValue::from_str(exchange.code_digest()),
        JsValue::from_str(request.client_id()),
        JsValue::from_str(exchange.redirect_uri()),
        JsValue::from_str(exchange.pkce_challenge()),
        JsValue::from_str(&assertion.client_revision().to_string()),
        JsValue::from_str(assertion.key_id()),
        JsValue::from_str(&assertion.key_revision().to_string()),
        JsValue::from_str(assertion.jti()),
        JsValue::from_str(assertion.audience()),
        JsValue::from_str(input.assertion_reservation_id()),
        JsValue::from_str(&assertion.retain_until().to_string()),
        JsValue::from_str(&operation_id),
    ];
    db.batch(vec![
        db.prepare(
            "UPDATE token_issue SET revoked=1 WHERE code_hash=?1 AND revoked=0 \
             AND EXISTS (SELECT 1 FROM authorization_code ac \
               JOIN client c ON c.client_id=ac.client_id \
               JOIN client_key ck ON ck.client_id=c.client_id \
               JOIN assertion_use au ON au.client_id=c.client_id \
               WHERE ac.code_hash=?1 AND ac.client_id=?2 AND ac.redirect_uri=?3 \
                 AND ac.pkce_challenge=?4 AND ac.consumed_by IS NOT NULL \
                 AND c.active=1 AND c.revision=?5 \
                 AND ck.kid=?6 AND ck.revision=?7 AND ck.active=1 \
                 AND au.jti=?8 AND au.endpoint=?9 AND au.accepted_by=?10 \
                 AND au.retain_until=?11 AND au.retain_until > CAST(strftime('%s','now') AS INTEGER))",
        )
        .bind(&values)?,
        db.prepare(
            "INSERT INTO atomic_guard(operation_id,passed) VALUES(?12,CASE WHEN NOT EXISTS ( \
             SELECT 1 FROM token_issue ti \
             JOIN authorization_code ac ON ac.code_hash=ti.code_hash \
             JOIN client c ON c.client_id=ac.client_id \
             JOIN client_key ck ON ck.client_id=c.client_id \
             JOIN assertion_use au ON au.client_id=c.client_id \
             WHERE ti.code_hash=?1 AND ti.revoked=0 AND ac.client_id=?2 \
               AND ac.redirect_uri=?3 AND ac.pkce_challenge=?4 \
               AND ac.consumed_by IS NOT NULL AND c.active=1 AND c.revision=?5 \
               AND ck.kid=?6 AND ck.revision=?7 AND ck.active=1 \
               AND au.jti=?8 AND au.endpoint=?9 AND au.accepted_by=?10 \
               AND au.retain_until=?11 AND au.retain_until > CAST(strftime('%s','now') AS INTEGER) \
             ) THEN 1 ELSE 0 END)",
        )
        .bind(&values)?,
        db.prepare("DELETE FROM atomic_guard WHERE operation_id=?12").bind(&values)?,
    ])
    .await?;
    Ok(())
}

/// Sign the response first, then consume the code and persist the opaque token
/// in a single D1 batch guarded by all authorization and key revisions.
#[cfg(target_arch = "wasm32")]
async fn commit_authorization_code_exchange(
    db: &worker::d1::D1Database,
    input: &AuthenticatedTokenRequest,
    context: &AuthorizationCodeContext,
    signer: &sakimori_oidc::P256TokenSigner,
    issuer: &str,
    now: u64,
    access_ttl_seconds: u64,
    id_token_ttl_seconds: u64,
    response_bytes: usize,
    random: &mut impl sakimori_oidc::CryptographicRandom,
) -> worker::Result<TokenEndpointSuccess> {
    use wasm_bindgen::JsValue;

    if context.client_id() != input.request().client_id()
        || context.signing_kid() != signer.kid()
        || now > i64::MAX as u64
    {
        return Err(worker::Error::RustError("invalid_grant".into()));
    }
    let access_expires_at = now
        .checked_add(access_ttl_seconds)
        .ok_or_else(|| worker::Error::RustError("invalid_grant".into()))?
        .min(context.parent_expires_at());
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
        .map_err(|_| worker::Error::RustError("server_error".into()))?;

    let mut access_secret = [0u8; 32];
    random
        .fill(&mut access_secret)
        .map_err(|_| worker::Error::RustError("server_error".into()))?;
    let access_token = URL_SAFE_NO_PAD.encode(access_secret);
    let access_hash = URL_SAFE_NO_PAD.encode(Sha256::digest(access_secret));
    access_secret.fill(0);
    let mut operation = [0u8; 32];
    random
        .fill(&mut operation)
        .map_err(|_| worker::Error::RustError("server_error".into()))?;
    let operation_id = URL_SAFE_NO_PAD.encode(operation);
    let response = TokenEndpointSuccess {
        access_token,
        token_type: "Bearer",
        expires_in: access_expires_at - now,
        scope: "openid",
        id_token,
    };
    if serde_json::to_vec(&response)
        .map_err(worker::Error::from)?
        .len()
        > response_bytes
    {
        return Err(worker::Error::RustError("server_error".into()));
    }

    let request = input.request();
    let assertion = request.assertion();
    let exchange = request.exchange();
    let values = [
        JsValue::from_str(exchange.code_digest()),
        JsValue::from_str(request.client_id()),
        JsValue::from_str(exchange.redirect_uri()),
        JsValue::from_str(exchange.pkce_challenge()),
        JsValue::from_str(&assertion.client_revision().to_string()),
        JsValue::from_str(assertion.key_id()),
        JsValue::from_str(&assertion.key_revision().to_string()),
        JsValue::from_str(assertion.jti()),
        JsValue::from_str(assertion.audience()),
        JsValue::from_str(input.assertion_reservation_id()),
        JsValue::from_str(&assertion.retain_until().to_string()),
        JsValue::from_str(context.signing_kid()),
        JsValue::from_str(&context.signing_generation().to_string()),
        JsValue::from_str(context.sid()),
        JsValue::from_str(context.subject()),
        JsValue::from_str(context.nonce()),
        JsValue::from_str(&context.auth_time().to_string()),
        JsValue::from_str(&context.parent_expires_at().to_string()),
        JsValue::from_str(&operation_id),
        JsValue::from_str(&access_expires_at.to_string()),
        JsValue::from_str(&id_token_expires_at.to_string()),
        JsValue::from_str(&access_hash),
        JsValue::from_str(&context.public_jwk),
    ];
    db.batch(vec![
        db.prepare(
            "UPDATE authorization_code SET consumed_by=?19, \
             consumed_at=CAST(strftime('%s','now') AS INTEGER) \
             WHERE code_hash=?1 AND client_id=?2 AND redirect_uri=?3 \
             AND pkce_challenge=?4 AND consumed_by IS NULL \
             AND expires_at > CAST(strftime('%s','now') AS INTEGER) \
             AND EXISTS (SELECT 1 FROM client c WHERE c.client_id=?2 \
               AND c.active=1 AND c.revision=?5) \
             AND EXISTS (SELECT 1 FROM eligible_client_session v \
               WHERE v.client_id=?2 AND v.sid=?14 AND v.sub=?15 AND v.expires_at=?18) \
             AND EXISTS (SELECT 1 FROM client_session cs \
               JOIN sso_context sx ON sx.sso_id=cs.sso_id \
               JOIN code_context cc ON cc.code_hash=?1 \
               WHERE cs.client_id=?2 AND cs.sid=?14 AND sx.auth_time=?17 AND cc.nonce=?16) \
             AND EXISTS (SELECT 1 FROM client_key ck WHERE ck.client_id=?2 \
               AND ck.kid=?6 AND ck.revision=?7 AND ck.active=1) \
             AND EXISTS (SELECT 1 FROM assertion_use au WHERE au.client_id=?2 \
               AND au.jti=?8 AND au.endpoint=?9 AND au.accepted_by=?10 \
               AND au.retain_until=?11 AND au.retain_until > CAST(strftime('%s','now') AS INTEGER)) \
             AND EXISTS (SELECT 1 FROM signing_key sk WHERE sk.kid=?12 \
               AND sk.generation=?13 AND sk.active=1 AND sk.public_jwk=?23) \
             AND ?20 > CAST(strftime('%s','now') AS INTEGER) AND ?20 <= ?18 \
             AND ?21 > CAST(strftime('%s','now') AS INTEGER) AND ?21 <= ?18",
        )
        .bind(&values)?,
        db.prepare(
            "INSERT INTO token_issue(code_hash,operation_id,access_hash,access_expires_at,signing_kid,issued_at,revoked) \
             SELECT ac.code_hash,?19,?22,MIN(?20,v.expires_at),?12,ac.consumed_at,0 \
             FROM authorization_code ac JOIN eligible_client_session v \
               ON v.client_id=ac.client_id AND v.sid=ac.sid \
             WHERE ac.code_hash=?1 AND ac.consumed_by=?19 \
               AND ?20 > CAST(strftime('%s','now') AS INTEGER)",
        )
        .bind(&values)?,
        db.prepare(
            "INSERT INTO atomic_guard(operation_id,passed) VALUES(?19,CASE WHEN EXISTS ( \
             SELECT 1 FROM authorization_code ac JOIN token_issue ti ON ti.code_hash=ac.code_hash \
             JOIN valid_client_session v ON v.client_id=ac.client_id AND v.sid=ac.sid \
             WHERE ac.code_hash=?1 AND ac.client_id=?2 AND ac.sid=?14 \
               AND ac.consumed_by=?19 AND ti.operation_id=?19 AND ti.access_hash=?22 \
               AND ti.access_expires_at=?20 AND ac.expires_at > CAST(strftime('%s','now') AS INTEGER) \
               AND ?21 > CAST(strftime('%s','now') AS INTEGER) AND ?21 <= ?18 \
             ) THEN 1 ELSE 0 END)",
        )
        .bind(&values)?,
        db.prepare("DELETE FROM atomic_guard WHERE operation_id=?19").bind(&values)?,
    ])
    .await?;

    Ok(response)
}

#[cfg(target_arch = "wasm32")]
async fn read_bounded_body(
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
fn oauth_error_response(code: &str, status: u16) -> worker::Result<worker::Response> {
    let body = TokenEndpointErrorBody {
        error: code.to_owned(),
    };
    worker::Response::builder()
        .with_status(status)
        .with_header("Cache-Control", "no-store")?
        .with_header("Pragma", "no-cache")?
        .from_json(&body)
}

#[cfg(target_arch = "wasm32")]
fn oauth_error_from_worker(error: worker::Error) -> (&'static str, u16) {
    match error {
        worker::Error::RustError(code) if code == "invalid_request" => ("invalid_request", 400),
        worker::Error::RustError(code) if code == "unsupported_grant_type" => {
            ("unsupported_grant_type", 400)
        }
        worker::Error::RustError(code) if code == "invalid_client" => ("invalid_client", 401),
        worker::Error::RustError(code) if code == "invalid_grant" => ("invalid_grant", 400),
        _ => ("server_error", 500),
    }
}

#[cfg(target_arch = "wasm32")]
fn configured_issuer(input: &str) -> Option<String> {
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
async fn issue_token_response(
    request: &mut worker::Request,
    env: &worker::Env,
) -> worker::Result<TokenEndpointSuccess> {
    let policy = WorkerRuntimePolicy::from_env(env)?;
    let issuer = env
        .var("SAKIMORI_ISSUER")
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
    let input = parse_token_endpoint_form(&body, &policy)?;
    let now_ms = js_sys::Date::now();
    if !now_ms.is_finite() || now_ms < 0.0 {
        return Err(worker::Error::RustError("server_error".into()));
    }
    let now = (now_ms / 1000.0).floor() as u64;
    let mut random = WorkersCryptoRandom;
    let db = env.d1("DB")?;
    let authenticated =
        authenticate_token_request(&db, input, &token_endpoint, now, &policy, &mut random).await?;
    let private_jwk = env
        .secret("OP_PRIVATE_JWK")
        .map_err(|_| worker::Error::RustError("server_error".into()))?
        .to_string();
    let signer = sakimori_oidc::P256TokenSigner::from_private_jwk(&private_jwk)
        .map_err(|_| worker::Error::RustError("server_error".into()))?;
    let context =
        load_authorization_code_context(&db, &authenticated, &signer, &mut random).await?;
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
    )
    .await?;
    Ok(response)
}

#[cfg(target_arch = "wasm32")]
async fn token_route(
    mut request: worker::Request,
    context: worker::RouteContext<()>,
) -> worker::Result<worker::Response> {
    match issue_token_response(&mut request, &context.env).await {
        Ok(body) => worker::Response::builder()
            .with_header("Cache-Control", "no-store")?
            .with_header("Pragma", "no-cache")?
            .from_json(&body),
        Err(error) => {
            let (code, status) = oauth_error_from_worker(error);
            oauth_error_response(code, status)
        }
    }
}

#[cfg(target_arch = "wasm32")]
async fn jwks_route(
    _request: worker::Request,
    context: worker::RouteContext<()>,
) -> worker::Result<worker::Response> {
    let db = context.env.d1("DB")?;
    let rows = db
        .prepare(
            "SELECT public_jwk FROM signing_key \
             WHERE active=1 AND algorithm='ES256' ORDER BY kid",
        )
        .all()
        .await?
        .results::<SigningPublicKeyRow>()?;
    let mut keys = Vec::with_capacity(rows.len());
    for row in rows {
        let jwk = sakimori_oidc::P256TokenSigner::canonical_public_jwk(&row.public_jwk)
            .ok_or_else(|| worker::Error::RustError("invalid signing key configuration".into()))?;
        keys.push(
            serde_json::from_str(&jwk).map_err(|_| {
                worker::Error::RustError("invalid signing key configuration".into())
            })?,
        );
    }
    worker::Response::builder()
        .with_header("Cache-Control", "public, max-age=60")?
        .from_json(&JwksResponse { keys })
}

#[cfg(target_arch = "wasm32")]
async fn userinfo_route(
    request: worker::Request,
    context: worker::RouteContext<()>,
) -> worker::Result<worker::Response> {
    let unauthorized = || {
        worker::Response::builder()
            .with_status(401)
            .with_header("Cache-Control", "no-store")?
            .with_header("Pragma", "no-cache")?
            .with_header("WWW-Authenticate", "Bearer error=\"invalid_token\"")?
            .from_json(&TokenEndpointErrorBody {
                error: "invalid_token".into(),
            })
    };
    let Some(header) = request.headers().get("authorization")? else {
        return unauthorized();
    };
    let Some((scheme, token)) = header.split_once(' ') else {
        return unauthorized();
    };
    if !scheme.eq_ignore_ascii_case("Bearer")
        || token.len() != 43
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return unauthorized();
    }
    let token_hash = URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()));
    let now_ms = js_sys::Date::now();
    if !now_ms.is_finite() || now_ms < 0.0 {
        return Err(worker::Error::RustError("server_error".into()));
    }
    let now = (now_ms / 1000.0).floor() as i64;
    let db = context.env.d1("DB")?;
    let subject = db
        .prepare(
            "SELECT v.sub FROM token_issue ti \
             JOIN authorization_code ac ON ac.code_hash=ti.code_hash \
             JOIN valid_client_session v ON v.client_id=ac.client_id AND v.sid=ac.sid \
             WHERE ti.access_hash=?1 AND ti.revoked=0 AND ti.access_expires_at>?2",
        )
        .bind(&[
            wasm_bindgen::JsValue::from_str(&token_hash),
            wasm_bindgen::JsValue::from_f64(now as f64),
        ])?
        .first::<UserInfoRow>(None)
        .await?;
    let Some(subject) = subject else {
        return unauthorized();
    };
    worker::Response::builder()
        .with_header("Cache-Control", "no-store")?
        .with_header("Pragma", "no-cache")?
        .from_json(&UserInfoResponse { sub: subject.sub })
}

#[cfg(all(target_arch = "wasm32", feature = "worker-entry"))]
#[worker::event(fetch)]
pub async fn main(
    req: worker::Request,
    env: worker::Env,
    _ctx: worker::Context,
) -> worker::Result<worker::Response> {
    worker::Router::with_data(())
        .get_async("/health", |_req, _ctx| async { worker::Response::ok("ok") })
        .get_async("/jwks", jwks_route)
        .get_async("/userinfo", userinfo_route)
        .post_async("/token", token_route)
        .run(req, env)
        .await
}
