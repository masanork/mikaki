//! Cloudflare Workers platform adapter. Protocol decisions remain in `mikaki-oidc`.

#[cfg(target_arch = "wasm32")]
use serde::{Deserialize, Serialize};

#[cfg(target_arch = "wasm32")]
use sha2::{Digest, Sha256};

#[cfg(target_arch = "wasm32")]
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::JsCast;

#[cfg(target_arch = "wasm32")]
use std::collections::{HashMap, HashSet};

#[cfg(target_arch = "wasm32")]
use mikaki_oidc::CryptographicRandom;

#[cfg(target_arch = "wasm32")]
pub struct WorkersCryptoRandom;

/// Token request whose assertion replay reservation is tied to this request.
/// The reservation ID is persisted by D1 and must be reused by code exchange.
#[cfg(target_arch = "wasm32")]
#[must_use = "use the assertion reservation receipt in the final code exchange"]
pub struct AuthenticatedTokenRequest {
    request: mikaki_oidc::AuthenticatedTokenEndpointInput,
    assertion_reservation_id: String,
}

#[cfg(target_arch = "wasm32")]
impl AuthenticatedTokenRequest {
    pub fn request(&self) -> &mikaki_oidc::AuthenticatedTokenEndpointInput {
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
    nonce: Option<String>,
    auth_time: i64,
    parent_expires_at: i64,
    signing_generation: i64,
    signing_algorithm: String,
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
#[derive(Deserialize)]
struct AuthorizationContextRow {
    client_revision: i64,
    sector_identifier: String,
    sso_id: String,
    account_id: String,
    parent_expires_at: i64,
    auth_time: i64,
}

#[cfg(target_arch = "wasm32")]
#[derive(Deserialize)]
struct ClientRegistrationRow {
    client_revision: i64,
    sector_identifier: String,
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

#[cfg(target_arch = "wasm32")]
#[derive(Serialize)]
struct DiscoveryResponse {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    userinfo_endpoint: String,
    response_types_supported: [&'static str; 1],
    response_modes_supported: [&'static str; 1],
    grant_types_supported: [&'static str; 1],
    subject_types_supported: [&'static str; 1],
    id_token_signing_alg_values_supported: [&'static str; 2],
    scopes_supported: [&'static str; 1],
    claims_supported: [&'static str; 8],
    token_endpoint_auth_methods_supported: [&'static str; 1],
    token_endpoint_auth_signing_alg_values_supported: [&'static str; 1],
    code_challenge_methods_supported: [&'static str; 1],
    authorization_response_iss_parameter_supported: bool,
    request_parameter_supported: bool,
    request_uri_parameter_supported: bool,
    claims_parameter_supported: bool,
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
    nonce: Option<String>,
    auth_time: u64,
    parent_expires_at: u64,
    signing_kid: String,
    signing_algorithm: String,
    signing_generation: u64,
    public_jwk: String,
}

#[cfg(target_arch = "wasm32")]
enum WorkerTokenSigner {
    Es256(mikaki_oidc::P256TokenSigner),
    Rs256 {
        key: mikaki_oidc::RsaPrivateTokenKey,
        crypto_key: web_sys::CryptoKey,
    },
}

#[cfg(target_arch = "wasm32")]
impl WorkerTokenSigner {
    async fn from_secret(input: &str) -> worker::Result<Self> {
        let value: serde_json::Value = serde_json::from_str(input)
            .map_err(|_| worker::Error::RustError("server_error".into()))?;
        match value.get("kty").and_then(serde_json::Value::as_str) {
            Some("EC") => mikaki_oidc::P256TokenSigner::from_private_jwk(input)
                .map(Self::Es256)
                .map_err(|_| worker::Error::RustError("server_error".into())),
            Some("RSA") => {
                let key = mikaki_oidc::RsaPrivateTokenKey::from_private_jwk(input)
                    .map_err(|_| worker::Error::RustError("server_error".into()))?;
                let global = js_sys::global();
                let crypto = js_sys::Reflect::get(&global, &"crypto".into())
                    .map_err(|_| worker::Error::RustError("server_error".into()))?
                    .dyn_into::<web_sys::Crypto>()
                    .map_err(|_| worker::Error::RustError("server_error".into()))?;
                let subtle = crypto.subtle();
                let jwk = js_sys::JSON::parse(
                    &key.webcrypto_private_jwk_json()
                        .map_err(|_| worker::Error::RustError("server_error".into()))?,
                )?
                .dyn_into::<js_sys::Object>()
                .map_err(|_| worker::Error::RustError("server_error".into()))?;
                let algorithm = js_sys::JSON::parse(
                    r#"{"name":"RSASSA-PKCS1-v1_5","hash":{"name":"SHA-256"}}"#,
                )?
                .dyn_into::<js_sys::Object>()
                .map_err(|_| worker::Error::RustError("server_error".into()))?;
                let usages = js_sys::Array::new();
                usages.push(&wasm_bindgen::JsValue::from_str("sign"));
                let imported =
                    wasm_bindgen_futures::JsFuture::from(subtle.import_key_with_object(
                        "jwk",
                        &jwk,
                        &algorithm,
                        false,
                        usages.as_ref(),
                    )?)
                    .await?;
                let crypto_key = imported
                    .dyn_into::<web_sys::CryptoKey>()
                    .map_err(|_| worker::Error::RustError("server_error".into()))?;
                Ok(Self::Rs256 { key, crypto_key })
            }
            _ => Err(worker::Error::RustError("server_error".into())),
        }
    }

    fn kid(&self) -> &str {
        match self {
            Self::Es256(key) => key.kid(),
            Self::Rs256 { key, .. } => key.kid(),
        }
    }

    fn algorithm(&self) -> &'static str {
        match self {
            Self::Es256(_) => "ES256",
            Self::Rs256 { .. } => "RS256",
        }
    }

    fn matches_public_jwk(&self, jwk: &str) -> bool {
        match self {
            Self::Es256(key) => key.matches_public_jwk(jwk),
            Self::Rs256 { key, .. } => key.matches_public_jwk(jwk),
        }
    }

    async fn sign_id_token(
        &self,
        issuer: &str,
        subject: &str,
        audience: &str,
        sid: &str,
        nonce: Option<&str>,
        auth_time: u64,
        issued_at: u64,
        expires_at: u64,
    ) -> worker::Result<String> {
        match self {
            Self::Es256(key) => key
                .sign_id_token(
                    issuer, subject, audience, sid, nonce, auth_time, issued_at, expires_at,
                )
                .map_err(|_| worker::Error::RustError("server_error".into())),
            Self::Rs256 { key, crypto_key } => {
                let input = mikaki_oidc::IdTokenSigningInput::new(
                    "RS256",
                    key.kid(),
                    issuer,
                    subject,
                    audience,
                    sid,
                    nonce,
                    auth_time,
                    issued_at,
                    expires_at,
                )
                .map_err(|_| worker::Error::RustError("server_error".into()))?;
                let global = js_sys::global();
                let crypto = js_sys::Reflect::get(&global, &"crypto".into())?
                    .dyn_into::<web_sys::Crypto>()
                    .map_err(|_| worker::Error::RustError("server_error".into()))?;
                let signature = wasm_bindgen_futures::JsFuture::from(
                    crypto.subtle().sign_with_str_and_u8_array(
                        "RSASSA-PKCS1-v1_5",
                        crypto_key,
                        input.as_bytes(),
                    )?,
                )
                .await?;
                let signature = js_sys::Uint8Array::new(&signature).to_vec();
                if signature.len() != key.modulus_bytes() {
                    return Err(worker::Error::RustError("server_error".into()));
                }
                input
                    .finish(&signature)
                    .map_err(|_| worker::Error::RustError("server_error".into()))
            }
        }
    }
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

    pub fn nonce(&self) -> Option<&str> {
        self.nonce.as_deref()
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
    authorization_code_ttl_seconds: u64,
    request_target_bytes: u64,
    parameter_count: u64,
    state_bytes: u64,
    nonce_bytes: u64,
    access_token_ttl_seconds: u64,
    id_token_ttl_seconds: u64,
    response_bytes: u64,
    jwt_bytes: u64,
    form_body_bytes: u64,
}

#[cfg(target_arch = "wasm32")]
pub struct WorkerRuntimePolicy {
    assertion: mikaki_oidc::ClientAssertionPolicy,
    authorization_code_ttl_seconds: u64,
    request_target_bytes: usize,
    parameter_count: usize,
    state_bytes: usize,
    nonce_bytes: usize,
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
            .var("MIKAKI_WORKER_POLICY")
            .map_err(|_| worker::Error::RustError("runtime policy is unavailable".into()))?
            .to_string();
        Self::from_compiled_json(&json)
    }

    pub fn from_compiled_json(json: &str) -> worker::Result<Self> {
        let compiled: CompiledWorkerPolicy = serde_json::from_str(json)
            .map_err(|_| worker::Error::RustError("invalid runtime policy".into()))?;
        if compiled.schema_version != 4
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
            || compiled.authorization_code_ttl_seconds == 0
            || compiled.access_token_ttl_seconds > i32::MAX as u64
            || compiled.id_token_ttl_seconds > i32::MAX as u64
            || compiled.authorization_code_ttl_seconds > i32::MAX as u64
            || compiled.request_target_bytes == 0
            || compiled.request_target_bytes > 1_048_576
            || compiled.parameter_count == 0
            || compiled.parameter_count > 128
            || compiled.state_bytes == 0
            || compiled.state_bytes > compiled.request_target_bytes
            || compiled.nonce_bytes == 0
            || compiled.nonce_bytes > compiled.request_target_bytes
            || compiled.response_bytes == 0
            || compiled.response_bytes > 1_048_576
        {
            return Err(worker::Error::RustError("invalid runtime policy".into()));
        }
        let canonical = serde_json::json!({
            "assertion_ttl_seconds": compiled.assertion_ttl_seconds,
            "clock_skew_seconds": compiled.clock_skew_seconds,
            "authorization_code_ttl_seconds": compiled.authorization_code_ttl_seconds,
            "request_target_bytes": compiled.request_target_bytes,
            "parameter_count": compiled.parameter_count,
            "state_bytes": compiled.state_bytes,
            "nonce_bytes": compiled.nonce_bytes,
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
        let request_target_bytes = usize::try_from(compiled.request_target_bytes)
            .map_err(|_| worker::Error::RustError("invalid runtime policy".into()))?;
        let parameter_count = usize::try_from(compiled.parameter_count)
            .map_err(|_| worker::Error::RustError("invalid runtime policy".into()))?;
        let state_bytes = usize::try_from(compiled.state_bytes)
            .map_err(|_| worker::Error::RustError("invalid runtime policy".into()))?;
        let nonce_bytes = usize::try_from(compiled.nonce_bytes)
            .map_err(|_| worker::Error::RustError("invalid runtime policy".into()))?;
        let assertion = mikaki_oidc::ClientAssertionPolicy::from_seconds(
            compiled.assertion_ttl_seconds,
            compiled.clock_skew_seconds,
        )
        .map_err(|_| worker::Error::RustError("invalid runtime policy".into()))?;
        Ok(Self {
            assertion,
            authorization_code_ttl_seconds: compiled.authorization_code_ttl_seconds,
            request_target_bytes,
            parameter_count,
            state_bytes,
            nonce_bytes,
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

    pub fn authorization_code_ttl_seconds(&self) -> u64 {
        self.authorization_code_ttl_seconds
    }

    pub fn request_target_bytes(&self) -> usize {
        self.request_target_bytes
    }
    pub fn parameter_count(&self) -> usize {
        self.parameter_count
    }
    pub fn state_bytes(&self) -> usize {
        self.state_bytes
    }
    pub fn nonce_bytes(&self) -> usize {
        self.nonce_bytes
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
) -> worker::Result<mikaki_oidc::ValidatedTokenEndpointInput> {
    if body.len() > policy.form_body_bytes {
        return Err(worker::Error::RustError("invalid_request".into()));
    }
    let input: mikaki_oidc::TokenEndpointInput = serde_urlencoded::from_str(body)
        .map_err(|_| worker::Error::RustError("invalid_request".into()))?;
    input.validate(policy.jwt_bytes).map_err(|error| {
        let code = match error {
            mikaki_oidc::TokenEndpointInputError::UnsupportedGrantType => "unsupported_grant_type",
            mikaki_oidc::TokenEndpointInputError::InvalidClient => "invalid_client",
            mikaki_oidc::TokenEndpointInputError::InvalidRequest => "invalid_request",
        };
        worker::Error::RustError(code.into())
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
async fn accept_client_assertion(
    db: &worker::d1::D1Database,
    assertion: &mikaki_oidc::VerifiedClientAssertion,
    endpoint: &str,
    random: &mut impl mikaki_oidc::CryptographicRandom,
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
async fn verify_and_accept_client_assertion(
    db: &worker::d1::D1Database,
    client_id: &str,
    compact: &str,
    audience: &str,
    endpoint: &str,
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
    let key = mikaki_oidc::ClientAssertionKey::new(
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
    input: mikaki_oidc::ValidatedTokenEndpointInput,
    token_endpoint: &str,
    now: u64,
    policy: &WorkerRuntimePolicy,
    random: &mut impl mikaki_oidc::CryptographicRandom,
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
async fn load_authorization_code_context(
    db: &worker::d1::D1Database,
    input: &AuthenticatedTokenRequest,
    signer: &WorkerTokenSigner,
    random: &mut impl mikaki_oidc::CryptographicRandom,
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
        JsValue::from_str(signer.algorithm()),
    ];
    let row = db
        .prepare(
            "SELECT ac.client_id, cs.sid, v.sub, cc.nonce, sx.auth_time, \
             v.expires_at AS parent_expires_at, sk.generation AS signing_generation, \
             sk.algorithm AS signing_algorithm, \
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
             AND sk.active=1 AND sk.algorithm=?13 LIMIT 1",
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
        signing_algorithm: row.signing_algorithm,
        signing_generation,
        public_jwk: row.public_jwk,
    })
}

#[cfg(target_arch = "wasm32")]
async fn revoke_reused_code(
    db: &worker::d1::D1Database,
    input: &AuthenticatedTokenRequest,
    random: &mut impl mikaki_oidc::CryptographicRandom,
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
        .bind(&values[..11])?,
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
    signer: &WorkerTokenSigner,
    issuer: &str,
    now: u64,
    access_ttl_seconds: u64,
    id_token_ttl_seconds: u64,
    response_bytes: usize,
    random: &mut impl mikaki_oidc::CryptographicRandom,
) -> worker::Result<TokenEndpointSuccess> {
    use wasm_bindgen::JsValue;

    if context.client_id() != input.request().client_id()
        || context.signing_kid() != signer.kid()
        || context.signing_algorithm != signer.algorithm()
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
               WHERE cs.client_id=?2 AND cs.sid=?14 AND sx.auth_time=?17 AND cc.nonce IS ?16) \
             AND EXISTS (SELECT 1 FROM client_key ck WHERE ck.client_id=?2 \
               AND ck.kid=?6 AND ck.revision=?7 AND ck.active=1) \
             AND EXISTS (SELECT 1 FROM assertion_use au WHERE au.client_id=?2 \
               AND au.jti=?8 AND au.endpoint=?9 AND au.accepted_by=?10 \
               AND au.retain_until=?11 AND au.retain_until > CAST(strftime('%s','now') AS INTEGER)) \
             AND EXISTS (SELECT 1 FROM signing_key sk WHERE sk.kid=?12 \
               AND sk.generation=?13 AND sk.active=1 AND sk.public_jwk=?23 \
               AND sk.algorithm=?24) \
             AND ?20 > CAST(strftime('%s','now') AS INTEGER) AND ?20 <= ?18 \
             AND ?21 > CAST(strftime('%s','now') AS INTEGER) AND ?21 <= ?18",
        )
        .bind(&values)?,
        db.prepare(
            "INSERT INTO token_issue(code_hash,operation_id,access_hash,access_expires_at,signing_kid,issued_at,revoked) \
             SELECT ac.code_hash,?19,?22,?20,?12,ac.consumed_at,0 \
             FROM authorization_code ac JOIN eligible_client_session v \
               ON v.client_id=ac.client_id AND v.sid=ac.sid \
             WHERE ac.code_hash=?1 AND ac.consumed_by=?19 \
               AND ?20 > CAST(strftime('%s','now') AS INTEGER)",
        )
        .bind(&values[..22])?,
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
        .bind(&values[..22])?,
        db.prepare("DELETE FROM atomic_guard WHERE operation_id=?19").bind(&values[..19])?,
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
    let signer = WorkerTokenSigner::from_secret(&private_jwk).await?;
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
struct ParsedAuthorizationParameters {
    values: HashMap<String, String>,
    duplicates: HashSet<String>,
    too_many: bool,
}

#[cfg(target_arch = "wasm32")]
fn parse_authorization_parameters(
    request_url: &url::Url,
    request_target_bytes: usize,
    parameter_count: usize,
) -> Option<ParsedAuthorizationParameters> {
    if request_url.as_str().len() > request_target_bytes {
        return None;
    }
    let mut parameters = HashMap::new();
    let mut duplicates = HashSet::new();
    let mut count = 0usize;
    for (key, value) in request_url.query_pairs() {
        count += 1;
        let key = key.into_owned();
        if parameters.contains_key(&key) {
            duplicates.insert(key);
        } else {
            parameters.insert(key, value.into_owned());
        }
    }
    Some(ParsedAuthorizationParameters {
        values: parameters,
        duplicates,
        too_many: count > parameter_count,
    })
}

#[cfg(target_arch = "wasm32")]
fn authorization_error_response(
    redirect_uri: &str,
    state: Option<&str>,
    issuer: &str,
    error: &str,
) -> worker::Result<worker::Response> {
    let mut target = url::Url::parse(redirect_uri)
        .map_err(|_| worker::Error::RustError("invalid registered redirect".into()))?;
    {
        let mut query = target.query_pairs_mut();
        query.append_pair("error", error);
        if let Some(state) = state {
            query.append_pair("state", state);
        }
        query.append_pair("iss", issuer);
    }
    Ok(worker::Response::builder()
        .with_status(302)
        .with_header("Location", target.as_str())?
        .with_header("Cache-Control", "no-store")?
        .with_header("Pragma", "no-cache")?
        .with_header("Referrer-Policy", "no-referrer")?
        .empty())
}

#[cfg(target_arch = "wasm32")]
fn browser_cookie(request: &worker::Request, cookie_name: &str) -> worker::Result<Option<String>> {
    let Some(header) = request.headers().get("cookie")? else {
        return Ok(None);
    };
    if header.len() > 4096 {
        return Ok(None);
    }
    let mut found = None;
    for part in header.split(';') {
        let Some((name, value)) = part.trim().split_once('=') else {
            continue;
        };
        if name == cookie_name {
            if found.is_some() || value.is_empty() || value.len() > 512 {
                return Ok(None);
            }
            found = Some(value.to_owned());
        }
    }
    Ok(found)
}

#[cfg(target_arch = "wasm32")]
async fn authorize_route(
    request: worker::Request,
    context: worker::RouteContext<()>,
) -> worker::Result<worker::Response> {
    use wasm_bindgen::JsValue;

    let policy = WorkerRuntimePolicy::from_env(&context.env)?;
    let request_url = request.url()?;
    let Some(parsed) = parse_authorization_parameters(
        &request_url,
        policy.request_target_bytes(),
        policy.parameter_count(),
    ) else {
        return worker::Response::builder()
            .with_status(400)
            .with_header("Cache-Control", "no-store")?
            .from_json(&TokenEndpointErrorBody {
                error: "invalid_request".into(),
            });
    };
    let parameters = &parsed.values;
    let Some(client_id) = parameters.get("client_id") else {
        return worker::Response::builder()
            .with_status(400)
            .with_header("Cache-Control", "no-store")?
            .from_json(&TokenEndpointErrorBody {
                error: "invalid_request".into(),
            });
    };
    if parsed.duplicates.contains("client_id") || parsed.duplicates.contains("redirect_uri") {
        return worker::Response::builder()
            .with_status(400)
            .with_header("Cache-Control", "no-store")?
            .from_json(&TokenEndpointErrorBody {
                error: "invalid_request".into(),
            });
    }
    let Some(redirect_uri) = parameters.get("redirect_uri") else {
        return worker::Response::builder()
            .with_status(400)
            .with_header("Cache-Control", "no-store")?
            .from_json(&TokenEndpointErrorBody {
                error: "invalid_request".into(),
            });
    };
    if client_id.is_empty() || client_id.len() > 128 || redirect_uri.len() > 2048 {
        return worker::Response::builder()
            .with_status(400)
            .with_header("Cache-Control", "no-store")?
            .from_json(&TokenEndpointErrorBody {
                error: "invalid_request".into(),
            });
    }

    let issuer = context
        .env
        .var("MIKAKI_ISSUER")
        .map_err(|_| worker::Error::RustError("server_error".into()))?
        .to_string();
    let issuer = configured_issuer(&issuer)
        .ok_or_else(|| worker::Error::RustError("server_error".into()))?;
    let authorization_endpoint = format!("{issuer}/authorize");
    if request_url.as_str().split('?').next() != Some(authorization_endpoint.as_str()) {
        return Err(worker::Error::RustError("invalid_request".into()));
    }

    let db = context.env.d1("DB")?;
    let registration = db
        .prepare(
            "SELECT c.revision AS client_revision,c.sector_identifier \
             FROM client c JOIN client_redirect_uri r ON r.client_id=c.client_id \
             WHERE c.client_id=?1 AND c.active=1 AND r.redirect_uri=?2",
        )
        .bind(&[
            JsValue::from_str(client_id),
            JsValue::from_str(redirect_uri),
        ])?
        .first::<ClientRegistrationRow>(None)
        .await?;
    let Some(registration) = registration else {
        return worker::Response::builder()
            .with_status(400)
            .with_header("Cache-Control", "no-store")?
            .from_json(&TokenEndpointErrorBody {
                error: "invalid_request".into(),
            });
    };

    let state = if parsed.duplicates.contains("state") {
        None
    } else {
        parameters.get("state").map(String::as_str)
    };
    let oauth_error = if parsed.too_many || !parsed.duplicates.is_empty() {
        Some("invalid_request")
    } else if parameters.contains_key("request") || parameters.contains_key("request_uri") {
        Some("request_not_supported")
    } else if parameters
        .get("response_type")
        .is_some_and(|value| value != "code")
    {
        Some("unsupported_response_type")
    } else if parameters
        .get("scope")
        .is_some_and(|value| value != "openid")
    {
        Some("invalid_scope")
    } else if parameters
        .get("response_mode")
        .is_some_and(|value| value != "query")
    {
        Some("invalid_request")
    } else if [
        "client_id",
        "redirect_uri",
        "response_type",
        "scope",
        "state",
        "code_challenge",
        "code_challenge_method",
    ]
    .iter()
    .any(|name| !parameters.contains_key(*name))
    {
        Some("invalid_request")
    } else {
        None
    };
    if let Some(error) = oauth_error {
        return authorization_error_response(redirect_uri, state, &issuer, error);
    }

    let raw = mikaki_oidc::Authorization {
        client_id: client_id.clone(),
        redirect_uri: redirect_uri.clone(),
        response_type: parameters["response_type"].clone(),
        scope: parameters["scope"].clone(),
        state: parameters["state"].clone(),
        nonce: parameters.get("nonce").cloned(),
        code_challenge: parameters["code_challenge"].clone(),
        code_challenge_method: parameters["code_challenge_method"].clone(),
    };
    let validated = match raw.validate(
        client_id,
        redirect_uri,
        policy.state_bytes(),
        policy.nonce_bytes(),
    ) {
        Ok(validated) => validated,
        Err(_) => {
            return authorization_error_response(redirect_uri, state, &issuer, "invalid_request");
        }
    };

    let mut prompts = Vec::new();
    if let Some(prompt) = parameters.get("prompt") {
        for item in prompt.split_ascii_whitespace() {
            if !["none", "login", "consent", "select_account"].contains(&item)
                || prompts.contains(&item)
            {
                return authorization_error_response(
                    redirect_uri,
                    state,
                    &issuer,
                    "invalid_request",
                );
            }
            prompts.push(item);
        }
    }
    if prompts.contains(&"none") && prompts.len() > 1 {
        return authorization_error_response(redirect_uri, state, &issuer, "invalid_request");
    }
    if prompts.contains(&"login") {
        return authorization_error_response(redirect_uri, state, &issuer, "login_required");
    }
    if prompts.contains(&"consent") {
        return authorization_error_response(redirect_uri, state, &issuer, "consent_required");
    }
    if prompts.contains(&"select_account") {
        return authorization_error_response(
            redirect_uri,
            state,
            &issuer,
            "account_selection_required",
        );
    }

    let now = now_seconds().ok_or_else(|| worker::Error::RustError("server_error".into()))?;

    let Some(cookie) = browser_cookie(&request, "__Host-op-sso")? else {
        return authorization_error_response(redirect_uri, state, &issuer, "login_required");
    };
    let cookie_hash = URL_SAFE_NO_PAD.encode(Sha256::digest(cookie.as_bytes()));
    let sso_values = [JsValue::from_str(&cookie_hash)];
    let sso = db
        .prepare(
            "SELECT ss.sso_id,ss.account_id,ss.expires_at AS parent_expires_at, \
             sx.auth_time,c.revision AS client_revision,c.sector_identifier \
             FROM sso_context sx JOIN sso_session ss ON ss.sso_id=sx.sso_id \
             JOIN account_security a ON a.account_id=ss.account_id \
             JOIN credential cr ON cr.credential_id=ss.credential_id AND cr.account_id=ss.account_id \
             JOIN client c ON c.client_id=?2 JOIN client_redirect_uri r \
               ON r.client_id=c.client_id AND r.redirect_uri=?3 \
             JOIN app_connection g ON g.account_id=ss.account_id AND g.client_id=c.client_id \
             WHERE sx.secret_hash=?1 AND ss.revoked=0 AND ss.expires_at>?4 \
             AND a.active=1 AND a.epoch=ss.epoch AND cr.active=1 \
             AND c.active=1 AND g.active=1",
        )
        .bind(&[
            sso_values[0].clone(),
            JsValue::from_str(client_id),
            JsValue::from_str(redirect_uri),
            JsValue::from_f64(now as f64),
        ])?
        .first::<AuthorizationContextRow>(None)
        .await?;
    let Some(sso) = sso else {
        return authorization_error_response(redirect_uri, state, &issuer, "login_required");
    };
    if registration.client_revision != sso.client_revision
        || registration.sector_identifier != sso.sector_identifier
    {
        return authorization_error_response(
            redirect_uri,
            state,
            &issuer,
            "temporarily_unavailable",
        );
    }
    if let Some(max_age) = parameters.get("max_age") {
        let Ok(max_age) = max_age.parse::<u64>() else {
            return authorization_error_response(redirect_uri, state, &issuer, "invalid_request");
        };
        if sso.auth_time < 0 || (sso.auth_time as u64).saturating_add(max_age) <= now {
            return authorization_error_response(redirect_uri, state, &issuer, "login_required");
        }
    }

    let mut random = WorkersCryptoRandom;
    let prepared = validated
        .prepare_code(
            &mut random,
            now,
            policy.authorization_code_ttl_seconds(),
            sso.parent_expires_at as u64,
        )
        .map_err(|_| worker::Error::RustError("server_error".into()))?;
    let (validated, presented_code, digest, expires_at) = prepared.into_parts();
    let mut sid_secret = [0u8; 32];
    let mut subject_secret = [0u8; 32];
    random
        .fill(&mut sid_secret)
        .and_then(|_| random.fill(&mut subject_secret))
        .map_err(|_| worker::Error::RustError("server_error".into()))?;
    let sid = URL_SAFE_NO_PAD.encode(sid_secret);
    let candidate_sub = URL_SAFE_NO_PAD.encode(subject_secret);
    let expires_at =
        i64::try_from(expires_at).map_err(|_| worker::Error::RustError("server_error".into()))?;
    let code_hash = digest.as_base64url();
    let pairwise_values = [
        JsValue::from_str(&sso.account_id),
        JsValue::from_str(&sso.sector_identifier),
        JsValue::from_str(&candidate_sub),
    ];
    let session_values = [
        JsValue::from_str(&sid),
        JsValue::from_str(&sso.sso_id),
        JsValue::from_str(&cookie_hash),
        JsValue::from_str(client_id),
        JsValue::from_str(&sso.client_revision.to_string()),
        JsValue::from_str(redirect_uri),
        JsValue::from_str(&now.to_string()),
    ];
    let code_values = [
        JsValue::from_str(code_hash),
        JsValue::from_str(client_id),
        JsValue::from_str(&sid),
        JsValue::from_str(&sso.client_revision.to_string()),
        JsValue::from_str(redirect_uri),
        JsValue::from_str(validated.code_challenge()),
        JsValue::from_str(&expires_at.to_string()),
        JsValue::from_str(&now.to_string()),
    ];
    let guard_values = [
        JsValue::from_str(code_hash),
        JsValue::from_str(client_id),
        JsValue::from_str(redirect_uri),
        validated
            .nonce()
            .map(JsValue::from_str)
            .unwrap_or(JsValue::NULL),
    ];
    db.batch(vec![
        db.prepare(include_str!("../sql/insert-pairwise-subject.sql"))
            .bind(&pairwise_values)?,
        db.prepare(include_str!(
            "../sql/insert-authorization-client-session.sql"
        ))
        .bind(&session_values)?,
        db.prepare(include_str!("../sql/insert-authorization-code.sql"))
            .bind(&code_values)?,
        db.prepare(include_str!("../sql/insert-authorization-code-context.sql"))
            .bind(&[
                code_values[0].clone(),
                validated
                    .nonce()
                    .map(JsValue::from_str)
                    .unwrap_or(JsValue::NULL),
            ])?,
        db.prepare(include_str!("../sql/guard-authorization-code.sql"))
            .bind(&[
                guard_values[0].clone(),
                guard_values[1].clone(),
                guard_values[2].clone(),
                guard_values[3].clone(),
                JsValue::from_str(&now.to_string()),
            ])?,
        db.prepare(include_str!("../sql/delete-authorization-code-guard.sql"))
            .bind(&[guard_values[0].clone()])?,
    ])
    .await?;

    let mut target = url::Url::parse(validated.redirect_uri())
        .map_err(|_| worker::Error::RustError("invalid registered redirect".into()))?;
    {
        let mut query = target.query_pairs_mut();
        query.append_pair("code", presented_code.as_str());
        query.append_pair("state", validated.state());
        query.append_pair("iss", &issuer);
    }
    Ok(worker::Response::builder()
        .with_status(302)
        .with_header("Location", target.as_str())?
        .with_header("Cache-Control", "no-store")?
        .with_header("Pragma", "no-cache")?
        .with_header("Referrer-Policy", "no-referrer")?
        .empty())
}

#[cfg(target_arch = "wasm32")]
fn now_seconds() -> Option<u64> {
    let milliseconds = js_sys::Date::now();
    if milliseconds.is_finite() && milliseconds >= 0.0 {
        Some((milliseconds / 1000.0).floor() as u64)
    } else {
        None
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
             WHERE active=1 AND algorithm IN ('ES256','RS256') ORDER BY kid",
        )
        .all()
        .await?
        .results::<SigningPublicKeyRow>()?;
    let mut keys = Vec::with_capacity(rows.len());
    for row in rows {
        let jwk = mikaki_oidc::P256TokenSigner::canonical_public_jwk(&row.public_jwk)
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
async fn discovery_route(
    _request: worker::Request,
    context: worker::RouteContext<()>,
) -> worker::Result<worker::Response> {
    let issuer = context
        .env
        .var("MIKAKI_ISSUER")
        .map_err(|_| worker::Error::RustError("server_error".into()))?
        .to_string();
    let issuer = configured_issuer(&issuer)
        .ok_or_else(|| worker::Error::RustError("server_error".into()))?;
    worker::Response::builder()
        .with_header("Cache-Control", "public, max-age=300")?
        .from_json(&DiscoveryResponse {
            authorization_endpoint: format!("{issuer}/authorize"),
            token_endpoint: format!("{issuer}/token"),
            jwks_uri: format!("{issuer}/jwks"),
            userinfo_endpoint: format!("{issuer}/userinfo"),
            issuer,
            response_types_supported: ["code"],
            response_modes_supported: ["query"],
            grant_types_supported: ["authorization_code"],
            subject_types_supported: ["pairwise"],
            id_token_signing_alg_values_supported: ["ES256", "RS256"],
            scopes_supported: ["openid"],
            claims_supported: [
                "iss",
                "sub",
                "aud",
                "exp",
                "iat",
                "nonce",
                "auth_time",
                "sid",
            ],
            token_endpoint_auth_methods_supported: ["private_key_jwt"],
            token_endpoint_auth_signing_alg_values_supported: ["ES256"],
            code_challenge_methods_supported: ["S256"],
            authorization_response_iss_parameter_supported: true,
            request_parameter_supported: false,
            request_uri_parameter_supported: false,
            claims_parameter_supported: false,
        })
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
    if request.url()?.query_pairs().next().is_some() {
        return worker::Response::builder()
            .with_status(400)
            .with_header("Cache-Control", "no-store")?
            .from_json(&TokenEndpointErrorBody {
                error: "invalid_request".into(),
            });
    }
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
        .get_async("/.well-known/openid-configuration", discovery_route)
        .get_async("/authorize", authorize_route)
        .get_async("/jwks", jwks_route)
        .get_async("/userinfo", userinfo_route)
        .post_async("/userinfo", userinfo_route)
        .post_async("/token", token_route)
        .run(req, env)
        .await
}
