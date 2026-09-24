//! Cloudflare Workers platform adapter. Protocol decisions remain in `mikaki-oidc`.

#[cfg(target_arch = "wasm32")]
mod admin_invitations;
#[cfg(target_arch = "wasm32")]
mod enrollment;
#[cfg(target_arch = "wasm32")]
mod passkey_login;
#[cfg(target_arch = "wasm32")]
mod session_check;

#[cfg(target_arch = "wasm32")]
mod i18n;
#[cfg(any(target_arch = "wasm32", test))]
mod vault_authzen;

#[cfg(target_arch = "wasm32")]
mod vault_attributes;
#[cfg(all(target_arch = "wasm32", feature = "worker-entry"))]
mod vault_gc;

#[cfg(target_arch = "wasm32")]
use serde::{Deserialize, Serialize};

#[cfg(target_arch = "wasm32")]
use sha2::{Digest, Sha256};

#[cfg(target_arch = "wasm32")]
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::JsCast;

#[cfg(target_arch = "wasm32")]
use std::collections::{HashMap, HashSet};

#[cfg(target_arch = "wasm32")]
use mikaki_oidc::CryptographicRandom;

#[cfg(target_arch = "wasm32")]
use subtle::ConstantTimeEq;

#[cfg(target_arch = "wasm32")]
pub struct WorkersCryptoRandom;

/// Token request whose assertion replay reservation is tied to this request.
/// The reservation ID is persisted by D1 and must be reused by code exchange.
#[cfg(target_arch = "wasm32")]
#[must_use = "use the assertion reservation receipt in the final code exchange"]
pub struct AuthenticatedTokenRequest {
    client_id: String,
    exchange: mikaki_oidc::AuthorizationCodeExchange,
    client_revision: u64,
    method: &'static str,
    endpoint: String,
    credential_id: String,
    credential_revision: u64,
    reservation_id: String,
    retain_until: u64,
}

#[cfg(target_arch = "wasm32")]
impl AuthenticatedTokenRequest {
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    pub fn exchange(&self) -> &mikaki_oidc::AuthorizationCodeExchange {
        &self.exchange
    }

    pub fn reservation_id(&self) -> &str {
        &self.reservation_id
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
    auth_method: String,
    algorithm: String,
    public_key_sec1: Vec<u8>,
}

#[cfg(target_arch = "wasm32")]
#[derive(Deserialize)]
struct ClientSecretRow {
    client_revision: u64,
    secret_revision: u64,
    auth_method: String,
    secret_hash: String,
    allow_missing_pkce: i64,
}

#[cfg(target_arch = "wasm32")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretTokenForm {
    grant_type: String,
    code: String,
    redirect_uri: String,
    code_verifier: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
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
struct ConsumedCodeRow {
    consumed_by: Option<String>,
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
    allow_missing_pkce: i64,
}

#[cfg(target_arch = "wasm32")]
#[derive(Deserialize)]
struct LoginTransactionRow {
    authorization_url: String,
    client_id: String,
    challenge: String,
    expires_at: i64,
    failures: u32,
}

#[cfg(target_arch = "wasm32")]
#[derive(Deserialize)]
struct PasskeyCredentialRow {
    credential_id: String,
    account_id: String,
    epoch: i64,
    public_key: String,
    user_handle: String,
    counter: u32,
    backup_eligible: i64,
    revision: i64,
}

#[cfg(target_arch = "wasm32")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginFinishInput {
    tx: String,
    consent: bool,
    response: mikaki_webauthn::Assertion,
}

#[cfg(target_arch = "wasm32")]
#[derive(Serialize)]
struct LoginFinishOutput {
    location: String,
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
    claims_supported: [&'static str; 9],
    acr_values_supported: [&'static str; 1],
    token_endpoint_auth_methods_supported: Vec<&'static str>,
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

    #[allow(clippy::too_many_arguments)]
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
    token_rate_window_seconds: u64,
    token_attempts_per_client: u64,
    sso_absolute_ttl_seconds: u64,
}

#[cfg(target_arch = "wasm32")]
#[derive(Deserialize)]
struct ActiveWorkerPolicyRow {
    projection_revision: String,
    policy_revision: String,
    projection_json: String,
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
    token_rate_window_seconds: u64,
    token_attempts_per_client: u64,
    sso_absolute_ttl_seconds: u64,
    access_token_ttl_seconds: u64,
    id_token_ttl_seconds: u64,
    response_bytes: usize,
    policy_revision: String,
    projection_revision: String,
}

#[cfg(target_arch = "wasm32")]
impl WorkerRuntimePolicy {
    pub async fn from_db(db: &worker::d1::D1Database) -> worker::Result<Self> {
        let row = db
            .prepare(
                "SELECT v.projection_revision,v.policy_revision,v.projection_json \
                 FROM runtime_policy_active a JOIN runtime_policy_version v \
                   ON v.projection_revision=a.projection_revision WHERE a.id=1",
            )
            .first::<ActiveWorkerPolicyRow>(None)
            .await?
            .ok_or_else(|| worker::Error::RustError("runtime policy is unavailable".into()))?;
        let policy = Self::from_compiled_json(&row.projection_json)?;
        if policy.policy_revision != row.policy_revision
            || policy.projection_revision != row.projection_revision
        {
            return Err(worker::Error::RustError("invalid runtime policy".into()));
        }
        Ok(policy)
    }

    pub fn from_compiled_json(json: &str) -> worker::Result<Self> {
        let compiled: CompiledWorkerPolicy = serde_json::from_str(json)
            .map_err(|_| worker::Error::RustError("invalid runtime policy".into()))?;
        if compiled.schema_version != 5
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
            || ![10, 60].contains(&compiled.token_rate_window_seconds)
            || compiled.token_attempts_per_client == 0
            || compiled.token_attempts_per_client > 1000
            || compiled.sso_absolute_ttl_seconds == 0
            || compiled.sso_absolute_ttl_seconds > 365 * 86400
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
            "token_rate_window_seconds": compiled.token_rate_window_seconds,
            "token_attempts_per_client": compiled.token_attempts_per_client,
            "sso_absolute_ttl_seconds": compiled.sso_absolute_ttl_seconds,
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
            token_rate_window_seconds: compiled.token_rate_window_seconds,
            token_attempts_per_client: compiled.token_attempts_per_client,
            sso_absolute_ttl_seconds: compiled.sso_absolute_ttl_seconds,
            access_token_ttl_seconds: compiled.access_token_ttl_seconds,
            id_token_ttl_seconds: compiled.id_token_ttl_seconds,
            response_bytes,
            policy_revision: compiled.policy_revision,
            projection_revision: compiled.projection_revision,
        })
    }

    pub fn policy_revision(&self) -> &str {
        &self.policy_revision
    }

    pub fn authorization_code_ttl_seconds(&self) -> u64 {
        self.authorization_code_ttl_seconds
    }

    pub fn sso_absolute_ttl_seconds(&self) -> u64 {
        self.sso_absolute_ttl_seconds
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
fn decode_basic_component(input: &str) -> Option<String> {
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
fn basic_credentials(header: &str) -> worker::Result<(String, String)> {
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
fn secret_form(body: &str) -> worker::Result<SecretTokenForm> {
    serde_urlencoded::from_str(body).map_err(|_| worker::Error::RustError("invalid_request".into()))
}

#[cfg(target_arch = "wasm32")]
async fn authenticate_secret_token_request(
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
        client_id: request.client_id().to_owned(),
        exchange: request.exchange().clone(),
        client_revision: request.assertion().client_revision(),
        method: "private_key_jwt",
        endpoint: request.assertion().audience().to_owned(),
        credential_id: request.assertion().key_id().to_owned(),
        credential_revision: request.assertion().key_revision(),
        reservation_id: assertion_reservation_id,
        retain_until: request.assertion().retain_until(),
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
             JOIN client_auth_use au ON au.client_id=c.client_id \
             JOIN signing_key sk ON sk.kid=?12 \
             WHERE c.client_id=?1 AND c.active=1 AND c.revision=?5 \
             AND ac.code_hash=?2 AND ac.client_id=?1 AND ac.consumed_by IS NULL \
             AND ac.redirect_uri=?3 AND ac.pkce_challenge=?4 \
             AND ac.expires_at > CAST(strftime('%s','now') AS INTEGER) \
             AND c.auth_method=?8 \
             AND au.method=?8 AND au.credential_id=?6 AND au.client_revision=?5 \
             AND au.credential_revision=?7 AND au.endpoint=?9 AND au.accepted_by=?10 \
             AND au.retain_until=?11 AND au.retain_until > CAST(strftime('%s','now') AS INTEGER) \
             AND ((?8='private_key_jwt' AND EXISTS (SELECT 1 FROM client_key ck WHERE ck.client_id=c.client_id \
               AND ck.kid=?6 AND ck.revision=?7 AND ck.active=1)) \
               OR (?8 IN ('client_secret_basic','client_secret_post') AND EXISTS (SELECT 1 FROM client_secret s \
               WHERE s.client_id=c.client_id AND s.revision=?7 AND s.active=1))) \
             AND sk.active=1 AND sk.algorithm=?13 LIMIT 1",
        )
        .bind(&values)?
        .first::<AuthorizationCodeContextRow>(None)
        .await?;
    let Some(row) = row else {
        revoke_reused_code(db, input, random).await?;
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
    ];
    db.batch(vec![
        db.prepare(
            "UPDATE token_issue SET revoked=1 WHERE code_hash=?1 AND revoked=0 \
             AND EXISTS (SELECT 1 FROM authorization_code ac \
               JOIN client c ON c.client_id=ac.client_id \
               JOIN client_auth_use au ON au.client_id=c.client_id \
               WHERE ac.code_hash=?1 AND ac.client_id=?2 AND ac.redirect_uri=?3 \
                 AND ac.pkce_challenge=?4 AND ac.consumed_by IS NOT NULL \
                 AND c.active=1 AND c.revision=?5 AND c.auth_method=?8 \
                 AND au.method=?8 AND au.credential_id=?6 AND au.credential_revision=?7 \
                 AND au.client_revision=?5 AND au.endpoint=?9 AND au.accepted_by=?10 \
                 AND ((?8='private_key_jwt' AND EXISTS (SELECT 1 FROM client_key ck WHERE ck.client_id=c.client_id \
                   AND ck.kid=?6 AND ck.revision=?7 AND ck.active=1)) \
                   OR (?8 IN ('client_secret_basic','client_secret_post') AND EXISTS (SELECT 1 FROM client_secret s \
                   WHERE s.client_id=c.client_id AND s.revision=?7 AND s.active=1))) \
                 AND au.retain_until=?11 AND au.retain_until > CAST(strftime('%s','now') AS INTEGER))",
        )
        .bind(&values[..11])?,
        db.prepare(
            "INSERT INTO atomic_guard(operation_id,passed) VALUES(?12,CASE WHEN NOT EXISTS ( \
             SELECT 1 FROM token_issue ti \
             JOIN authorization_code ac ON ac.code_hash=ti.code_hash \
             JOIN client c ON c.client_id=ac.client_id \
             JOIN client_auth_use au ON au.client_id=c.client_id \
             WHERE ti.code_hash=?1 AND ti.revoked=0 AND ac.client_id=?2 \
               AND ac.redirect_uri=?3 AND ac.pkce_challenge=?4 \
               AND ac.consumed_by IS NOT NULL AND c.active=1 AND c.revision=?5 AND c.auth_method=?8 \
               AND au.method=?8 AND au.credential_id=?6 AND au.credential_revision=?7 \
               AND au.client_revision=?5 AND au.endpoint=?9 AND au.accepted_by=?10 \
               AND ((?8='private_key_jwt' AND EXISTS (SELECT 1 FROM client_key ck WHERE ck.client_id=c.client_id \
                 AND ck.kid=?6 AND ck.revision=?7 AND ck.active=1)) \
                 OR (?8 IN ('client_secret_basic','client_secret_post') AND EXISTS (SELECT 1 FROM client_secret s \
                 WHERE s.client_id=c.client_id AND s.revision=?7 AND s.active=1))) \
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
#[allow(clippy::too_many_arguments)]
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

    if context.client_id() != input.client_id()
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
    ];
    let commit = db.batch(vec![
        db.prepare(
            "UPDATE authorization_code SET consumed_by=?19, \
             consumed_at=CAST(strftime('%s','now') AS INTEGER) \
             WHERE code_hash=?1 AND client_id=?2 AND redirect_uri=?3 \
             AND pkce_challenge=?4 AND consumed_by IS NULL \
             AND expires_at > CAST(strftime('%s','now') AS INTEGER) \
             AND EXISTS (SELECT 1 FROM client c WHERE c.client_id=?2 \
               AND c.active=1 AND c.revision=?5 AND c.auth_method=?8) \
             AND EXISTS (SELECT 1 FROM eligible_client_session v \
               WHERE v.client_id=?2 AND v.sid=?14 AND v.sub=?15 AND v.expires_at=?18) \
             AND EXISTS (SELECT 1 FROM client_session cs \
               JOIN sso_context sx ON sx.sso_id=cs.sso_id \
               JOIN code_context cc ON cc.code_hash=?1 \
               WHERE cs.client_id=?2 AND cs.sid=?14 AND sx.auth_time=?17 AND cc.nonce IS ?16) \
             AND EXISTS (SELECT 1 FROM client_auth_use au WHERE au.client_id=?2 \
               AND au.method=?8 AND au.credential_id=?6 AND au.client_revision=?5 \
               AND au.credential_revision=?7 AND au.endpoint=?9 AND au.accepted_by=?10 \
               AND au.retain_until=?11 AND au.retain_until > CAST(strftime('%s','now') AS INTEGER)) \
             AND ((?8='private_key_jwt' AND EXISTS (SELECT 1 FROM client_key ck WHERE ck.client_id=?2 \
               AND ck.kid=?6 AND ck.revision=?7 AND ck.active=1)) \
               OR (?8 IN ('client_secret_basic','client_secret_post') AND EXISTS (SELECT 1 FROM client_secret s \
               WHERE s.client_id=?2 AND s.revision=?7 AND s.active=1))) \
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
    .await;
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
            return Err(worker::Error::RustError("invalid_grant".into()));
        }
        return Err(error);
    }

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
fn oauth_error_response(
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
fn conformance_deployment(env: &worker::Env) -> worker::Result<bool> {
    match env.var("MIKAKI_DEPLOYMENT_PROFILE") {
        Err(_) => Ok(false),
        Ok(value) if value.to_string() == "normal" => Ok(false),
        Ok(value) if value.to_string() == "conformance" => Ok(true),
        _ => Err(worker::Error::RustError(
            "invalid deployment profile".into(),
        )),
    }
}

#[cfg(target_arch = "wasm32")]
async fn issue_token_response(
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
    let now_ms = js_sys::Date::now();
    if !now_ms.is_finite() || now_ms < 0.0 {
        return Err(worker::Error::RustError("server_error".into()));
    }
    let now = (now_ms / 1000.0).floor() as u64;
    let mut random = WorkersCryptoRandom;
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
    } else {
        let input = parse_token_endpoint_form(&body, &policy)?;
        authenticate_token_request(&db, input, &token_endpoint, now, &policy, &mut random).await?
    };
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
            oauth_error_response(code, status, basic_challenge)
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
        match parameters.entry(key) {
            std::collections::hash_map::Entry::Occupied(entry) => {
                duplicates.insert(entry.key().clone());
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(value.into_owned());
            }
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
#[allow(clippy::too_many_arguments)]
async fn authorization_interaction_response(
    request: &worker::Request,
    db: &worker::d1::D1Database,
    issuer: &str,
    client_id: &str,
    redirect_uri: &str,
    state: Option<&str>,
    error: &str,
    prompt_none: bool,
) -> worker::Result<worker::Response> {
    if prompt_none {
        authorization_error_response(redirect_uri, state, issuer, error)
    } else {
        passkey_login::start(request, db, issuer, client_id).await
    }
}

#[cfg(target_arch = "wasm32")]
async fn authorize_route(
    request: worker::Request,
    context: worker::RouteContext<()>,
) -> worker::Result<worker::Response> {
    use wasm_bindgen::JsValue;

    let db = context.env.d1("DB")?;
    let policy = WorkerRuntimePolicy::from_db(&db).await?;
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

    let registration = db
        .prepare(
            "SELECT c.revision AS client_revision,c.sector_identifier,c.allow_missing_pkce \
             FROM client c JOIN client_redirect_uri r ON r.client_id=c.client_id \
             WHERE c.client_id=?1 AND c.active=1 AND r.redirect_uri=?2 AND r.active=1",
        )
        .bind(&[
            JsValue::from_str(client_id),
            JsValue::from_str(redirect_uri),
        ])?
        .first::<ClientRegistrationRow>(None)
        .await?;
    let Some(registration) = registration else {
        let strings = i18n::catalog(i18n::select(
            &request,
            parameters.get("ui_locales").map(String::as_str),
        )?);
        let html = format!(
            "<!doctype html><html lang=\"{}\"><head><meta charset=\"utf-8\"><title>{}</title></head><body><main><h1>{}</h1><p>{}</p></main></body></html>",
            strings.locale,
            i18n::html_escape(strings.message("invalidRedirectTitle")),
            i18n::html_escape(strings.message("invalidRedirectTitle")),
            i18n::html_escape(strings.message("invalidRedirectBody")),
        );
        return worker::Response::builder()
            .with_status(400)
            .with_header("Cache-Control", "no-store")?
            .with_header(
                "Content-Security-Policy",
                "default-src 'none'; frame-ancestors 'none'",
            )?
            .from_html(html);
    };

    let state = if parsed.duplicates.contains("state") {
        None
    } else {
        parameters.get("state").map(String::as_str)
    };
    let allow_missing_pkce =
        conformance_deployment(&context.env)? && registration.allow_missing_pkce == 1;
    let has_pkce = parameters.contains_key("code_challenge")
        || parameters.contains_key("code_challenge_method");
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
        || [
            "client_id",
            "redirect_uri",
            "response_type",
            "scope",
            "state",
        ]
        .iter()
        .any(|name| !parameters.contains_key(*name))
        || (!has_pkce && !allow_missing_pkce)
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
        code_challenge: parameters
            .get("code_challenge")
            .cloned()
            .unwrap_or_default(),
        code_challenge_method: parameters
            .get("code_challenge_method")
            .cloned()
            .unwrap_or_default(),
    };
    let validated = match raw.validate_with_optional_pkce(
        client_id,
        redirect_uri,
        policy.state_bytes(),
        policy.nonce_bytes(),
        allow_missing_pkce,
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
        return authorization_interaction_response(
            &request,
            &db,
            &issuer,
            client_id,
            redirect_uri,
            state,
            "login_required",
            false,
        )
        .await;
    }
    if prompts.contains(&"consent") {
        return authorization_interaction_response(
            &request,
            &db,
            &issuer,
            client_id,
            redirect_uri,
            state,
            "consent_required",
            false,
        )
        .await;
    }
    if prompts.contains(&"select_account") {
        return authorization_interaction_response(
            &request,
            &db,
            &issuer,
            client_id,
            redirect_uri,
            state,
            "account_selection_required",
            false,
        )
        .await;
    }

    let now = now_seconds().ok_or_else(|| worker::Error::RustError("server_error".into()))?;

    let Some(cookie) = browser_cookie(&request, "__Host-op-sso")? else {
        return authorization_interaction_response(
            &request,
            &db,
            &issuer,
            client_id,
            redirect_uri,
            state,
            "login_required",
            prompts.contains(&"none"),
        )
        .await;
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
               ON r.client_id=c.client_id AND r.redirect_uri=?3 AND r.active=1 \
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
        return authorization_interaction_response(
            &request,
            &db,
            &issuer,
            client_id,
            redirect_uri,
            state,
            "login_required",
            prompts.contains(&"none"),
        )
        .await;
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
            return authorization_interaction_response(
                &request,
                &db,
                &issuer,
                client_id,
                redirect_uri,
                state,
                "login_required",
                prompts.contains(&"none"),
            )
            .await;
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
                "acr",
            ],
            acr_values_supported: [mikaki_oidc::PASSKEY_UV_ACR],
            token_endpoint_auth_methods_supported: if conformance_deployment(&context.env)? {
                vec![
                    "private_key_jwt",
                    "client_secret_basic",
                    "client_secret_post",
                ]
            } else {
                vec!["private_key_jwt"]
            },
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
    mut request: worker::Request,
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
    let header = request.headers().get("authorization")?;
    let token = if let Some(header) = header {
        if request.method() == worker::Method::Post {
            let db = context.env.d1("DB")?;
            let policy = WorkerRuntimePolicy::from_db(&db).await?;
            if !read_bounded_body(&mut request, policy.form_body_bytes)
                .await?
                .is_empty()
            {
                return unauthorized();
            }
        }
        let Some((scheme, token)) = header.split_once(' ') else {
            return unauthorized();
        };
        if !scheme.eq_ignore_ascii_case("Bearer") {
            return unauthorized();
        }
        token.to_owned()
    } else if request.method() == worker::Method::Post && conformance_deployment(&context.env)? {
        let Some(content_type) = request.headers().get("content-type")? else {
            return unauthorized();
        };
        if !content_type.split(';').next().is_some_and(|value| {
            value
                .trim()
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        }) {
            return unauthorized();
        }
        let db = context.env.d1("DB")?;
        let policy = WorkerRuntimePolicy::from_db(&db).await?;
        let body = read_bounded_body(&mut request, policy.form_body_bytes).await?;
        let fields = url::form_urlencoded::parse(body.as_bytes()).collect::<Vec<_>>();
        match fields.as_slice() {
            [(key, value)] if key == "access_token" => value.to_string(),
            _ => return unauthorized(),
        }
    } else {
        return unauthorized();
    };
    if token.len() != 43
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
        .get_async("/login", passkey_login::get)
        .get_async("/login/login.js", passkey_login::script)
        .post_async("/login/finish", passkey_login::finish)
        .post_async("/register/start", enrollment::start)
        .post_async("/register/finish", enrollment::finish)
        .get_async("/enroll", enrollment::entry)
        .get_async("/enroll/complete", enrollment::complete)
        .get_async("/enroll/complete.js", enrollment::complete_script)
        .post_async("/admin/invitations/start", admin_invitations::start)
        .post_async("/admin/invitations/finish", admin_invitations::finish)
        .post_async("/session/check", session_check::check)
        .get_async("/admin", admin_invitations::page)
        .get_async("/admin/admin.js", admin_invitations::script)
        .get_async("/jwks", jwks_route)
        .get_async("/userinfo", userinfo_route)
        .post_async("/userinfo", userinfo_route)
        .post_async("/token", token_route)
        .get_async("/vault", vault_attributes::page)
        .get_async("/vault/session", vault_attributes::session)
        .get_async(
            "/vault/recipient-keys/userinfo",
            vault_attributes::recipient_key,
        )
        .get_async(
            "/vault/shares/userinfo/name",
            vault_attributes::share_status,
        )
        .post_async("/vault/shares/userinfo/name", vault_attributes::share)
        .delete_async(
            "/vault/shares/userinfo/name",
            vault_attributes::revoke_share,
        )
        .get_async("/vault/vault.js", vault_attributes::script)
        .get_async("/vault/attributes/:attribute", vault_attributes::get)
        .put_async("/vault/attributes/:attribute", vault_attributes::put)
        .delete_async("/vault/attributes/:attribute", vault_attributes::delete)
        .run(req, env)
        .await
}

#[cfg(all(target_arch = "wasm32", feature = "worker-entry"))]
#[worker::event(scheduled)]
pub async fn scheduled(
    event: worker::ScheduledEvent,
    env: worker::Env,
    _ctx: worker::ScheduleContext,
) {
    vault_gc::run(&env, event.schedule() as u64)
        .await
        .expect("Vault garbage collection failed");
}
