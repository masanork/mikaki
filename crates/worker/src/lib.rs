//! Cloudflare Workers platform adapter. Protocol decisions remain in `mikaki-oidc`.

#[cfg(target_arch = "wasm32")]
mod admin_invitations;
#[cfg(any(target_arch = "wasm32", test))]
mod app_association;
#[cfg(target_arch = "wasm32")]
mod auth_resources;
#[cfg(target_arch = "wasm32")]
mod branding;
#[cfg(target_arch = "wasm32")]
mod dpop;
#[cfg(target_arch = "wasm32")]
mod token;
#[cfg(target_arch = "wasm32")]
use token::*;
#[cfg(target_arch = "wasm32")]
mod enrollment;
#[cfg(target_arch = "wasm32")]
mod home;
#[cfg(target_arch = "wasm32")]
mod identity;
#[cfg(target_arch = "wasm32")]
mod logout;
#[cfg(target_arch = "wasm32")]
mod logout_delivery;
#[cfg(target_arch = "wasm32")]
mod par;
#[cfg(target_arch = "wasm32")]
mod passkey_login;
#[cfg(target_arch = "wasm32")]
mod session_check;

#[cfg(target_arch = "wasm32")]
mod i18n;
#[cfg(any(target_arch = "wasm32", test))]
mod vault_authzen;

#[cfg(target_arch = "wasm32")]
mod agent_access;
#[cfg(target_arch = "wasm32")]
mod owner_passkeys;
#[cfg(target_arch = "wasm32")]
mod vault_approved;
#[cfg(target_arch = "wasm32")]
#[cfg(target_arch = "wasm32")]
mod vault_claim_releases;
#[cfg(all(target_arch = "wasm32", feature = "worker-entry"))]
mod vault_gc;
#[cfg(target_arch = "wasm32")]
mod vault_http;
#[cfg(target_arch = "wasm32")]
mod vault_oauth_consent;
#[cfg(target_arch = "wasm32")]
#[cfg(target_arch = "wasm32")]
mod vault_owner_approved;
#[cfg(target_arch = "wasm32")]
mod vault_owner_keys;
#[cfg(target_arch = "wasm32")]
mod vault_owner_records;
#[cfg(target_arch = "wasm32")]
mod vault_record_sharing;
#[cfg(target_arch = "wasm32")]
mod vault_ui;

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
    requested_resource: Option<String>,
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
struct NativeClientTokenRow {
    client_revision: u64,
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
    dpop_jkt: Option<String>,
    sid: String,
    sub: String,
    nonce: Option<String>,
    scope: String,
    auth_time: i64,
    parent_expires_at: i64,
    signing_generation: i64,
    signing_algorithm: String,
    public_jwk: String,
}

#[cfg(target_arch = "wasm32")]
#[derive(Deserialize)]
struct VaultCodeGrantRow {
    grant_id: String,
    grant_version: i64,
    resource: String,
    attribute_id: String,
    expires_at: i64,
}

#[cfg(target_arch = "wasm32")]
struct VaultCodeGrant {
    grant_id: String,
    grant_version: i64,
    resource: String,
    attribute_id: String,
    expires_at: u64,
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
struct UserInfoScopeRow {
    scope: String,
}

#[cfg(target_arch = "wasm32")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UserInfoNameRow {
    name: String,
}

#[cfg(target_arch = "wasm32")]
#[derive(Deserialize)]
struct TokenBindingRow {
    dpop_jkt: Option<String>,
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
    client_type: String,
    auth_method: String,
}

#[cfg(target_arch = "wasm32")]
#[derive(Deserialize)]
struct LoginTransactionRow {
    authorization_url: String,
    client_id: String,
    challenge: String,
    expires_at: i64,
    failures: u32,
    // 0: RP authorization, 1: agent owner login, 2: first-party Web sign-in.
    owner_login: i64,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mikaki_linked_document: Option<serde_json::Value>,
}

#[cfg(target_arch = "wasm32")]
#[derive(Serialize)]
struct DiscoveryResponse {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pushed_authorization_request_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    require_pushed_authorization_requests: Option<bool>,
    jwks_uri: String,
    userinfo_endpoint: String,
    end_session_endpoint: String,
    backchannel_logout_supported: bool,
    backchannel_logout_session_supported: bool,
    response_types_supported: [&'static str; 1],
    response_modes_supported: [&'static str; 1],
    grant_types_supported: [&'static str; 1],
    subject_types_supported: [&'static str; 1],
    id_token_signing_alg_values_supported: [&'static str; 2],
    scopes_supported: Vec<&'static str>,
    claims_supported: Vec<&'static str>,
    acr_values_supported: [&'static str; 1],
    token_endpoint_auth_methods_supported: Vec<&'static str>,
    token_endpoint_auth_signing_alg_values_supported: [&'static str; 1],
    dpop_signing_alg_values_supported: [&'static str; 1],
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
    dpop_jkt: Option<String>,
    sid: String,
    sub: String,
    nonce: Option<String>,
    scope: &'static str,
    auth_time: u64,
    parent_expires_at: u64,
    signing_kid: String,
    signing_algorithm: String,
    signing_generation: u64,
    public_jwk: String,
    vault: Option<VaultCodeGrant>,
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

    #[allow(clippy::too_many_arguments)]
    async fn sign_logout_token(
        &self,
        issuer: &str,
        audience: &str,
        subject: &str,
        sid: &str,
        jti: &str,
        issued_at: u64,
        expires_at: u64,
    ) -> worker::Result<String> {
        match self {
            Self::Es256(key) => key
                .sign_logout_token(issuer, audience, subject, sid, jti, issued_at, expires_at)
                .map_err(|_| worker::Error::RustError("server_error".into())),
            Self::Rs256 { key, crypto_key } => {
                let input = mikaki_oidc::LogoutTokenSigningInput::new(
                    "RS256",
                    key.kid(),
                    issuer,
                    audience,
                    subject,
                    sid,
                    jti,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    authorization_details: Option<serde_json::Value>,
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
    fapi: bool,
) -> worker::Result<mikaki_oidc::ValidatedTokenEndpointInput> {
    if body.len() > policy.form_body_bytes {
        return Err(worker::Error::RustError("invalid_request".into()));
    }
    let input: mikaki_oidc::TokenEndpointInput = serde_urlencoded::from_str(body)
        .map_err(|_| worker::Error::RustError("invalid_request".into()))?;
    (if fapi {
        input.validate_for_fapi(policy.jwt_bytes)
    } else {
        input.validate(policy.jwt_bytes)
    })
    .map_err(|error| {
        let code = match error {
            mikaki_oidc::TokenEndpointInputError::UnsupportedGrantType => "unsupported_grant_type",
            mikaki_oidc::TokenEndpointInputError::InvalidClient => "invalid_client",
            mikaki_oidc::TokenEndpointInputError::InvalidRequest => "invalid_request",
            mikaki_oidc::TokenEndpointInputError::InvalidGrant => "invalid_grant",
        };
        worker::Error::RustError(code.into())
    })
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
fn authorization_url_without_vault_receipt(url: &url::Url) -> url::Url {
    let fields = url
        .query_pairs()
        .filter(|(name, _)| name != "vault_consent")
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    let mut clean = url.clone();
    clean.query_pairs_mut().clear().extend_pairs(fields);
    clean
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
fn authorization_par_error_page(
    request: &worker::Request,
    missing_reference: bool,
) -> worker::Result<worker::Response> {
    let strings = i18n::catalog(i18n::select(request, None)?);
    let title = i18n::html_escape(strings.message("parInvalidTitle"));
    let body = i18n::html_escape(strings.message(if missing_reference {
        "parMissingBody"
    } else {
        "parInvalidBody"
    }));
    let html = format!(
        "<!doctype html><html lang=\"{}\"><head><meta charset=\"utf-8\"><title>{title}</title><link rel=\"icon\" type=\"image/svg+xml\" href=\"/favicon.svg\"></head><body><main><h1>{title}</h1><p>{body}</p></main></body></html>",
        strings.locale,
    );
    worker::Response::builder()
        .with_status(400)
        .with_header("Cache-Control", "no-store")?
        .with_header(
            "Content-Security-Policy",
            "default-src 'none'; img-src 'self'; frame-ancestors 'none'",
        )?
        .from_html(html)
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
        passkey_login::start(request, db, issuer, client_id, redirect_uri, state).await
    }
}

/// RFC 8252 loopback registration uses port 0 as the exact registered
/// template. Only the port may vary in the authorization request.
#[cfg(target_arch = "wasm32")]
fn loopback_redirect_template(actual: &str) -> Option<String> {
    let mut url = url::Url::parse(actual).ok()?;
    if url.scheme() != "http"
        || url.as_str() != actual
        || url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() == "/"
        || !matches!(
            url.host(),
            Some(url::Host::Ipv4(std::net::Ipv4Addr::LOCALHOST))
                | Some(url::Host::Ipv6(std::net::Ipv6Addr::LOCALHOST))
        )
        || url.port().is_none_or(|port| port == 0)
    {
        return None;
    }
    url.set_port(Some(0)).ok()?;
    Some(url.into())
}

#[cfg(target_arch = "wasm32")]
async fn authorize_route(
    request: worker::Request,
    context: worker::RouteContext<()>,
) -> worker::Result<worker::Response> {
    use wasm_bindgen::JsValue;

    let db = context.env.d1("DB")?;
    let policy = WorkerRuntimePolicy::from_db(&db).await?;
    let mut request_url = request.url()?;
    let pushed = if par::required(&context.env)? {
        if policy.authorization_code_ttl_seconds() > 60 {
            return Err(worker::Error::RustError(
                "PAR code lifetime exceeds 60 seconds".into(),
            ));
        }
        let Some(reference) = parse_authorization_parameters(
            &request_url,
            policy.request_target_bytes(),
            policy.parameter_count(),
        ) else {
            return oauth_error_response("invalid_request", 400, false);
        };
        // RFC 9101 makes the authenticated pushed request authoritative. Query
        // duplicates may be present for compatibility, but never override it.
        if reference.too_many
            || reference.duplicates.contains("client_id")
            || reference.duplicates.contains("request_uri")
            || reference.values.contains_key("request")
        {
            return oauth_error_response("invalid_request", 400, false);
        }
        let (Some(client_id), Some(request_uri)) = (
            reference.values.get("client_id"),
            reference.values.get("request_uri"),
        ) else {
            return authorization_par_error_page(&request, true);
        };
        let Some(pushed) = par::load(&db, client_id, request_uri).await? else {
            return authorization_par_error_page(&request, false);
        };
        request_url.set_query(Some(&pushed.request_query));
        Some(pushed)
    } else {
        None
    };
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
    let loopback_template = loopback_redirect_template(redirect_uri);
    let registered_redirect_uri = loopback_template.as_deref().unwrap_or(redirect_uri);
    if redirect_uri.starts_with("http:") && loopback_template.is_none() {
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
    let fapi = fapi2_deployment(&context.env)?;
    let authorization_endpoint = format!("{issuer}/authorize");
    if request_url.as_str().split('?').next() != Some(authorization_endpoint.as_str()) {
        return Err(worker::Error::RustError("invalid_request".into()));
    }

    let registration = db
        .prepare(
            "SELECT c.revision AS client_revision,c.sector_identifier,c.allow_missing_pkce, \
             c.client_type,c.auth_method \
             FROM client c JOIN client_redirect_uri r ON r.client_id=c.client_id \
             WHERE c.client_id=?1 AND c.active=1 AND r.redirect_uri=?2 AND r.active=1 \
             AND (?3=0 OR c.client_type='web') \
             AND (?4=0 OR (c.client_type='native' AND c.auth_method='none'))",
        )
        .bind(&[
            JsValue::from_str(client_id),
            JsValue::from_str(registered_redirect_uri),
            JsValue::from_f64(if fapi { 1.0 } else { 0.0 }),
            JsValue::from_f64(if loopback_template.is_some() {
                1.0
            } else {
                0.0
            }),
        ])?
        .first::<ClientRegistrationRow>(None)
        .await?;
    let Some(registration) = registration else {
        let strings = i18n::catalog(i18n::select(
            &request,
            parameters.get("ui_locales").map(String::as_str),
        )?);
        let html = format!(
            "<!doctype html><html lang=\"{}\"><head><meta charset=\"utf-8\"><title>{}</title><link rel=\"icon\" type=\"image/svg+xml\" href=\"/favicon.svg\"></head><body><main><h1>{}</h1><p>{}</p></main></body></html>",
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
                "default-src 'none'; img-src 'self'; frame-ancestors 'none'",
            )?
            .from_html(html);
    };

    let state = if parsed.duplicates.contains("state") {
        None
    } else {
        parameters.get("state").map(String::as_str)
    };
    let vault_scope = parameters
        .get("scope")
        .is_some_and(|value| matches!(value.as_str(), "openid vault.read" | "vault.read openid"));
    let vault_preview = context
        .env
        .var("MIKAKI_NATIVE_VAULT_OAUTH")
        .ok()
        .is_some_and(|value| value.to_string() == "preview");
    let vault_request = if vault_scope
        && vault_preview
        && !fapi
        && pushed.is_none()
        && registration.client_type == "native"
        && registration.auth_method == "none"
        && loopback_template.is_none()
    {
        parameters
            .get("resource")
            .zip(parameters.get("authorization_details"))
            .and_then(|(resource, details)| {
                mikaki_oidc::VaultReadRequest::parse(
                    parameters["scope"].as_str(),
                    resource,
                    details,
                )
                .ok()
            })
    } else {
        None
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
    } else if parameters.contains_key("resource") && vault_request.is_none() {
        // No Vault-audience issuance path is connected yet. Never silently
        // turn a resource request into a UserInfo token.
        Some("invalid_target")
    } else if (parameters.contains_key("authorization_details")
        || parameters.contains_key("vault_consent"))
        && vault_request.is_none()
    {
        Some("invalid_request")
    } else if parameters.get("scope").is_some_and(|value| {
        !matches!(
            value.as_str(),
            "openid" | "openid profile" | "profile openid"
        ) && vault_request.is_none()
    }) {
        Some("invalid_scope")
    } else if parameters
        .get("response_mode")
        .is_some_and(|value| value != "query")
        || ["client_id", "redirect_uri", "response_type", "scope"]
            .iter()
            .any(|name| !parameters.contains_key(*name))
        || (!fapi && !parameters.contains_key("state"))
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
        state: parameters.get("state").cloned().unwrap_or_default(),
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
    let validated = match if vault_request.is_some() {
        raw.validate_for_vault(
            client_id,
            redirect_uri,
            policy.state_bytes(),
            policy.nonce_bytes(),
        )
    } else if fapi {
        raw.validate_for_fapi(
            client_id,
            redirect_uri,
            policy.state_bytes(),
            policy.nonce_bytes(),
        )
    } else {
        raw.validate_with_optional_pkce(
            client_id,
            redirect_uri,
            policy.state_bytes(),
            policy.nonce_bytes(),
            allow_missing_pkce,
        )
    } {
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
    if prompts.contains(&"consent") && vault_request.is_none() {
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
            JsValue::from_str(registered_redirect_uri),
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
    let vault_consent = if let Some(vault) = &vault_request {
        let clean_url = authorization_url_without_vault_receipt(&request_url).to_string();
        if let Some(tx) = parameters.get("vault_consent") {
            if !passkey_login::valid_tx(tx) {
                return authorization_error_response(
                    redirect_uri,
                    state,
                    &issuer,
                    "invalid_request",
                );
            }
            let approved = db
                .prepare(
                    "SELECT 1 AS approved FROM vault_oauth_consent vc \
                     WHERE vc.tx_id=?1 AND vc.sso_secret_hash=?2 AND vc.sso_id=?3 \
                     AND vc.account_id=?4 AND vc.client_id=?5 AND vc.client_revision=?6 \
                     AND vc.authorization_url=?7 AND vc.redirect_uri=?8 AND vc.state=?9 \
                     AND vc.attribute_id=?10 AND vc.resource=?11 \
                     AND vc.decision='approved' AND vc.expires_at>unixepoch()",
                )
                .bind(&[
                    JsValue::from_str(tx),
                    JsValue::from_str(&cookie_hash),
                    JsValue::from_str(&sso.sso_id),
                    JsValue::from_str(&sso.account_id),
                    JsValue::from_str(client_id),
                    JsValue::from_f64(sso.client_revision as f64),
                    JsValue::from_str(&clean_url),
                    JsValue::from_str(redirect_uri),
                    JsValue::from_str(validated.state()),
                    JsValue::from_str(vault.attribute()),
                    JsValue::from_str(vault.resource()),
                ])?
                .first::<i64>(Some("approved"))
                .await?;
            if approved.is_none() {
                return authorization_error_response(
                    redirect_uri,
                    state,
                    &issuer,
                    "invalid_request",
                );
            }
            Some(tx.clone())
        } else {
            if prompts.contains(&"none") {
                return authorization_error_response(
                    redirect_uri,
                    state,
                    &issuer,
                    "consent_required",
                );
            }
            let tx = passkey_login::random_secret(&mut random)?;
            let consent_expires = (now + 300).min(sso.parent_expires_at as u64);
            let inserted = db
                .prepare(
                    "INSERT INTO vault_oauth_consent \
                     (tx_id,sso_secret_hash,sso_id,account_id,client_id,client_revision, \
                      authorization_url,redirect_uri,state,attribute_id,resource,expires_at,created_at) \
                     VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
                )
                .bind(&[
                    JsValue::from_str(&tx),
                    JsValue::from_str(&cookie_hash),
                    JsValue::from_str(&sso.sso_id),
                    JsValue::from_str(&sso.account_id),
                    JsValue::from_str(client_id),
                    JsValue::from_f64(sso.client_revision as f64),
                    JsValue::from_str(&clean_url),
                    JsValue::from_str(redirect_uri),
                    JsValue::from_str(validated.state()),
                    JsValue::from_str(vault.attribute()),
                    JsValue::from_str(vault.resource()),
                    JsValue::from_f64(consent_expires as f64),
                    JsValue::from_f64(now as f64),
                ])?
                .run()
                .await;
            if inserted.is_err() {
                return authorization_error_response(
                    redirect_uri,
                    state,
                    &issuer,
                    "temporarily_unavailable",
                );
            }
            let target = format!("{issuer}/vault/oauth/consent?tx={tx}");
            return Ok(worker::Response::builder()
                .with_status(302)
                .with_header("Location", &target)?
                .with_header("Cache-Control", "no-store")?
                .with_header("Referrer-Policy", "no-referrer")?
                .empty());
        }
    } else {
        None
    };
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
        JsValue::from_str(registered_redirect_uri),
        JsValue::from_str(&now.to_string()),
    ];
    let code_values = [
        JsValue::from_str(code_hash),
        JsValue::from_str(client_id),
        JsValue::from_str(&sid),
        JsValue::from_str(&sso.client_revision.to_string()),
        JsValue::from_str(registered_redirect_uri),
        JsValue::from_str(validated.code_challenge()),
        JsValue::from_str(&expires_at.to_string()),
        JsValue::from_str(&now.to_string()),
        JsValue::from_str(if loopback_template.is_some() {
            redirect_uri
        } else {
            ""
        }),
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
    let mut statements = vec![
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
                JsValue::from_str(parameters["scope"].as_str()),
            ])?,
    ];
    if let (Some(tx), Some(vault)) = (vault_consent.as_deref(), vault_request.as_ref()) {
        let grant_id = passkey_login::random_secret(&mut random)?;
        let grant_expires = (now + 600).min(sso.parent_expires_at as u64);
        let clean_url = authorization_url_without_vault_receipt(&request_url).to_string();
        statements.push(
            db.prepare(
                "UPDATE vault_oauth_consent SET decision='consumed' \
                 WHERE tx_id=?1 AND sso_secret_hash=?2 AND sso_id=?3 \
                 AND account_id=?4 AND client_id=?5 AND client_revision=?6 \
                 AND authorization_url=?7 AND redirect_uri=?8 AND state=?9 \
                 AND attribute_id=?10 AND resource=?11 \
                 AND decision='approved' AND expires_at>unixepoch()",
            )
            .bind(&[
                JsValue::from_str(tx),
                JsValue::from_str(&cookie_hash),
                JsValue::from_str(&sso.sso_id),
                JsValue::from_str(&sso.account_id),
                JsValue::from_str(client_id),
                JsValue::from_f64(sso.client_revision as f64),
                JsValue::from_str(&clean_url),
                JsValue::from_str(redirect_uri),
                JsValue::from_str(validated.state()),
                JsValue::from_str(vault.attribute()),
                JsValue::from_str(vault.resource()),
            ])?,
        );
        statements.push(
            db.prepare(
                "INSERT INTO vault_oauth_grant \
                 (grant_id,consent_tx_id,account_id,client_id,client_revision,attribute_id, \
                  resource,action,version,expires_at,created_at) \
                 VALUES(?1,?2,?3,?4,?5,?6,?7,'read_ciphertext',1,?8,?9)",
            )
            .bind(&[
                JsValue::from_str(&grant_id),
                JsValue::from_str(tx),
                JsValue::from_str(&sso.account_id),
                JsValue::from_str(client_id),
                JsValue::from_f64(sso.client_revision as f64),
                JsValue::from_str(vault.attribute()),
                JsValue::from_str(vault.resource()),
                JsValue::from_f64(grant_expires as f64),
                JsValue::from_f64(now as f64),
            ])?,
        );
        statements.push(
            db.prepare(
                "INSERT INTO vault_oauth_code_context \
                 (code_hash,grant_id,grant_version,resource,attribute_id) \
                 VALUES(?1,?2,1,?3,?4)",
            )
            .bind(&[
                JsValue::from_str(code_hash),
                JsValue::from_str(&grant_id),
                JsValue::from_str(vault.resource()),
                JsValue::from_str(vault.attribute()),
            ])?,
        );
    }
    if let Some(pushed) = &pushed {
        statements.push(
            db.prepare(
                "UPDATE authorization_code SET dpop_jkt=?2 \
            WHERE code_hash=?1 AND dpop_jkt IS NULL",
            )
            .bind(&[
                JsValue::from_str(code_hash),
                pushed
                    .dpop_jkt
                    .as_deref()
                    .map(JsValue::from_str)
                    .unwrap_or(JsValue::NULL),
            ])?,
        );
        statements.push(
            db.prepare(
                "UPDATE par_request SET consumed_by=?1 \
            WHERE request_uri=?2 AND client_id=?3 AND client_revision=?4 \
            AND key_id=?5 AND key_revision=?6 AND consumed_by IS NULL \
            AND expires_at>CAST(strftime('%s','now') AS INTEGER) \
            AND EXISTS (SELECT 1 FROM client c JOIN client_key k \
                ON k.client_id=c.client_id AND k.kid=?5 \
                WHERE c.client_id=?3 AND c.active=1 AND c.revision=?4 \
                AND k.active=1 AND k.revision=?6)",
            )
            .bind(&[
                JsValue::from_str(code_hash),
                JsValue::from_str(&pushed.request_uri),
                JsValue::from_str(client_id),
                JsValue::from_str(&pushed.client_revision.to_string()),
                JsValue::from_str(&pushed.key_id),
                JsValue::from_str(&pushed.key_revision.to_string()),
            ])?,
        );
    }
    statements.push(
        db.prepare(include_str!("../sql/guard-authorization-code.sql"))
            .bind(&[
                guard_values[0].clone(),
                guard_values[1].clone(),
                guard_values[2].clone(),
                guard_values[3].clone(),
                JsValue::from_str(&now.to_string()),
            ])?,
    );
    if let Some(pushed) = &pushed {
        statements.push(
            db.prepare(
                "UPDATE atomic_guard SET passed=CASE WHEN EXISTS ( \
            SELECT 1 FROM par_request p JOIN authorization_code ac ON ac.code_hash=p.consumed_by \
            WHERE p.request_uri=?2 AND p.consumed_by=?1 AND p.client_id=?3 \
            AND p.client_revision=?4 AND p.key_id=?5 AND p.key_revision=?6 \
            AND p.expires_at>CAST(strftime('%s','now') AS INTEGER) \
            AND ac.client_id=?3 AND ac.dpop_jkt IS p.dpop_jkt \
            ) THEN 1 ELSE 0 END WHERE operation_id=?1",
            )
            .bind(&[
                JsValue::from_str(code_hash),
                JsValue::from_str(&pushed.request_uri),
                JsValue::from_str(client_id),
                JsValue::from_str(&pushed.client_revision.to_string()),
                JsValue::from_str(&pushed.key_id),
                JsValue::from_str(&pushed.key_revision.to_string()),
            ])?,
        );
    }
    statements.push(
        db.prepare(include_str!("../sql/delete-authorization-code-guard.sql"))
            .bind(&[guard_values[0].clone()])?,
    );
    if let Err(error) = db.batch(statements).await {
        if vault_consent.is_some() {
            return authorization_error_response(
                redirect_uri,
                state,
                &issuer,
                "temporarily_unavailable",
            );
        }
        if let Some(pushed) = &pushed {
            let consumed = db
                .prepare("SELECT consumed_by FROM par_request WHERE request_uri=?1")
                .bind(&[JsValue::from_str(&pushed.request_uri)])?
                .first::<ConsumedCodeRow>(None)
                .await;
            if consumed
                .ok()
                .flatten()
                .and_then(|row| row.consumed_by)
                .is_some_and(|winner| winner != code_hash)
            {
                return authorization_par_error_page(&request, false);
            }
        }
        return Err(error);
    }

    let mut target = url::Url::parse(validated.redirect_uri())
        .map_err(|_| worker::Error::RustError("invalid registered redirect".into()))?;
    {
        let mut query = target.query_pairs_mut();
        query.append_pair("code", presented_code.as_str());
        if !validated.state().is_empty() {
            query.append_pair("state", validated.state());
        }
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
    let name_release_available = if context.env.service("USERINFO_CLAIMS").is_ok()
        && context.env.bucket("VAULT_BLOBS").is_ok()
    {
        context
            .env
            .d1("DB")?
            .prepare(
                "SELECT 1 AS active FROM vault_claim_release_policy rp \
             WHERE rp.id=1 AND rp.enabled=1 AND ( \
             EXISTS(SELECT 1 FROM vault_share_policy WHERE id=1 AND enabled=1) OR \
             EXISTS(SELECT 1 FROM vault_record_share_policy WHERE id=1 AND enabled=1))",
            )
            .first::<i64>(Some("active"))
            .await?
            .is_some()
    } else {
        false
    };
    worker::Response::builder()
        .with_header("Cache-Control", "public, max-age=300")?
        .from_json(&DiscoveryResponse {
            authorization_endpoint: format!("{issuer}/authorize"),
            token_endpoint: format!("{issuer}/token"),
            pushed_authorization_request_endpoint: par::required(&context.env)?
                .then(|| format!("{issuer}/par")),
            require_pushed_authorization_requests: par::required(&context.env)?.then_some(true),
            jwks_uri: format!("{issuer}/jwks"),
            userinfo_endpoint: format!("{issuer}/userinfo"),
            end_session_endpoint: format!("{issuer}/logout"),
            backchannel_logout_supported: true,
            backchannel_logout_session_supported: true,
            issuer,
            response_types_supported: ["code"],
            response_modes_supported: ["query"],
            grant_types_supported: ["authorization_code"],
            subject_types_supported: ["pairwise"],
            id_token_signing_alg_values_supported: ["ES256", "RS256"],
            scopes_supported: vec!["openid", "profile"],
            claims_supported: {
                let mut claims = vec![
                    "iss",
                    "sub",
                    "aud",
                    "exp",
                    "iat",
                    "nonce",
                    "auth_time",
                    "sid",
                    "acr",
                ];
                if name_release_available {
                    claims.push("name");
                }
                if identity::claims_enabled(&context.env) {
                    claims.push(identity::CLAIM);
                }
                claims
            },
            acr_values_supported: [mikaki_oidc::PASSKEY_UV_ACR],
            token_endpoint_auth_methods_supported: if conformance_deployment(&context.env)? {
                vec![
                    "private_key_jwt",
                    "client_secret_basic",
                    "client_secret_post",
                ]
            } else if fapi2_deployment(&context.env)? {
                vec!["private_key_jwt"]
            } else {
                vec!["private_key_jwt", "none"]
            },
            token_endpoint_auth_signing_alg_values_supported: ["ES256"],
            dpop_signing_alg_values_supported: ["ES256"],
            code_challenge_methods_supported: ["S256"],
            authorization_response_iss_parameter_supported: true,
            request_parameter_supported: false,
            request_uri_parameter_supported: par::required(&context.env)?,
            claims_parameter_supported: false,
        })
}

#[cfg(target_arch = "wasm32")]
#[derive(Deserialize)]
struct LatestMigrationRow {
    name: String,
}

#[cfg(target_arch = "wasm32")]
fn ready_token_bytes(value: &str) -> Option<[u8; 32]> {
    if value.len() != 43 {
        return None;
    }
    let decoded = URL_SAFE_NO_PAD.decode(value).ok()?;
    let bytes: [u8; 32] = decoded.try_into().ok()?;
    (URL_SAFE_NO_PAD.encode(bytes) == value).then_some(bytes)
}

#[cfg(target_arch = "wasm32")]
fn authorized_ready(request: &worker::Request, env: &worker::Env) -> bool {
    let Ok(secret) = env.secret("MIKAKI_READY_TOKEN") else {
        return false;
    };
    let Some(expected) = ready_token_bytes(&secret.to_string()) else {
        return false;
    };
    let Ok(Some(header)) = request.headers().get("authorization") else {
        return false;
    };
    let Some(actual) = header.strip_prefix("Bearer ").and_then(ready_token_bytes) else {
        return false;
    };
    expected.ct_eq(&actual).unwrap_u8() == 1
}

#[cfg(target_arch = "wasm32")]
async fn ready_route(
    request: worker::Request,
    context: worker::RouteContext<()>,
) -> worker::Result<worker::Response> {
    if !authorized_ready(&request, &context.env) {
        return Ok(worker::Response::builder()
            .with_status(404)
            .with_header("Cache-Control", "no-store")?
            .empty());
    }
    let ready = async {
        let version = context
            .env
            .get_binding::<worker::WorkerVersionMetadata>("CF_VERSION_METADATA")?;
        if version.id().is_empty() {
            return Err(worker::Error::RustError("missing Worker version".into()));
        }
        let bucket = context.env.bucket("VAULT_BLOBS")?;
        // Probe only metadata in a reserved namespace; absence is healthy.
        // Bound this dependency check without writing or reading Vault ciphertext.
        match futures_util::future::select(
            Box::pin(bucket.head("__mikaki_readiness__/r2-head")),
            Box::pin(worker::Delay::from(std::time::Duration::from_secs(3))),
        )
        .await
        {
            futures_util::future::Either::Left((result, _)) => {
                result?;
            }
            futures_util::future::Either::Right(_) => {
                return Err(worker::Error::RustError("R2 readiness timed out".into()));
            }
        }
        let issuer = context.env.var("MIKAKI_ISSUER")?.to_string();
        if configured_issuer(&issuer).is_none() {
            return Err(worker::Error::RustError("invalid issuer".into()));
        }
        let private_jwk = context.env.secret("OP_PRIVATE_JWK")?.to_string();
        let signer = WorkerTokenSigner::from_secret(&private_jwk).await?;
        let db = context.env.d1("DB")?;
        WorkerRuntimePolicy::from_db(&db).await?;
        let migration = db
            .prepare("SELECT name FROM d1_migrations ORDER BY id DESC LIMIT 1")
            .first::<LatestMigrationRow>(None)
            .await?;
        if migration.as_ref().map(|row| row.name.as_str()) != Some(env!("MIKAKI_LATEST_MIGRATION"))
        {
            return Err(worker::Error::RustError(
                "Worker migrations are incomplete".into(),
            ));
        }
        let signing_key = db
            .prepare("SELECT public_jwk FROM signing_key WHERE active=1 AND kid=?1 AND algorithm=?2 LIMIT 1")
            .bind(&[
                wasm_bindgen::JsValue::from_str(signer.kid()),
                wasm_bindgen::JsValue::from_str(signer.algorithm()),
            ])?
            .first::<SigningPublicKeyRow>(None)
            .await?;
        if !signing_key.is_some_and(|row| signer.matches_public_jwk(&row.public_jwk)) {
            return Err(worker::Error::RustError(
                "signing key is unavailable".into(),
            ));
        }
        let response = context
            .env
            .service("USERINFO_CLAIMS")?
            .fetch("https://userinfo.internal/internal/ready", None)
            .await?;
        if response.status_code() != 204 {
            return Err(worker::Error::RustError(
                "claim Worker is unavailable".into(),
            ));
        }
        Ok::<(), worker::Error>(())
    };
    // Bound the complete read-only probe, including D1 and the Claim Worker.
    let ready = match futures_util::future::select(
        Box::pin(ready),
        Box::pin(worker::Delay::from(std::time::Duration::from_secs(5))),
    )
    .await
    {
        futures_util::future::Either::Left((result, _)) => result,
        futures_util::future::Either::Right(_) => {
            Err(worker::Error::RustError("readiness timed out".into()))
        }
    };
    if ready.is_err() {
        worker::console_warn!("readiness unavailable");
    }
    Ok(worker::Response::builder()
        .with_status(if ready.is_ok() { 204 } else { 503 })
        .with_header("Cache-Control", "no-store")?
        .empty())
}

#[cfg(target_arch = "wasm32")]
async fn userinfo_name(
    env: &worker::Env,
    db: &worker::d1::D1Database,
    token_hash: &str,
) -> worker::Result<Option<String>> {
    use wasm_bindgen::JsValue;

    let scope = db
        .prepare(
            "SELECT cc.scope FROM token_issue ti \
         JOIN authorization_code ac ON ac.code_hash=ti.code_hash \
         JOIN code_context cc ON cc.code_hash=ac.code_hash \
         JOIN valid_client_session v ON v.client_id=ac.client_id AND v.sid=ac.sid \
         WHERE ti.access_hash=?1 AND ti.revoked=0 AND ti.access_expires_at>unixepoch()",
        )
        .bind(&[JsValue::from_str(token_hash)])?
        .first::<UserInfoScopeRow>(None)
        .await?;
    let Some(scope) = scope else {
        return Err(worker::Error::RustError("invalid_token".into()));
    };
    if scope.scope == "openid" {
        return Ok(None);
    }
    if !matches!(scope.scope.as_str(), "openid profile" | "profile openid") {
        return Err(worker::Error::RustError("invalid_token".into()));
    }
    let body = serde_json::json!({"access_hash": token_hash}).to_string();
    let mut init = worker::RequestInit::new();
    init.with_method(worker::Method::Post)
        .with_body(Some(JsValue::from_str(&body)));
    init.headers.set("Content-Type", "application/json")?;
    let mut response = env
        .service("USERINFO_CLAIMS")?
        .fetch("https://userinfo.internal/internal/claims/name", Some(init))
        .await?;
    if response.status_code() == 204 {
        return Ok(None);
    }
    if response.status_code() != 200 {
        return Err(worker::Error::RustError("claim release unavailable".into()));
    }
    let bytes = response.bytes().await?;
    if bytes.len() > 2048 {
        return Err(worker::Error::RustError("claim release unavailable".into()));
    }
    let value: UserInfoNameRow = serde_json::from_slice(&bytes)
        .map_err(|_| worker::Error::RustError("claim release unavailable".into()))?;
    if value.name.is_empty() || value.name.len() > 1024 {
        return Err(worker::Error::RustError("claim release unavailable".into()));
    }
    Ok(Some(value.name))
}

#[cfg(target_arch = "wasm32")]
fn userinfo_unavailable() -> worker::Result<worker::Response> {
    Ok(worker::Response::builder()
        .with_status(503)
        .with_header("Cache-Control", "no-store")?
        .with_header("Pragma", "no-cache")?
        .with_header("Retry-After", "5")?
        .empty())
}

#[cfg(target_arch = "wasm32")]
async fn userinfo_route(
    request: worker::Request,
    context: worker::RouteContext<()>,
) -> worker::Result<worker::Response> {
    match userinfo_route_inner(request, context).await {
        Ok(response) => Ok(response),
        Err(_) => userinfo_unavailable(),
    }
}

#[cfg(target_arch = "wasm32")]
async fn userinfo_route_inner(
    mut request: worker::Request,
    context: worker::RouteContext<()>,
) -> worker::Result<worker::Response> {
    let header = request.headers().get("authorization")?;
    let requested_dpop = header
        .as_deref()
        .and_then(|value| value.split_once(' '))
        .is_some_and(|(scheme, _)| scheme.eq_ignore_ascii_case("DPoP"));
    let unauthorized = || {
        worker::Response::builder()
            .with_status(401)
            .with_header("Cache-Control", "no-store")?
            .with_header("Pragma", "no-cache")?
            .with_header(
                "WWW-Authenticate",
                if requested_dpop {
                    "DPoP error=\"invalid_token\", algs=\"ES256\""
                } else {
                    "Bearer error=\"invalid_token\""
                },
            )?
            .from_json(&TokenEndpointErrorBody {
                error: "invalid_token".into(),
            })
    };
    if fapi2_deployment(&context.env)? && !requested_dpop {
        return unauthorized();
    }
    if request.url()?.query_pairs().next().is_some() {
        return worker::Response::builder()
            .with_status(400)
            .with_header("Cache-Control", "no-store")?
            .from_json(&TokenEndpointErrorBody {
                error: "invalid_request".into(),
            });
    }
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
        if !scheme.eq_ignore_ascii_case("Bearer") && !scheme.eq_ignore_ascii_case("DPoP") {
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
    if requested_dpop {
        let invalid_proof = || {
            worker::Response::builder()
                .with_status(401)
                .with_header("Cache-Control", "no-store")?
                .with_header("Pragma", "no-cache")?
                .with_header(
                    "WWW-Authenticate",
                    "DPoP error=\"invalid_dpop_proof\", algs=\"ES256\"",
                )?
                .from_json(&TokenEndpointErrorBody {
                    error: "invalid_dpop_proof".into(),
                })
        };
        let issuer = configured_issuer(&context.env.var("MIKAKI_ISSUER")?.to_string())
            .ok_or_else(|| worker::Error::RustError("server_error".into()))?;
        let endpoint = format!("{issuer}/userinfo");
        if request.url()?.to_string() != endpoint {
            return unauthorized();
        }
        let binding = db
            .prepare(
                "SELECT ti.dpop_jkt FROM token_issue ti \
                JOIN authorization_code ac ON ac.code_hash=ti.code_hash \
                JOIN valid_client_session v ON v.client_id=ac.client_id AND v.sid=ac.sid \
                WHERE ti.access_hash=?1 AND ti.revoked=0 \
                AND NOT EXISTS (SELECT 1 FROM vault_oauth_token_context vt WHERE vt.access_hash=ti.access_hash) \
                AND ti.access_expires_at>CAST(strftime('%s','now') AS INTEGER)",
            )
            .bind(&[wasm_bindgen::JsValue::from_str(&token_hash)])?
            .first::<TokenBindingRow>(None)
            .await?;
        let Some(jkt) = binding.and_then(|row| row.dpop_jkt) else {
            return unauthorized();
        };
        let require_nonce = dpop_nonce_required(&context.env)?;
        let challenge = if require_nonce {
            Some(
                dpop::current_nonce(
                    &db,
                    dpop::NonceScope::ResourceServer,
                    &mut WorkersCryptoRandom,
                )
                .await?,
            )
        } else {
            None
        };
        let Some(compact) = request.headers().get("dpop")? else {
            if let Some(nonce) = challenge.as_deref() {
                return dpop_nonce_error_response(nonce, true);
            }
            return invalid_proof();
        };
        let method = match request.method() {
            worker::Method::Get => "GET",
            worker::Method::Post => "POST",
            _ => return unauthorized(),
        };
        let Ok(proof) = mikaki_oidc::verify_dpop_proof(
            &compact,
            method,
            &endpoint,
            mikaki_oidc::DpopTarget::Resource {
                access_token: &token,
                thumbprint: &jkt,
            },
            now as u64,
        ) else {
            return invalid_proof();
        };
        if require_nonce
            && !dpop::accepts_nonce(&db, dpop::NonceScope::ResourceServer, proof.nonce()).await?
        {
            return dpop_nonce_error_response(
                challenge
                    .as_deref()
                    .expect("required nonce has a challenge"),
                true,
            );
        }
        let mut receipt = [0u8; 32];
        mikaki_oidc::CryptographicRandom::fill(&mut WorkersCryptoRandom, &mut receipt)
            .map_err(|_| worker::Error::RustError("server_error".into()))?;
        let Some(sub) = dpop::authorize_resource(
            &db,
            &proof,
            &URL_SAFE_NO_PAD.encode(receipt),
            &token_hash,
            require_nonce,
        )
        .await?
        else {
            return invalid_proof();
        };
        let name = userinfo_name(&context.env, &db, &token_hash).await?;
        return worker::Response::builder()
            .with_header("Cache-Control", "no-store")?
            .with_header("Pragma", "no-cache")?
            .from_json(&UserInfoResponse {
                sub,
                name,
                mikaki_linked_document: identity::userinfo(&context.env, &db, &token_hash).await?,
            });
    }
    let subject = db
        .prepare(
            "SELECT v.sub FROM token_issue ti \
             JOIN authorization_code ac ON ac.code_hash=ti.code_hash \
             JOIN valid_client_session v ON v.client_id=ac.client_id AND v.sid=ac.sid \
             WHERE ti.access_hash=?1 AND ti.revoked=0 AND ti.access_expires_at>?2 AND ti.dpop_jkt IS NULL \
             AND NOT EXISTS (SELECT 1 FROM vault_oauth_token_context vt WHERE vt.access_hash=ti.access_hash)",
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
    let name = userinfo_name(&context.env, &db, &token_hash).await?;
    worker::Response::builder()
        .with_header("Cache-Control", "no-store")?
        .with_header("Pragma", "no-cache")?
        .from_json(&UserInfoResponse {
            sub: subject.sub,
            name,
            mikaki_linked_document: identity::userinfo(&context.env, &db, &token_hash).await?,
        })
}

#[cfg(all(target_arch = "wasm32", feature = "worker-entry"))]
#[worker::event(fetch)]
pub async fn main(
    req: worker::Request,
    env: worker::Env,
    _ctx: worker::Context,
) -> worker::Result<worker::Response> {
    // The native callback host must not become a second OP origin. A browser
    // reaching the callback gets a fixed redirect that drops the code and
    // state query before displaying recovery instructions.
    let url = req.url()?;
    if matches!(
        url.host_str(),
        Some("app.mikaki.org" | "mikaki-native.tossa.app")
    ) {
        return match native_host_route(req.method() == worker::Method::Get, url.path()) {
            NativeHostRoute::Apple => app_association::apple_for_env(&env),
            NativeHostRoute::Android => app_association::android_for_env(&env),
            NativeHostRoute::CallbackFallback => app_association::callback_fallback(),
            NativeHostRoute::Help => app_association::callback_help(),
            NativeHostRoute::NotFound => Ok(worker::Response::builder()
                .with_status(404)
                .with_header("Cache-Control", "no-store")?
                .with_header("Referrer-Policy", "no-referrer")?
                .fixed(b"not found".to_vec())),
        };
    }
    if !auth_resources::admit(&req, &env).await? {
        return auth_resources::limited();
    }
    worker::Router::with_data(())
        .get_async("/", home::get)
        .get_async("/signin", passkey_login::web_signin)
        .get_async("/favicon.svg", branding::get)
        .get_async("/favicon.ico", branding::get)
        .get_async("/favicon-32x32.png", branding::get)
        .get_async("/health", |_req, _ctx| async { worker::Response::ok("ok") })
        .get_async("/ready", ready_route)
        .get_async("/version", |_req, ctx| async move {
            let version = match ctx
                .env
                .get_binding::<worker::WorkerVersionMetadata>("CF_VERSION_METADATA")
            {
                Ok(version) => version,
                Err(_) => return worker::Response::error("version metadata unavailable", 503),
            };
            let commit = env!("MIKAKI_SOURCE_COMMIT");
            worker::Response::builder()
                .with_header("Cache-Control", "no-store")?
                .from_json(&serde_json::json!({
                    "worker": "mikaki-op",
                    "version_id": version.id(),
                    "source_commit": if commit.is_empty() { None } else { Some(commit) },
                    "source_clean": env!("MIKAKI_SOURCE_CLEAN") == "true",
                }))
        })
        .get_async("/.well-known/openid-configuration", discovery_route)
        .get_async("/authorize", authorize_route)
        .get_async("/login", passkey_login::get)
        .get_async("/login/cue", passkey_login::cue)
        .get_async("/login/login.js", passkey_login::script)
        .get_async("/login/login.css", passkey_login::stylesheet)
        .get_async("/ui/product.css", passkey_login::product_stylesheet)
        .get_async("/ui/session-events.js", logout::script)
        .post_async("/login/finish", passkey_login::finish)
        .post_async("/login/deny", passkey_login::deny)
        .post_async("/register/start", enrollment::start)
        .post_async("/register/finish", enrollment::finish)
        .get_async("/enroll", enrollment::entry)
        .get_async("/enroll/complete", enrollment::complete)
        .get_async("/enroll/complete.js", enrollment::complete_script)
        .post_async("/admin/invitations/start", admin_invitations::start)
        .post_async("/admin/invitations/finish", admin_invitations::finish)
        .post_async("/session/check", session_check::check)
        .get_async("/logout", logout::get)
        .post_async("/logout", logout::post)
        .get_async("/admin", admin_invitations::page)
        .get_async("/admin/admin.js", admin_invitations::script)
        .get_async("/jwks", jwks_route)
        .get_async("/userinfo", userinfo_route)
        .post_async("/userinfo", userinfo_route)
        .post_async("/token", token_route)
        .post_async("/par", par::route)
        .get_async("/identity", identity::manage_get)
        .post_async("/identity/erase", identity::manage_post)
        .post_async("/identity/intake", identity::intake)
        .get_async("/identity/approve", identity::approve_get)
        .post_async("/identity/approve", identity::approve_post)
        .post_async("/identity/poll", identity::poll)
        .get_async("/identity/documents", identity::documents)
        .delete_async("/identity/documents/:document", identity::revoke)
        .get_async(
            "/.well-known/openid-credential-issuer/identity/issuer",
            identity::metadata,
        )
        .get_async(
            "/.well-known/oauth-authorization-server/identity/issuer",
            identity::oauth_metadata,
        )
        .get_async("/identity/issuer/jwks", identity::jwks)
        .get_async(
            "/identity/issuer/types/linked-document",
            identity::type_metadata,
        )
        .post_async("/identity/release", identity::release_post)
        .get_async("/identity/issuer/authorize", identity::authorize_get)
        .post_async("/identity/issuer/authorize", identity::authorize_post)
        .post_async("/identity/issuer/par", identity::par)
        .post_async("/identity/issuer/token", identity::token)
        .post_async("/identity/issuer/nonce", identity::nonce)
        .post_async("/identity/issuer/credential", identity::credential)
        .post_async("/identity/attester/challenge", identity::attester_challenge)
        .post_async("/identity/attester/attestation", identity::attester_redeem)
        .get_async("/vault", vault_ui::page)
        .get_async("/vault/oauth/consent", vault_oauth_consent::get)
        .post_async("/vault/oauth/consent", vault_oauth_consent::post)
        .get_async("/vault/session", vault_ui::session)
        .get_async(
            "/vault/record-recipient-keys/userinfo",
            vault_record_sharing::recipient,
        )
        .get_async(
            "/vault/records/personal/name/sharing",
            vault_record_sharing::status,
        )
        .post_async(
            "/vault/records/personal/name/sharing",
            vault_record_sharing::share,
        )
        .delete_async(
            "/vault/records/personal/name/sharing",
            vault_record_sharing::revoke,
        )
        .get_async(
            "/vault/records/personal/name/releases",
            vault_claim_releases::status_record,
        )
        .post_async(
            "/vault/records/personal/name/releases",
            vault_claim_releases::grant_record,
        )
        .delete_async(
            "/vault/records/personal/name/releases",
            vault_claim_releases::revoke_record,
        )
        .post_async(
            "/vault/records/:collection/:record/approved",
            vault_owner_records::approved,
        )
        .get_async("/vault/records/:collection", vault_owner_records::list)
        .get_async(
            "/vault/records/:collection/:record",
            vault_owner_records::get,
        )
        .put_async(
            "/vault/records/:collection/:record",
            vault_owner_records::put,
        )
        .delete_async(
            "/vault/records/:collection/:record",
            vault_owner_records::delete,
        )
        .get_async("/vault/owner-key", vault_owner_keys::get)
        .put_async("/vault/owner-key", vault_owner_keys::create)
        .get_async("/vault/passkeys", owner_passkeys::list)
        .post_async("/vault/passkeys/start", owner_passkeys::start)
        .post_async("/vault/passkeys/finish", owner_passkeys::finish)
        .get_async("/vault/agents/:operation", agent_access::route)
        .post_async("/vault/agents/:operation", agent_access::route)
        .get_async("/vault/vault.js", vault_ui::script)
        .get_async("/vault/search.js", vault_ui::search_script)
        .get_async("/vault/sqlite3.wasm", vault_ui::search_wasm)
        .run(req, env)
        .await
        .or_else(|error| {
            if error.to_string().contains("auth_capacity_exceeded") {
                auth_resources::limited()
            } else {
                Err(error)
            }
        })
}

#[cfg(any(test, all(target_arch = "wasm32", feature = "worker-entry")))]
#[derive(Debug, PartialEq, Eq)]
enum NativeHostRoute {
    Apple,
    Android,
    CallbackFallback,
    Help,
    NotFound,
}

#[cfg(any(test, all(target_arch = "wasm32", feature = "worker-entry")))]
fn native_host_route(is_get: bool, path: &str) -> NativeHostRoute {
    match (is_get, path) {
        (true, "/.well-known/apple-app-site-association") => NativeHostRoute::Apple,
        (true, "/.well-known/assetlinks.json") => NativeHostRoute::Android,
        (true, "/oidc/native/callback") => NativeHostRoute::CallbackFallback,
        (true, "/identity/issuance/callback") => NativeHostRoute::CallbackFallback,
        (true, "/native-link-help") => NativeHostRoute::Help,
        _ => NativeHostRoute::NotFound,
    }
}

#[cfg(test)]
mod native_host_tests {
    use super::{NativeHostRoute, native_host_route};

    #[test]
    fn native_host_exposes_association_and_callback_recovery() {
        assert_eq!(
            native_host_route(true, "/.well-known/apple-app-site-association"),
            NativeHostRoute::Apple
        );
        assert_eq!(
            native_host_route(true, "/.well-known/assetlinks.json"),
            NativeHostRoute::Android
        );
        assert_eq!(
            native_host_route(true, "/oidc/native/callback"),
            NativeHostRoute::CallbackFallback
        );
        assert_eq!(
            native_host_route(true, "/identity/issuance/callback"),
            NativeHostRoute::CallbackFallback
        );
        assert_eq!(
            native_host_route(true, "/native-link-help"),
            NativeHostRoute::Help
        );
        for path in ["/authorize", "/token", "/jwks"] {
            assert_eq!(native_host_route(true, path), NativeHostRoute::NotFound);
        }
        assert_eq!(
            native_host_route(false, "/oidc/native/callback"),
            NativeHostRoute::NotFound
        );
        assert_eq!(
            native_host_route(false, "/identity/issuance/callback"),
            NativeHostRoute::NotFound
        );
        assert_eq!(
            native_host_route(false, "/.well-known/apple-app-site-association"),
            NativeHostRoute::NotFound
        );
    }
}

#[cfg(all(target_arch = "wasm32", feature = "worker-entry"))]
#[worker::event(scheduled)]
pub async fn scheduled(
    event: worker::ScheduledEvent,
    env: worker::Env,
    _ctx: worker::ScheduleContext,
) {
    if matches!(event.cron().as_str(), "*/10 * * * *" | "0 3 * * *")
        && vault_gc::run(&env, event.schedule() as u64).await.is_err()
    {
        worker::console_error!("{{\"event\":\"vault_gc_failure\"}}");
    }
    if auth_resources::collect(&env).await.is_err() {
        worker::console_error!("{{\"event\":\"auth_gc_failure\"}}");
    }
    if identity::purge(&env).await.is_err() {
        worker::console_error!("{{\"event\":\"identity_gc_failure\"}}");
    }
    logout_delivery::run_due(&env)
        .await
        .expect("Logout delivery failed");
    if event.cron() == "* * * * *" {
        vault_owner_records::collect(&env, event.schedule() as u64)
            .await
            .expect("Owner record garbage collection failed");
    }
}
