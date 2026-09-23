//! Cloudflare Workers platform adapter. Protocol decisions remain in `sakimori-oidc`.

#[cfg(target_arch = "wasm32")]
use serde::Deserialize;

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
#[serde(deny_unknown_fields)]
struct CompiledWorkerPolicy {
    schema_version: u32,
    policy_revision: String,
    projection_revision: String,
    assertion_ttl_seconds: u64,
    clock_skew_seconds: u64,
    jwt_bytes: u64,
    form_body_bytes: u64,
}

#[cfg(target_arch = "wasm32")]
pub struct WorkerRuntimePolicy {
    assertion: sakimori_oidc::ClientAssertionPolicy,
    jwt_bytes: usize,
    form_body_bytes: usize,
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
        if compiled.schema_version != 1
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
        {
            return Err(worker::Error::RustError("invalid runtime policy".into()));
        }
        let canonical = serde_json::json!({
            "assertion_ttl_seconds": compiled.assertion_ttl_seconds,
            "clock_skew_seconds": compiled.clock_skew_seconds,
            "form_body_bytes": compiled.form_body_bytes,
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
        let assertion = sakimori_oidc::ClientAssertionPolicy::from_seconds(
            compiled.assertion_ttl_seconds,
            compiled.clock_skew_seconds,
        )
        .map_err(|_| worker::Error::RustError("invalid runtime policy".into()))?;
        Ok(Self {
            assertion,
            jwt_bytes,
            form_body_bytes,
            policy_revision: compiled.policy_revision,
        })
    }

    pub fn policy_revision(&self) -> &str {
        &self.policy_revision
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
    input
        .validate(policy.jwt_bytes)
        .map_err(|_| worker::Error::RustError("invalid_request".into()))
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

#[cfg(all(target_arch = "wasm32", feature = "worker-entry"))]
#[worker::event(fetch)]
pub async fn main(
    req: worker::Request,
    env: worker::Env,
    _ctx: worker::Context,
) -> worker::Result<worker::Response> {
    worker::Router::with_data(())
        .get_async("/health", |_req, _ctx| async { worker::Response::ok("ok") })
        .run(req, env)
        .await
}
