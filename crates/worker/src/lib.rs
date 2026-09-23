//! Cloudflare Workers platform adapter. Protocol decisions remain in `sakimori-oidc`.

#[cfg(target_arch = "wasm32")]
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::JsCast;

#[cfg(target_arch = "wasm32")]
pub struct WorkersCryptoRandom;

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
pub async fn accept_client_assertion(
    db: &worker::d1::D1Database,
    assertion: &sakimori_oidc::VerifiedClientAssertion,
    endpoint: &str,
    clock_skew_seconds: u64,
    random: &mut impl sakimori_oidc::CryptographicRandom,
) -> worker::Result<()> {
    use wasm_bindgen::JsValue;

    if endpoint.is_empty() || assertion.audience() != endpoint {
        return Err(worker::Error::RustError(
            "client assertion endpoint mismatch".into(),
        ));
    }
    let retain_until = assertion
        .retain_until(clock_skew_seconds)
        .ok_or_else(|| worker::Error::RustError("client assertion expiry overflow".into()))?;
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
    Ok(())
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
