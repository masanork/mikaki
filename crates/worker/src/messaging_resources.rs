//! Chat-only ingress reservations and bounded expiry; no authentication counters.
use serde::Deserialize;
use wasm_bindgen::JsValue;
use worker::{Env, Request, Response};

#[derive(Deserialize)]
struct Policy {
    source_per_minute: u32,
    deployment_per_minute: u32,
}

async fn policy(env: &Env) -> worker::Result<Policy> {
    env.d1("DB")?
        .with_session_constraint(worker::D1SessionConstraint::FirstPrimary)?
        .prepare("SELECT source_per_minute,deployment_per_minute FROM messaging_resource_policy WHERE id=1")
        .first(None)
        .await?
        .ok_or_else(|| worker::Error::RustError("messaging_resource_policy_missing".into()))
}

pub(super) async fn ready(env: &Env) -> worker::Result<()> {
    policy(env).await.map(|_| ())
}

pub(super) async fn admit(request: &Request, env: &Env) -> worker::Result<bool> {
    let policy = policy(env).await?;
    // The edge supplies this address. Cookies and forwarded headers cannot
    // create another source budget. Missing addresses share one bounded bucket.
    let source = request
        .headers()
        .get("CF-Connecting-IP")?
        .unwrap_or_else(|| "unknown".into());
    let source_hash = crate::passkey_login::hash(&format!("messaging-source:{source}"));
    let deployment_hash = crate::passkey_login::hash("messaging-deployment");
    let window =
        crate::now_seconds().ok_or_else(|| worker::Error::RustError("server_error".into()))? / 60
            * 60;
    let db = env.d1("DB")?;
    // Expiry and both reservations share a transaction. On storage failure,
    // neither partial debit nor partial expiry survives. Each sweep is bounded.
    let results = db
        .batch(vec![
            db.prepare(include_str!("messaging_retention.sql")),
            db.prepare(include_str!("messaging_admission.sql")).bind(&[
                JsValue::from_str(&deployment_hash),
                JsValue::from_str(&source_hash),
                JsValue::from_f64(window as f64),
                JsValue::from(policy.deployment_per_minute),
                JsValue::from(policy.source_per_minute),
            ])?,
        ])
        .await?;
    let admission = results
        .get(1)
        .ok_or_else(|| worker::Error::RustError("messaging_admission_result_missing".into()))?;
    let admitted = admission.results::<serde_json::Value>()?.len() == 2;
    if !admitted {
        worker::console_log!("{{\"event\":\"messaging_request_limited\"}}");
    }
    Ok(admitted)
}

pub(super) fn limited() -> worker::Result<Response> {
    Response::builder()
        .with_status(429)
        .with_header("Cache-Control", "no-store")?
        .with_header("Retry-After", "60")?
        .from_json(&serde_json::json!({"error":"temporarily_unavailable"}))
}

pub(super) async fn collect(env: &Env) -> worker::Result<()> {
    env.d1("DB")?
        .prepare(include_str!("messaging_retention.sql"))
        .run()
        .await?;
    Ok(())
}
