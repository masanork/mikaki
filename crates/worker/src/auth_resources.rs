//! Durable ingress budgets and bounded collection of protocol state.
use super::*;
use wasm_bindgen::JsValue;

#[derive(Deserialize)]
struct Policy {
    source_per_minute: u64,
    deployment_per_minute: u64,
}

pub(super) async fn admit(request: &worker::Request, env: &worker::Env) -> worker::Result<bool> {
    let path = request.url()?.path().to_owned();
    if !matches!(
        path.as_str(),
        "/authorize"
            | "/token"
            | "/par"
            | "/signin"
            | "/enroll"
            | "/login"
            | "/login/cue"
            | "/login/finish"
            | "/login/deny"
            | "/enroll/complete"
    ) {
        return Ok(true);
    }
    let db = env.d1("DB")?;
    let policy = db
        .prepare(
            "SELECT source_per_minute,deployment_per_minute FROM auth_resource_policy WHERE id=1",
        )
        .first::<Policy>(None)
        .await?
        .ok_or_else(|| worker::Error::RustError("auth_resource_policy_missing".into()))?;
    // Cloudflare supplies this header at the edge. Missing addresses share a
    // conservative budget; an attacker-chosen cookie cannot create a new IP budget.
    let source = request
        .headers()
        .get("CF-Connecting-IP")?
        .unwrap_or_else(|| "unknown".into());
    let source_hash = passkey_login::hash(&format!("auth-source:{source}"));
    let global_hash = passkey_login::hash("auth-deployment");
    let window =
        now_seconds().ok_or_else(|| worker::Error::RustError("server_error".into()))? / 60 * 60;
    let statements = [(global_hash, policy.deployment_per_minute), (source_hash, policy.source_per_minute)]
        .into_iter().map(|(key, limit)| db.prepare(
            "INSERT INTO auth_request_window(key_hash,window_start,attempts) SELECT ?1,?2,1 WHERE (SELECT count(*) FROM auth_request_window)<10000 OR EXISTS(SELECT 1 FROM auth_request_window WHERE key_hash=?1 AND window_start=?2) ON CONFLICT(key_hash,window_start) DO UPDATE SET attempts=attempts+1 WHERE attempts<?3 RETURNING attempts")
            .bind(&[JsValue::from_str(&key), JsValue::from_f64(window as f64), JsValue::from_f64(limit as f64)]))
        .collect::<worker::Result<Vec<_>>>()?;
    let results = db.batch(statements).await?;
    let admitted = results.iter().all(|result| {
        result
            .results::<serde_json::Value>()
            .is_ok_and(|rows| rows.len() == 1)
    });
    if !admitted {
        worker::console_log!("{{\"event\":\"auth_request_limited\"}}");
    }
    Ok(admitted)
}

pub(super) fn limited() -> worker::Result<worker::Response> {
    worker::Response::builder()
        .with_status(429)
        .with_header("Cache-Control", "no-store")?
        .with_header("Retry-After", "60")?
        .from_json(&serde_json::json!({"error":"temporarily_unavailable"}))
}

pub(super) async fn collect(env: &worker::Env) -> worker::Result<()> {
    let db = env.d1("DB")?;
    // Parents are deleted only after their last retained child. Native consent
    // audit and Vault contexts intentionally pin their parent state for now.
    let statements = include_str!("auth_retention.sql")
        .split(';')
        .filter(|sql| !sql.trim().is_empty())
        .map(|sql| db.prepare(sql))
        .collect();
    let results = db.batch(statements).await?;
    let reclaimed: f64 = results
        .iter()
        .filter_map(|r| r.meta().ok().flatten())
        .map(|meta| meta.changes.unwrap_or_default() as f64)
        .sum();
    let backlog = db.prepare(
        "SELECT 'login' AS kind,count(*) AS expired,min(expires_at) AS oldest FROM login_transaction WHERE expires_at<unixepoch()-86400 UNION ALL \
         SELECT 'codes',count(*),min(expires_at) FROM authorization_code WHERE expires_at<unixepoch()-7776000 UNION ALL \
         SELECT 'tokens',count(*),min(access_expires_at) FROM token_issue WHERE access_expires_at<unixepoch()-7776000 UNION ALL \
         SELECT 'sso',count(*),min(expires_at) FROM sso_session WHERE expires_at<unixepoch()-7776000 UNION ALL \
         SELECT 'logout',count(*),min(deadline) FROM sso_logout_event WHERE deadline<unixepoch()-7776000 UNION ALL \
         SELECT 'dpop',count(*),min(retain_until) FROM dpop_proof_use WHERE retain_until<unixepoch()"
    ).all().await?.results::<serde_json::Value>()?;
    worker::console_log!(
        "{}",
        serde_json::json!({"event":"auth_gc","reclaimed":reclaimed,"backlog":backlog})
    );
    Ok(())
}
