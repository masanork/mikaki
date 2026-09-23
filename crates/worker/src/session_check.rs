//! Client-authenticated session validity for managed RPs. This is a mikaki
//! extension, not OIDC Session Management or OAuth token introspection.

use super::*;
use wasm_bindgen::JsValue;

const ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    client_id: String,
    client_assertion_type: String,
    client_assertion: String,
    sid: String,
}

#[derive(Deserialize)]
struct Policy {
    lease_ttl_seconds: u64,
    app_idle_timeout_seconds: u64,
    revision: u64,
}

#[derive(Deserialize)]
struct Session {
    sub: String,
    auth_time: u64,
    expires_at: u64,
}

#[derive(Serialize)]
struct Inactive {
    active: bool,
}

#[derive(Serialize)]
struct Active<'a> {
    active: bool,
    sub: &'a str,
    auth_time: u64,
    expires_at: u64,
    lease_ttl: u64,
    app_idle_timeout: u64,
    policy_revision: &'a str,
    session_policy_revision: u64,
}

fn reject(status: u16) -> worker::Result<worker::Response> {
    Ok(worker::Response::builder()
        .with_status(status)
        .with_header("Cache-Control", "no-store")?
        .empty())
}

pub async fn check(
    mut request: worker::Request,
    context: worker::RouteContext<()>,
) -> worker::Result<worker::Response> {
    let issuer = enrollment::issuer(&context)?;
    let endpoint = format!("{issuer}/session/check");
    let db = context.env.d1("DB")?;
    let runtime = WorkerRuntimePolicy::from_db(&db).await?;
    let body = read_bounded_body(&mut request, runtime.form_body_bytes).await?;
    if mikaki_webauthn::strict_json(&body, runtime.form_body_bytes, 8).is_err() {
        return reject(400);
    }
    let Ok(input) = serde_json::from_str::<Input>(&body) else {
        return reject(400);
    };
    if input.client_assertion_type != ASSERTION_TYPE
        || input.sid.is_empty()
        || input.sid.len() > 128
        || input.client_id.is_empty()
        || input.client_id.len() > 128
    {
        return reject(400);
    }
    let now = now_seconds().ok_or_else(|| worker::Error::RustError("server_error".into()))?;
    let mut random = WorkersCryptoRandom;
    match verify_and_accept_client_assertion(
        &db,
        &input.client_id,
        &input.client_assertion,
        &endpoint,
        &endpoint,
        now,
        &runtime,
        &mut random,
    )
    .await
    {
        Ok(_) => {}
        Err(worker::Error::RustError(message)) if message == "invalid_client" => {
            return reject(401);
        }
        Err(error) => return Err(error),
    }
    let policy = db
        .prepare("SELECT lease_ttl_seconds,app_idle_timeout_seconds,revision FROM session_validation_policy WHERE id=1")
        .first::<Policy>(None)
        .await?
        .ok_or_else(|| worker::Error::RustError("session validation policy unavailable".into()))?;
    let row = db
        .prepare(
            "SELECT v.sub,sx.auth_time,v.expires_at FROM valid_client_session v \
         JOIN client_session cs ON cs.client_id=v.client_id AND cs.sid=v.sid \
         JOIN sso_context sx ON sx.sso_id=cs.sso_id \
         WHERE v.client_id=?1 AND v.sid=?2",
        )
        .bind(&[
            JsValue::from_str(&input.client_id),
            JsValue::from_str(&input.sid),
        ])?
        .first::<Session>(None)
        .await?;
    let response = worker::Response::builder().with_header("Cache-Control", "no-store")?;
    if let Some(row) = row {
        response.from_json(&Active {
            active: true,
            sub: &row.sub,
            auth_time: row.auth_time,
            expires_at: row.expires_at,
            lease_ttl: policy.lease_ttl_seconds,
            app_idle_timeout: policy.app_idle_timeout_seconds,
            policy_revision: runtime.policy_revision(),
            session_policy_revision: policy.revision,
        })
    } else {
        response.from_json(&Inactive { active: false })
    }
}
