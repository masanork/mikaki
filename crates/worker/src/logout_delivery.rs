//! Bounded, leased Back-Channel Logout delivery. The signed token is rebuilt
//! from the immutable outbox snapshot on each retry; its jti stays stable.

use super::*;
use wasm_bindgen::JsValue;

const BATCH_SIZE: usize = 16;
const FETCH_TIMEOUT_MS: u32 = 5000;
const LEASE_SECONDS: u64 = 20;

#[derive(Deserialize)]
struct DeliveryRow {
    event_id: String,
    client_id: String,
    sid: String,
    sub: String,
    logout_uri: String,
    attempts: u32,
    deadline: u64,
}

pub async fn run_due(env: &worker::Env) -> worker::Result<()> {
    run(env, None).await
}

pub async fn run_event(env: &worker::Env, event_id: &str) -> worker::Result<()> {
    run(env, Some(event_id)).await
}

async fn run(env: &worker::Env, event_id: Option<&str>) -> worker::Result<()> {
    let db = env.d1("DB")?;
    let now = now_seconds().ok_or_else(|| worker::Error::RustError("server_error".into()))?;
    db.prepare(
        "UPDATE logout_delivery SET state='expired',lease_id=NULL,lease_until=NULL,finished_at=?1 \
         WHERE state IN ('pending','leased') AND event_id IN \
           (SELECT event_id FROM sso_logout_event WHERE deadline<=?1)",
    )
    .bind(&[JsValue::from_f64(now as f64)])?
    .run()
    .await?;
    let query = if event_id.is_some() {
        "SELECT d.event_id,d.client_id,d.sid,d.sub,d.logout_uri,d.attempts,e.deadline \
         FROM logout_delivery d JOIN sso_logout_event e ON e.event_id=d.event_id \
         WHERE d.event_id=?2 AND e.deadline>?1 AND d.next_at<=?1 \
           AND (d.state='pending' OR (d.state='leased' AND d.lease_until<=?1)) \
         ORDER BY d.next_at LIMIT 16"
    } else {
        "SELECT d.event_id,d.client_id,d.sid,d.sub,d.logout_uri,d.attempts,e.deadline \
         FROM logout_delivery d JOIN sso_logout_event e ON e.event_id=d.event_id \
         WHERE e.deadline>?1 AND d.next_at<=?1 \
           AND (d.state='pending' OR (d.state='leased' AND d.lease_until<=?1)) \
         ORDER BY d.next_at LIMIT 16"
    };
    let mut bindings = vec![JsValue::from_f64(now as f64)];
    if let Some(event_id) = event_id {
        bindings.push(JsValue::from_str(event_id));
    }
    let rows = db
        .prepare(query)
        .bind(&bindings)?
        .all()
        .await?
        .results::<DeliveryRow>()?;
    if rows.is_empty() {
        return Ok(());
    }
    let private_jwk = env.secret("OP_PRIVATE_JWK")?.to_string();
    let signer = WorkerTokenSigner::from_secret(&private_jwk).await?;
    let registered = db
        .prepare("SELECT public_jwk FROM signing_key WHERE kid=?1 AND active=1 AND algorithm=?2")
        .bind(&[
            JsValue::from_str(signer.kid()),
            JsValue::from_str(signer.algorithm()),
        ])?
        .first::<SigningPublicKeyRow>(None)
        .await?;
    if !registered.is_some_and(|row| signer.matches_public_jwk(&row.public_jwk)) {
        return Err(worker::Error::RustError(
            "invalid signing key configuration".into(),
        ));
    }
    let issuer = env.var("MIKAKI_ISSUER")?.to_string();
    let mut random = WorkersCryptoRandom;
    for row in rows.into_iter().take(BATCH_SIZE) {
        let lease_id = passkey_login::random_secret(&mut random)?;
        let claimed = db
            .prepare(
                "UPDATE logout_delivery SET state='leased',lease_id=?5,lease_until=?6, \
                 attempts=attempts+1 WHERE event_id=?1 AND client_id=?2 AND sid=?3 \
                 AND next_at<=?4 AND (state='pending' OR (state='leased' AND lease_until<=?4))",
            )
            .bind(&[
                JsValue::from_str(&row.event_id),
                JsValue::from_str(&row.client_id),
                JsValue::from_str(&row.sid),
                JsValue::from_f64(now as f64),
                JsValue::from_str(&lease_id),
                JsValue::from_f64((now + LEASE_SECONDS) as f64),
            ])?
            .run()
            .await?
            .meta()?
            .and_then(|meta| meta.changes)
            .unwrap_or(0);
        if claimed != 1 {
            continue;
        }
        let status = deliver(&signer, &issuer, &row, now).await.ok().flatten();
        let delivered = status.is_some_and(|status| (200..300).contains(&status));
        let backoff = 30_u64
            .saturating_mul(1_u64 << row.attempts.min(7))
            .min(3600);
        let next_at = now.saturating_add(backoff);
        let next_state = if delivered {
            "delivered"
        } else if next_at >= row.deadline {
            "failed"
        } else {
            "pending"
        };
        let finished_at = (next_state != "pending").then_some(now);
        db.prepare(
            "UPDATE logout_delivery SET state=?5,next_at=?6,lease_id=NULL,lease_until=NULL, \
             last_status=?7,finished_at=?8 WHERE event_id=?1 AND client_id=?2 AND sid=?3 \
             AND lease_id=?4 AND state='leased'",
        )
        .bind(&[
            JsValue::from_str(&row.event_id),
            JsValue::from_str(&row.client_id),
            JsValue::from_str(&row.sid),
            JsValue::from_str(&lease_id),
            JsValue::from_str(next_state),
            JsValue::from_f64(next_at as f64),
            status.map_or(JsValue::NULL, |value| JsValue::from_f64(value as f64)),
            finished_at.map_or(JsValue::NULL, |value| JsValue::from_f64(value as f64)),
        ])?
        .run()
        .await?;
    }
    Ok(())
}

async fn deliver(
    signer: &WorkerTokenSigner,
    issuer: &str,
    row: &DeliveryRow,
    now: u64,
) -> worker::Result<Option<u16>> {
    let uri = url::Url::parse(&row.logout_uri)
        .map_err(|_| worker::Error::RustError("invalid logout destination".into()))?;
    if uri.scheme() != "https"
        || uri.host().is_none()
        || !uri.username().is_empty()
        || uri.password().is_some()
        || uri.fragment().is_some()
    {
        return Err(worker::Error::RustError(
            "invalid logout destination".into(),
        ));
    }
    let jti = passkey_login::hash(&format!("{}:{}:{}", row.event_id, row.client_id, row.sid));
    let token = signer
        .sign_logout_token(
            issuer,
            &row.client_id,
            &row.sub,
            &row.sid,
            &jti,
            now,
            now + 300,
        )
        .await?;
    let mut init = worker::RequestInit::new();
    init.with_method(worker::Method::Post)
        .with_redirect(worker::RequestRedirect::Manual)
        .with_body(Some(JsValue::from_str(
            &url::form_urlencoded::Serializer::new(String::new())
                .append_pair("logout_token", &token)
                .finish(),
        )));
    init.headers
        .set("Content-Type", "application/x-www-form-urlencoded")?;
    let request = worker::Request::new_with_init(uri.as_str(), &init)?;
    let signal =
        worker::AbortSignal::from(web_sys::AbortSignal::timeout_with_u32(FETCH_TIMEOUT_MS));
    let response = worker::Fetch::Request(request)
        .send_with_signal(&signal)
        .await?;
    Ok(Some(response.status_code()))
}
