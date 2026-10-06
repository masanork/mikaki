//! Bounded, leased Back-Channel Logout delivery. The signed token is rebuilt
//! from the immutable outbox snapshot on each retry; its jti stays stable.

use super::*;
use wasm_bindgen::JsValue;

const BATCH_SIZE: usize = 2;
const FETCH_TIMEOUT_MS: u32 = 5000;
const LEASE_SECONDS: u64 = 20;
const GLOBAL_CONCURRENCY: u32 = 2;

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

#[derive(Serialize)]
struct QueueWakeup {
    version: u8,
    event_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct QueueWakeupBody {
    version: u8,
    event_id: String,
}

#[derive(Deserialize)]
struct BacklogStats {
    pending: u64,
    due: u64,
    leased: u64,
    retry: u64,
    oldest_pending_at: Option<u64>,
    oldest_due_at: Option<u64>,
    earliest_deadline: Option<u64>,
    attempts_total: u64,
    failed: u64,
    expired: u64,
}

#[derive(Default)]
struct RunSummary {
    claimed: usize,
    more_due: bool,
}

async fn log_backlog(env: &worker::Env) {
    let result = async {
        let now = now_seconds().ok_or_else(|| worker::Error::RustError("server_error".into()))?;
        env.d1("DB")?
            .prepare(
                "SELECT \
                   COALESCE(SUM(CASE WHEN d.state='pending' THEN 1 ELSE 0 END),0) AS pending, \
                   COALESCE(SUM(CASE WHEN d.state='pending' AND d.next_at<=?1 AND e.deadline>?1 THEN 1 ELSE 0 END),0) AS due, \
                   COALESCE(SUM(CASE WHEN d.state='leased' AND d.lease_until>?1 AND e.deadline>?1 THEN 1 ELSE 0 END),0) AS leased, \
                   COALESCE(SUM(CASE WHEN d.state='pending' AND d.next_at>?1 AND e.deadline>?1 THEN 1 ELSE 0 END),0) AS retry, \
                   MIN(CASE WHEN d.state IN ('pending','leased') AND e.deadline>?1 THEN e.created_at END) AS oldest_pending_at, \
                   MIN(CASE WHEN d.state IN ('pending','leased') AND d.next_at<=?1 AND e.deadline>?1 THEN d.next_at END) AS oldest_due_at, \
                   MIN(CASE WHEN d.state IN ('pending','leased') AND e.deadline>?1 THEN e.deadline END) AS earliest_deadline, \
                   COALESCE(SUM(d.attempts),0) AS attempts_total, \
                   COALESCE(SUM(CASE WHEN d.state='failed' THEN 1 ELSE 0 END),0) AS failed, \
                   COALESCE(SUM(CASE WHEN d.state='expired' THEN 1 ELSE 0 END),0) AS expired \
                 FROM logout_delivery d JOIN sso_logout_event e ON e.event_id=d.event_id",
            )
            .bind(&[JsValue::from_f64(now as f64)])?
            .first::<BacklogStats>(None)
            .await?
            .ok_or_else(|| worker::Error::RustError("logout backlog unavailable".into()))
    }
    .await;
    match result {
        Ok(stats) => worker::console_log!(
            "{}",
            serde_json::json!({
                "event": "logout_delivery_backlog",
                "pending": stats.pending,
                "due": stats.due,
                "leased": stats.leased,
                "retry": stats.retry,
                "oldest_pending_at": stats.oldest_pending_at,
                "oldest_due_at": stats.oldest_due_at,
                "earliest_deadline": stats.earliest_deadline,
                "attempts_total": stats.attempts_total,
                "failed": stats.failed,
                "expired": stats.expired,
            })
        ),
        Err(_) => worker::console_error!("{{\"event\":\"logout_backlog_metrics_failure\"}}"),
    }
}

pub async fn enqueue_wakeup(env: &worker::Env, event_id: String) -> worker::Result<()> {
    env.queue("LOGOUT_QUEUE")?
        .send(QueueWakeup {
            version: 1,
            event_id,
        })
        .await
}

#[worker::event(queue)]
pub async fn queue_consumer(
    batch: worker::MessageBatch<JsValue>,
    env: worker::Env,
    _context: worker::Context,
) -> worker::Result<()> {
    use worker::MessageExt;

    for message in batch.raw_iter() {
        let parsed = js_sys::JSON::stringify(&message.body())
            .ok()
            .and_then(|value| value.as_string())
            .and_then(|json| serde_json::from_str::<QueueWakeupBody>(&json).ok());
        let Some(wakeup) = parsed
            .filter(|wakeup| wakeup.version == 1 && passkey_login::valid_tx(&wakeup.event_id))
        else {
            worker::console_error!("{{\"event\":\"logout_queue_invalid_message\"}}");
            message.ack();
            continue;
        };

        let summary = match run_event(&env, &wakeup.event_id).await {
            Ok(summary) => summary,
            Err(_) => {
                worker::console_error!("{{\"event\":\"logout_queue_consumer_failure\"}}");
                message.retry();
                continue;
            }
        };
        if summary.claimed > 0
            && summary.more_due
            && enqueue_wakeup(&env, wakeup.event_id).await.is_err()
        {
            // The durable outbox remains authoritative; cron is the fallback.
            worker::console_error!("{{\"event\":\"logout_queue_continuation_failure\"}}");
        }
        message.ack();
    }
    log_backlog(&env).await;
    Ok(())
}

pub async fn run_due(env: &worker::Env) -> worker::Result<()> {
    // Bound a scheduled pass while draining fair pages. Queue wake-ups provide
    // prompt continuation; cron remains a bounded recovery path.
    for _ in 0..8 {
        let summary = run(env, None).await?;
        if summary.claimed == 0 || !summary.more_due {
            break;
        }
    }
    log_backlog(env).await;
    Ok(())
}

async fn run_event(env: &worker::Env, event_id: &str) -> worker::Result<RunSummary> {
    run(env, Some(event_id)).await
}

async fn run(env: &worker::Env, event_id: Option<&str>) -> worker::Result<RunSummary> {
    let db = env.d1("DB")?;
    let expiration_now =
        now_seconds().ok_or_else(|| worker::Error::RustError("server_error".into()))?;
    let (expire_query, expire_bindings) = if let Some(event_id) = event_id {
        (
            "UPDATE logout_delivery SET state='expired',lease_id=NULL,lease_until=NULL,finished_at=?1 \
             WHERE state IN ('pending','leased') AND event_id=?2 \
               AND EXISTS (SELECT 1 FROM sso_logout_event WHERE event_id=?2 AND deadline<=?1)",
            vec![
                JsValue::from_f64(expiration_now as f64),
                JsValue::from_str(event_id),
            ],
        )
    } else {
        (
            "UPDATE logout_delivery SET state='expired',lease_id=NULL,lease_until=NULL,finished_at=?1 \
             WHERE state IN ('pending','leased') AND event_id IN \
               (SELECT event_id FROM sso_logout_event WHERE deadline<=?1)",
            vec![JsValue::from_f64(expiration_now as f64)],
        )
    };
    db.prepare(expire_query)
        .bind(&expire_bindings)?
        .run()
        .await?;
    let now = now_seconds().ok_or_else(|| worker::Error::RustError("server_error".into()))?;
    // One oldest due row per eligible RP, ordered by an attempt-history proxy.
    // `next_at` advances when a previous attempt settles, so an RP with a long
    // backlog yields to clients that have not had a turn yet. CTEs aggregate
    // history once per page instead of running a correlated history scan per row.
    let query = if event_id.is_some() {
        "WITH busy_clients AS ( \
           SELECT DISTINCT client_id FROM logout_delivery \
           WHERE state='leased' AND lease_until>?1 \
         ), client_history AS ( \
           SELECT client_id,MAX(next_at) AS last_attempt_at FROM logout_delivery \
           WHERE attempts>0 GROUP BY client_id \
         ), candidates AS ( \
           SELECT d.event_id,d.client_id,d.sid,d.sub,d.logout_uri,d.attempts,e.deadline,d.next_at, \
             ROW_NUMBER() OVER (PARTITION BY d.client_id ORDER BY d.next_at,d.event_id,d.sid) AS client_rank \
           FROM logout_delivery d JOIN sso_logout_event e ON e.event_id=d.event_id \
           LEFT JOIN busy_clients busy ON busy.client_id=d.client_id \
           WHERE d.event_id=?2 AND e.deadline>?1 AND d.next_at<=?1 \
             AND (d.state='pending' OR (d.state='leased' AND d.lease_until<=?1)) \
             AND busy.client_id IS NULL \
         ) \
         SELECT c.event_id,c.client_id,c.sid,c.sub,c.logout_uri,c.attempts,c.deadline \
         FROM candidates c LEFT JOIN client_history h ON h.client_id=c.client_id \
         WHERE c.client_rank=1 \
         ORDER BY COALESCE(h.last_attempt_at,0),c.next_at,c.event_id,c.client_id,c.sid LIMIT 2"
    } else {
        "WITH busy_clients AS ( \
           SELECT DISTINCT client_id FROM logout_delivery \
           WHERE state='leased' AND lease_until>?1 \
         ), client_history AS ( \
           SELECT client_id,MAX(next_at) AS last_attempt_at FROM logout_delivery \
           WHERE attempts>0 GROUP BY client_id \
         ), candidates AS ( \
           SELECT d.event_id,d.client_id,d.sid,d.sub,d.logout_uri,d.attempts,e.deadline,d.next_at, \
             ROW_NUMBER() OVER (PARTITION BY d.client_id ORDER BY d.next_at,d.event_id,d.sid) AS client_rank \
           FROM logout_delivery d JOIN sso_logout_event e ON e.event_id=d.event_id \
           LEFT JOIN busy_clients busy ON busy.client_id=d.client_id \
           WHERE e.deadline>?1 AND d.next_at<=?1 \
             AND (d.state='pending' OR (d.state='leased' AND d.lease_until<=?1)) \
             AND busy.client_id IS NULL \
         ) \
         SELECT c.event_id,c.client_id,c.sid,c.sub,c.logout_uri,c.attempts,c.deadline \
         FROM candidates c LEFT JOIN client_history h ON h.client_id=c.client_id \
         WHERE c.client_rank=1 \
         ORDER BY COALESCE(h.last_attempt_at,0),c.next_at,c.event_id,c.client_id,c.sid LIMIT 2"
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
        return Ok(RunSummary::default());
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
    let mut claimed_rows = Vec::with_capacity(BATCH_SIZE);
    for row in rows.into_iter().take(BATCH_SIZE) {
        let claim_now =
            now_seconds().ok_or_else(|| worker::Error::RustError("server_error".into()))?;
        let lease_id = passkey_login::random_secret(&mut random)?;
        let claimed = db
            .prepare(
                "UPDATE logout_delivery SET state='leased',lease_id=?5,lease_until=?6, \
                 attempts=attempts+1 WHERE event_id=?1 AND client_id=?2 AND sid=?3 \
                 AND next_at<=?4 AND (state='pending' OR (state='leased' AND lease_until<=?4)) \
                 AND EXISTS (SELECT 1 FROM sso_logout_event e WHERE e.event_id=?1 AND e.deadline>?4) \
                 AND (SELECT COUNT(*) FROM logout_delivery active \
                   WHERE active.state='leased' AND active.lease_until>?4)<?7 \
                 AND (SELECT COUNT(*) FROM logout_delivery active \
                   WHERE active.client_id=?2 AND active.state='leased' AND active.lease_until>?4)<1",
            )
            .bind(&[
                JsValue::from_str(&row.event_id),
                JsValue::from_str(&row.client_id),
                JsValue::from_str(&row.sid),
                JsValue::from_f64(claim_now as f64),
                JsValue::from_str(&lease_id),
                JsValue::from_f64((claim_now + LEASE_SECONDS) as f64),
                JsValue::from_f64(GLOBAL_CONCURRENCY as f64),
            ])?
            .run()
            .await?
            .meta()?
            .and_then(|meta| meta.changes)
            .unwrap_or(0);
        if claimed != 1 {
            continue;
        }
        claimed_rows.push((row, lease_id));
    }
    let claimed = claimed_rows.len();
    futures_util::future::join_all(
        claimed_rows
            .into_iter()
            .map(|(row, lease_id)| deliver_claimed(env, &signer, &issuer, row, lease_id)),
    )
    .await
    .into_iter()
    .collect::<worker::Result<Vec<_>>>()?;
    let mut summary = RunSummary {
        claimed,
        more_due: false,
    };
    summary.more_due = has_due(env, event_id).await?;
    Ok(summary)
}

async fn deliver_claimed(
    env: &worker::Env,
    signer: &WorkerTokenSigner,
    issuer: &str,
    row: DeliveryRow,
    lease_id: String,
) -> worker::Result<()> {
    let sent_at = now_seconds().ok_or_else(|| worker::Error::RustError("server_error".into()))?;
    let status = deliver(signer, issuer, &row, sent_at).await.ok().flatten();
    let delivered = status.is_some_and(|status| (200..300).contains(&status));
    let backoff = 30_u64
        .saturating_mul(1_u64 << row.attempts.min(7))
        .min(3600);
    let settled_at =
        now_seconds().ok_or_else(|| worker::Error::RustError("server_error".into()))?;
    let next_at = settled_at.saturating_add(backoff);
    let next_state = if delivered {
        "delivered"
    } else if next_at >= row.deadline {
        "failed"
    } else {
        "pending"
    };
    let finished_at = (next_state != "pending").then_some(settled_at);
    env.d1("DB")?
        .prepare(
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
    Ok(())
}

async fn has_due(env: &worker::Env, event_id: Option<&str>) -> worker::Result<bool> {
    let db = env.d1("DB")?;
    let now = now_seconds().ok_or_else(|| worker::Error::RustError("server_error".into()))?;
    let query = if event_id.is_some() {
        "SELECT 1 FROM logout_delivery d JOIN sso_logout_event e ON e.event_id=d.event_id \
         WHERE d.event_id=?2 AND e.deadline>?1 AND d.next_at<=?1 \
           AND (d.state='pending' OR (d.state='leased' AND d.lease_until<=?1)) \
           AND NOT EXISTS (SELECT 1 FROM logout_delivery active WHERE active.client_id=d.client_id \
             AND active.state='leased' AND active.lease_until>?1) \
           AND (SELECT COUNT(*) FROM logout_delivery active \
             WHERE active.state='leased' AND active.lease_until>?1)<?3 LIMIT 1"
    } else {
        "SELECT 1 FROM logout_delivery d JOIN sso_logout_event e ON e.event_id=d.event_id \
         WHERE e.deadline>?1 AND d.next_at<=?1 \
           AND (d.state='pending' OR (d.state='leased' AND d.lease_until<=?1)) \
           AND NOT EXISTS (SELECT 1 FROM logout_delivery active WHERE active.client_id=d.client_id \
             AND active.state='leased' AND active.lease_until>?1) \
           AND (SELECT COUNT(*) FROM logout_delivery active \
             WHERE active.state='leased' AND active.lease_until>?1)<?2 LIMIT 1"
    };
    let mut bindings = vec![JsValue::from_f64(now as f64)];
    if let Some(event_id) = event_id {
        bindings.push(JsValue::from_str(event_id));
    }
    bindings.push(JsValue::from_f64(GLOBAL_CONCURRENCY as f64));
    Ok(db
        .prepare(query)
        .bind(&bindings)?
        .first::<serde_json::Value>(None)
        .await?
        .is_some())
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
