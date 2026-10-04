//! Bounded candidate collection for Owner Vault record objects.

use serde::Deserialize;
use wasm_bindgen::JsValue;
use worker::{Env, Result};

#[derive(Deserialize)]
struct CursorRow {
    cursor: Option<String>,
}

#[derive(Deserialize)]
struct Candidate {
    object_key: String,
}

#[derive(Deserialize, serde::Serialize)]
struct Backlog {
    pending: i64,
    oldest_eligible_at: Option<i64>,
}

pub async fn run(env: &Env, scheduled_ms: u64) -> Result<()> {
    let bucket = env.bucket("VAULT_BLOBS")?;
    let db = env.d1("DB")?;
    let now = scheduled_ms / 1000;
    let started = js_sys::Date::now();
    // A sweep is a fallback, not the collection throughput limit. New uploads
    // and retired heads have durable candidates even if no sweep reaches them.
    let previous = db
        .prepare("SELECT cursor FROM vault_owner_record_gc_cursor WHERE id=1")
        .first::<CursorRow>(None)
        .await?
        .ok_or_else(|| worker::Error::RustError("vault_owner_record_gc_cursor_missing".into()))?;
    let mut listing = bucket.list().prefix("vault-owner-record/").limit(128);
    if let Some(cursor) = previous.cursor {
        listing = listing.cursor(cursor);
    }
    let page = listing.execute().await?;
    let cutoff = scheduled_ms.saturating_sub(86_400_000);
    let mut discovered = Vec::new();
    for object in page.objects() {
        if object.uploaded().as_millis() >= cutoff {
            continue;
        }
        discovered.push(db.prepare("INSERT OR IGNORE INTO vault_gc_candidate(object_key,eligible_at) SELECT ?1,?2 WHERE NOT EXISTS(SELECT 1 FROM vault_owner_record_head WHERE object_key=?1 AND deleted=0)")
            .bind(&[JsValue::from_str(&object.key()),JsValue::from_f64((object.uploaded().as_millis()/1000+86400) as f64)])?);
    }
    if !discovered.is_empty() {
        db.batch(discovered).await?;
    }
    db.prepare("UPDATE vault_owner_record_gc_cursor SET cursor=?1 WHERE id=1")
        .bind(&[page
            .cursor()
            .as_deref()
            .map_or(JsValue::NULL, JsValue::from_str)])?
        .run()
        .await?;
    let mut collected = 0;
    for _ in 0..4 {
        if js_sys::Date::now() - started >= 20_000.0 {
            break;
        }
        // This transaction serializes with head updates. The write path checks
        // pending state before installing a head; triggers also reject deleting keys.
        let candidates = db.prepare("UPDATE vault_gc_candidate SET state='deleting' WHERE object_key IN (SELECT object_key FROM vault_gc_candidate WHERE eligible_at<=?1 AND NOT EXISTS(SELECT 1 FROM vault_owner_record_head h WHERE h.object_key=vault_gc_candidate.object_key AND h.deleted=0) ORDER BY eligible_at,object_key LIMIT 256) RETURNING object_key")
            .bind(&[JsValue::from_f64(now as f64)])?.all().await?.results::<Candidate>()?;
        if candidates.is_empty() {
            break;
        }
        let keys: Vec<String> = candidates.into_iter().map(|row| row.object_key).collect();
        // A failure leaves deleting candidates for the next invocation. R2
        // deletion is idempotent, including a crash between R2 and D1 cleanup.
        if let Err(error) = bucket.delete_multiple(keys.clone()).await {
            worker::console_error!(
                "{{\"event\":\"vault_gc_failure\",\"candidates\":{}}}",
                keys.len()
            );
            return Err(error);
        }
        let removals = keys
            .iter()
            .map(|key| {
                db.prepare(
                    "DELETE FROM vault_gc_candidate WHERE object_key=?1 AND state='deleting'",
                )
                .bind(&[JsValue::from_str(key)])
            })
            .collect::<Result<Vec<_>>>()?;
        db.batch(removals).await?;
        collected += keys.len();
    }
    let backlog = db.prepare("SELECT count(*) AS pending,min(eligible_at) AS oldest_eligible_at FROM vault_gc_candidate")
        .first::<Backlog>(None).await?;
    worker::console_log!(
        "{}",
        serde_json::json!({"event":"vault_gc", "collected":collected, "backlog":backlog, "duration_ms":js_sys::Date::now()-started})
    );
    let retention = now.saturating_sub(90 * 86400);
    db.prepare("DELETE FROM vault_owner_record_mutation WHERE rowid IN (SELECT rowid FROM vault_owner_record_mutation WHERE created_at<?1 LIMIT 1000)")
        .bind(&[JsValue::from_f64(retention as f64)])?.run().await?;
    let registration_retention = now.saturating_sub(86400);
    db.prepare("DELETE FROM owner_passkey_registration WHERE transaction_id IN (SELECT transaction_id FROM owner_passkey_registration WHERE expires_at<?1 LIMIT 1000)")
        .bind(&[JsValue::from_f64(registration_retention as f64)])?.run().await?;
    Ok(())
}
