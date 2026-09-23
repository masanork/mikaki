//! Daily R2 cleanup. Only unreferenced blobs older than one day are removed.

use serde::Deserialize;
use wasm_bindgen::JsValue;
use worker::{Env, Result};

#[derive(Deserialize)]
struct CursorRow {
    cursor: Option<String>,
}

pub async fn run(env: &Env, scheduled_ms: u64) -> Result<()> {
    let bucket = env.bucket("VAULT_BLOBS")?;
    let db = env.d1("DB")?;
    let previous = db
        .prepare("SELECT cursor FROM vault_gc_cursor WHERE id=1")
        .first::<CursorRow>(None)
        .await?
        .ok_or_else(|| worker::Error::RustError("vault_gc_cursor_missing".into()))?;
    let mut listing = bucket.list().prefix("vault-attribute/").limit(256);
    if let Some(cursor) = previous.cursor {
        listing = listing.cursor(cursor);
    }
    let page = listing.execute().await?;
    let cutoff = scheduled_ms.saturating_sub(24 * 60 * 60 * 1000);
    for object in page.objects() {
        if object.uploaded().as_millis() >= cutoff {
            continue;
        }
        let key = object.key();
        let referenced = db
            .prepare("SELECT 1 AS referenced FROM vault_attribute_head WHERE object_key=?1 AND deleted=0")
            .bind(&[JsValue::from_str(&key)])?
            .first::<serde_json::Value>(None)
            .await?;
        if referenced.is_none() {
            bucket.delete(&key).await?;
        }
    }
    let cursor = page.cursor();
    let value = cursor.as_deref().map_or(JsValue::NULL, JsValue::from_str);
    db.prepare("UPDATE vault_gc_cursor SET cursor=?1 WHERE id=1")
        .bind(&[value])?
        .run()
        .await?;
    let retention = (scheduled_ms / 1000).saturating_sub(90 * 24 * 60 * 60);
    db.prepare("DELETE FROM vault_attribute_mutation WHERE rowid IN (SELECT rowid FROM vault_attribute_mutation WHERE created_at<?1 LIMIT 1000)")
        .bind(&[JsValue::from_f64(retention as f64)])?
        .run()
        .await?;
    Ok(())
}
