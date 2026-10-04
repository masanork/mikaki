//! Bounded owner-only v2 records, including separately authorized approved notes.
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use mikaki_oidc::CryptographicRandom;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use wasm_bindgen::JsValue;
use worker::{D1Database, Request, Response, RouteContext};

use crate::vault_attributes::{
    Owner, error, expected_revision, operation_id, owner, request_hash, same_origin,
};
use crate::{WorkersCryptoRandom, read_bounded_body};

const SUITE: &str = "PRF-HKDF-SHA256-AES256GCM-v2";
const MAX_CIPHERTEXT: usize = 24 * 1024;
const MAX_BODY: usize = 36 * 1024;
const PREFIX: &str = "vault-owner-record/";

#[derive(Clone, Deserialize, PartialEq)]
struct Root {
    vault_id: String,
    origin: String,
    key_generation: i64,
    revision: i64,
    format_version: u8,
    suite: String,
    observed_at: i64,
}
impl Root {
    fn same(&self, other: &Self) -> bool {
        self.vault_id == other.vault_id
            && self.origin == other.origin
            && self.key_generation == other.key_generation
            && self.revision == other.revision
            && self.format_version == other.format_version
            && self.suite == other.suite
    }
    fn supported(&self, origin: &str) -> bool {
        self.format_version == 2
            && self.suite == SUITE
            && self.origin == origin
            && origin.starts_with("https://")
            && identifier(&self.vault_id)
    }
}
#[derive(Deserialize, PartialEq)]
struct Head {
    kind: String,
    revision: i64,
    key_generation: i64,
    format_version: u8,
    object_key: Option<String>,
    ciphertext_sha256: Option<String>,
    key_envelope: Option<String>,
    deleted: i64,
}
#[derive(Deserialize)]
struct Mutation {
    request_hash: String,
    result_revision: i64,
    deleted: i64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeleteBody {
    format_version: u8,
    vault_id: String,
    key_generation: i64,
    owner_key_revision: i64,
    kind: String,
    revision: i64,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PutBody {
    format_version: u8,
    vault_id: String,
    key_generation: i64,
    owner_key_revision: i64,
    kind: String,
    revision: i64,
    ciphertext: String,
    key_envelope: String,
}
#[derive(Deserialize, Serialize)]
struct ListEntry {
    record_id: String,
    kind: String,
    revision: i64,
    key_generation: i64,
    deleted: i64,
}
#[derive(Deserialize)]
struct Limits {
    recent: i64,
    slots: i64,
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
fn target(context: &RouteContext<()>) -> Option<(&str, &str)> {
    let collection = context.param("collection")?.as_str();
    let record = context.param("record")?.as_str();
    (identifier(collection) && identifier(record)).then_some((collection, record))
}
fn decode(value: &str, min: usize, max: usize) -> Option<Vec<u8>> {
    if value.len() > (max * 4).div_ceil(3) {
        return None;
    }
    let bytes = URL_SAFE_NO_PAD.decode(value).ok()?;
    ((min..=max).contains(&bytes.len()) && URL_SAFE_NO_PAD.encode(&bytes) == value).then_some(bytes)
}
fn frame(value: &str, min: usize, max: usize) -> Option<Vec<u8>> {
    decode(value, min, max).filter(|bytes| bytes.first() == Some(&2))
}
async fn authority(db: &D1Database, owner: &Owner) -> worker::Result<Option<Root>> {
    db.prepare(include_str!("../sql/select-owner-record-authority.sql"))
        .bind(&[
            JsValue::from_str(&owner.account_id),
            JsValue::from_str(&owner.secret_hash),
            JsValue::from_str(&owner.credential_id),
        ])?
        .first::<Root>(None)
        .await
}
async fn still_authorized(db: &D1Database, owner: &Owner, root: &Root) -> worker::Result<bool> {
    Ok(authority(db, owner)
        .await?
        .is_some_and(|current| current.same(root)))
}
async fn receipt_authorized(
    db: &D1Database,
    owner: &Owner,
    root: &Root,
    approved: bool,
) -> worker::Result<bool> {
    if approved {
        crate::vault_owner_approved::retry_owner(db, owner).await
    } else {
        still_authorized(db, owner, root).await
    }
}
async fn head(
    db: &D1Database,
    account: &str,
    vault: &str,
    collection: &str,
    record: &str,
) -> worker::Result<Option<Head>> {
    db.prepare("SELECT kind,revision,key_generation,format_version,object_key,ciphertext_sha256,key_envelope,deleted FROM vault_owner_record_head WHERE account_id=?1 AND vault_id=?2 AND collection_id=?3 AND record_id=?4")
        .bind(&[JsValue::from_str(account), JsValue::from_str(vault), JsValue::from_str(collection), JsValue::from_str(record)])?
        .first::<Head>(None).await
}
async fn mutation(
    db: &D1Database,
    account: &str,
    operation: &str,
) -> worker::Result<Option<Mutation>> {
    db.prepare("SELECT request_hash,result_revision,deleted FROM vault_owner_record_mutation WHERE account_id=?1 AND operation_id=?2 AND created_at>=unixepoch()-7776000")
        .bind(&[JsValue::from_str(account), JsValue::from_str(operation)])?.first::<Mutation>(None).await
}
async fn approved_retry(
    db: &D1Database,
    owner: &Owner,
    operation: &str,
    hash: &str,
) -> worker::Result<Option<Response>> {
    let Some(previous) = mutation(db, &owner.account_id, operation).await? else {
        return Ok(None);
    };
    if !crate::vault_owner_approved::retry_owner(db, owner).await? {
        return error(401, "authentication_required").map(Some);
    }
    outcome(previous, hash).map(Some)
}
fn outcome(previous: Mutation, hash: &str) -> worker::Result<Response> {
    if previous.request_hash != hash {
        return error(409, "operation_id_reused");
    }
    Response::builder().with_header("Cache-Control", "no-store")?
        .with_header("ETag", &format!("\"{}\"", previous.result_revision))?
        .from_json(&serde_json::json!({"revision":previous.result_revision,"deleted":previous.deleted != 0}))
}
fn not_found(revision: Option<i64>) -> worker::Result<Response> {
    if let Some(revision) = revision {
        return Response::builder()
            .with_status(404)
            .with_header("Cache-Control", "no-store")?
            .with_header("ETag", &format!("\"{revision}\""))?
            .from_json(&serde_json::json!({"error":"not_found","deleted":true}));
    }
    error(404, "not_found")
}

pub async fn get(request: Request, context: RouteContext<()>) -> worker::Result<Response> {
    let Ok(bucket) = context.env.bucket("VAULT_BLOBS") else {
        return error(404, "not_found");
    };
    let Some((collection, record)) = target(&context) else {
        return error(400, "invalid_record");
    };
    let db = context.env.d1("DB")?;
    let Some(owner) = owner(&request, &db).await? else {
        return error(401, "authentication_required");
    };
    let Some(root) = authority(&db, &owner).await? else {
        return error(409, "owner_key_unavailable");
    };
    if !root.supported(&request.url()?.origin().ascii_serialization()) {
        return error(409, "owner_key_changed");
    }
    let selected = head(&db, &owner.account_id, &root.vault_id, collection, record).await?;
    let Some(selected) = selected else {
        if !still_authorized(&db, &owner, &root).await? {
            return error(409, "owner_key_changed");
        }
        return not_found(None);
    };
    if selected.format_version != 2 || selected.key_generation != root.key_generation {
        return error(409, "owner_key_changed");
    }
    if selected.deleted != 0 {
        if !still_authorized(&db, &owner, &root).await? {
            return error(409, "owner_key_changed");
        }
        return not_found(Some(selected.revision));
    }
    let (Some(object_key), Some(digest), Some(envelope)) = (
        &selected.object_key,
        &selected.ciphertext_sha256,
        &selected.key_envelope,
    ) else {
        return error(503, "storage_unavailable");
    };
    if frame(envelope, 61, 61).is_none() {
        return error(503, "storage_unavailable");
    }
    let Ok(Some(object)) = bucket.get(object_key).execute().await else {
        return error(503, "storage_unavailable");
    };
    if object.size() > MAX_CIPHERTEXT as u64 {
        return error(503, "storage_unavailable");
    }
    let Some(body) = object.body() else {
        return error(503, "storage_unavailable");
    };
    let Ok(bytes) = body.bytes().await else {
        return error(503, "storage_unavailable");
    };
    if !(29..=MAX_CIPHERTEXT).contains(&bytes.len())
        || bytes.first() != Some(&2)
        || URL_SAFE_NO_PAD.encode(Sha256::digest(&bytes)) != *digest
    {
        return error(503, "storage_unavailable");
    }
    // Check after the entire body read, not just R2.get's first await.
    if head(&db, &owner.account_id, &root.vault_id, collection, record)
        .await?
        .as_ref()
        != Some(&selected)
        || !still_authorized(&db, &owner, &root).await?
    {
        return error(409, "record_changed");
    }
    Response::builder().with_header("Cache-Control","no-store")?
        .with_header("ETag", &format!("\"{}\"",selected.revision))?
        .from_json(&serde_json::json!({
            "format_version":2,"owner_id":owner.account_id,"origin":root.origin,"vault_id":root.vault_id,
            "key_generation":root.key_generation,"owner_key_revision":root.revision,"collection_id":collection,"record_id":record,
            "kind":selected.kind,"revision":selected.revision,"ciphertext":URL_SAFE_NO_PAD.encode(bytes),"key_envelope":envelope
        }))
}

pub async fn list(request: Request, context: RouteContext<()>) -> worker::Result<Response> {
    if context.env.bucket("VAULT_BLOBS").is_err() {
        return error(404, "not_found");
    }
    let Some(collection) = context.param("collection").filter(|id| identifier(id)) else {
        return error(400, "invalid_record");
    };
    let mut after = None;
    let mut limit = None;
    for (key, value) in request.url()?.query_pairs() {
        match key.as_ref() {
            "after" if after.is_none() && identifier(&value) => after = Some(value.into_owned()),
            "limit" if limit.is_none() => {
                let Ok(parsed) = value.parse::<u8>() else {
                    return error(400, "invalid_query");
                };
                if !(1..=50).contains(&parsed) || parsed.to_string() != value {
                    return error(400, "invalid_query");
                }
                limit = Some(parsed);
            }
            _ => return error(400, "invalid_query"),
        }
    }
    let limit = limit.unwrap_or(50) as usize;
    let db = context.env.d1("DB")?;
    let Some(owner) = owner(&request, &db).await? else {
        return error(401, "authentication_required");
    };
    let Some(root) = authority(&db, &owner).await? else {
        return error(409, "owner_key_unavailable");
    };
    if !root.supported(&request.url()?.origin().ascii_serialization()) {
        return error(409, "owner_key_changed");
    }
    let mut records = db.prepare("SELECT record_id,kind,revision,key_generation,deleted FROM vault_owner_record_head WHERE account_id=?1 AND vault_id=?2 AND collection_id=?3 AND record_id>?4 ORDER BY record_id LIMIT ?5")
        .bind(&[JsValue::from_str(&owner.account_id),JsValue::from_str(&root.vault_id),JsValue::from_str(collection),JsValue::from_str(after.as_deref().unwrap_or("")),JsValue::from_f64((limit+1) as f64)])?
        .all().await?.results::<ListEntry>()?;
    if records
        .iter()
        .any(|record| record.key_generation != root.key_generation)
        || !still_authorized(&db, &owner, &root).await?
    {
        return error(409, "owner_key_changed");
    }
    let next_cursor = if records.len() > limit {
        records.truncate(limit);
        records.last().map(|item| item.record_id.clone())
    } else {
        None
    };
    Response::builder().with_header("Cache-Control","no-store")?.from_json(&serde_json::json!({
        "format_version":2,"owner_id":owner.account_id,"origin":root.origin,"vault_id":root.vault_id,"key_generation":root.key_generation,
        "owner_key_revision":root.revision,"collection_id":collection,"records":records.iter().map(|item| serde_json::json!({"record_id":item.record_id,"kind":item.kind,"revision":item.revision,"key_generation":item.key_generation,"deleted":item.deleted != 0})).collect::<Vec<_>>(),"next_cursor":next_cursor
    }))
}

pub async fn put(mut request: Request, context: RouteContext<()>) -> worker::Result<Response> {
    write(&mut request, &context, false, false).await
}
pub async fn delete(mut request: Request, context: RouteContext<()>) -> worker::Result<Response> {
    write(&mut request, &context, true, false).await
}

pub async fn approved(mut request: Request, context: RouteContext<()>) -> worker::Result<Response> {
    write(&mut request, &context, false, true).await
}

async fn write(
    request: &mut Request,
    context: &RouteContext<()>,
    deleted: bool,
    approved: bool,
) -> worker::Result<Response> {
    let Ok(bucket) = context.env.bucket("VAULT_BLOBS") else {
        return error(404, "not_found");
    };
    let Some((collection, record)) = target(context) else {
        return error(400, "invalid_record");
    };
    let approval = if approved {
        if collection != "personal" || record != "owner_note" {
            return error(400, "invalid_approved_target");
        }
        let Some(approval) = crate::vault_approved::Approval::read(request)? else {
            return error(400, "approval_required");
        };
        if decode(&approval.proposal_id, 32, 32).is_none()
            || decode(&approval.request_hash, 32, 32).is_none()
        {
            return error(400, "approval_required");
        }
        Some(approval)
    } else {
        None
    };
    if !same_origin(request)? {
        return error(403, "origin_required");
    }
    let Some(expected) = expected_revision(request)? else {
        return error(428, "precondition_required");
    };
    if (deleted && expected == -1)
        || (expected > 0
            && request.headers().get("If-Match")?.as_deref()
                != Some(format!("\"{expected}\"").as_str()))
    {
        return error(428, "precondition_required");
    }
    let Some(operation) = operation_id(request)?.filter(|id| decode(id, 32, 32).is_some()) else {
        return error(400, "operation_id_required");
    };
    let db = context.env.d1("DB")?;
    let Some(owner) = owner(request, &db).await? else {
        return error(401, "authentication_required");
    };
    if request.headers().get("Content-Type")?.as_deref() != Some("application/json") {
        return error(415, "json_required");
    }
    let body = match read_bounded_body(request, if deleted { 1024 } else { MAX_BODY }).await {
        Ok(body) => body,
        Err(_) => return error(413, "body_too_large_or_invalid"),
    };
    let (value, ciphertext, envelope) = if deleted {
        let Ok(value) = serde_json::from_str::<DeleteBody>(&body) else {
            return error(400, "invalid_body");
        };
        (value, None, None)
    } else {
        let Ok(value) = serde_json::from_str::<PutBody>(&body) else {
            return error(400, "invalid_body");
        };
        // The verified preparation pins this strict field order and exact bytes.
        if approved && serde_json::to_string(&value).ok().as_deref() != Some(&body) {
            return error(400, "invalid_candidate_encoding");
        }
        let (Some(ciphertext), Some(_)) = (
            frame(&value.ciphertext, 29, MAX_CIPHERTEXT),
            frame(&value.key_envelope, 61, 61),
        ) else {
            return error(400, "invalid_body");
        };
        (
            DeleteBody {
                format_version: value.format_version,
                vault_id: value.vault_id,
                key_generation: value.key_generation,
                owner_key_revision: value.owner_key_revision,
                kind: value.kind,
                revision: value.revision,
            },
            Some(ciphertext),
            Some(value.key_envelope),
        )
    };
    let revision = if expected == -1 { 1 } else { expected + 1 };
    if value.format_version != 2
        || !identifier(&value.vault_id)
        || !identifier(&value.kind)
        || !(1..=9_007_199_254_740_991).contains(&value.key_generation)
        || !(1..=9_007_199_254_740_991).contains(&value.owner_key_revision)
        || value.revision != revision
        || (approved && value.kind != "owner_note")
    {
        return error(400, "invalid_record");
    }
    let origin = request.url()?.origin().ascii_serialization();
    let method = approval
        .as_ref()
        .map(|value| format!("V2-APPROVED/{}/{}", value.proposal_id, value.request_hash));
    let hash = request_hash(
        method
            .as_deref()
            .unwrap_or(if deleted { "V2-DELETE" } else { "V2-PUT" }),
        &format!("{collection}/{record}"),
        expected,
        body.as_bytes(),
    );
    // Approved retries are historical acknowledgments independent of retained
    // proposal metadata and current grant/root authority. Only a live same-owner
    // session and the exact mutation identity can observe the original outcome.
    if approved && let Some(response) = approved_retry(&db, &owner, &operation, &hash).await? {
        return Ok(response);
    }
    let selected_root = authority(&db, &owner).await?;
    // A matching commit may finish while authority is being read. Reconcile its
    // receipt before rejecting a now-replaced root or removed credential wrap.
    if approved && let Some(response) = approved_retry(&db, &owner, &operation, &hash).await? {
        return Ok(response);
    }
    let Some(root) = selected_root else {
        return error(409, "owner_key_unavailable");
    };
    if !root.supported(&origin) || root.vault_id != value.vault_id {
        return error(409, "owner_key_changed");
    }
    // Historical acknowledgment only; old context/body can never be reapplied.
    if let Some(previous) = mutation(&db, &owner.account_id, &operation).await? {
        if !receipt_authorized(&db, &owner, &root, approved).await? {
            return error(409, "owner_key_changed");
        }
        return outcome(previous, &hash);
    }
    if root.key_generation != value.key_generation || root.revision != value.owner_key_revision {
        return error(409, "owner_key_changed");
    }
    let current = head(&db, &owner.account_id, &root.vault_id, collection, record).await?;
    if deleted && current.as_ref().is_some_and(|head| head.deleted != 0) {
        if let Some(previous) = mutation(&db, &owner.account_id, &operation).await? {
            if !receipt_authorized(&db, &owner, &root, approved).await? {
                return error(409, "owner_key_changed");
            }
            return outcome(previous, &hash);
        }
        return error(409, "record_deleted");
    }
    if (expected == -1 && current.is_some())
        || (expected > 0
            && current.as_ref().is_none_or(|head| {
                head.revision != expected
                    || head.kind != value.kind
                    || head.key_generation != root.key_generation
            }))
    {
        // A concurrent matching request may have committed while this request was reading.
        if let Some(previous) = mutation(&db, &owner.account_id, &operation).await? {
            if !receipt_authorized(&db, &owner, &root, approved).await? {
                return error(409, "owner_key_changed");
            }
            return outcome(previous, &hash);
        }
        return error(409, "revision_conflict");
    }
    let candidate_hash = URL_SAFE_NO_PAD.encode(Sha256::digest(body.as_bytes()));
    let commit = approval
        .as_ref()
        .map(|approval| crate::vault_owner_approved::Commit {
            approval,
            account: &owner.account_id,
            session_hash: &owner.secret_hash,
            credential: &owner.credential_id,
            operation: &operation,
            candidate_hash: &candidate_hash,
            candidate: &body,
            origin: &origin,
            vault: &root.vault_id,
            key_generation: root.key_generation,
            owner_key_revision: root.revision,
            base_revision: if expected == -1 { 0 } else { expected },
            result_revision: revision,
            mutation_hash: &hash,
        });
    if let Some(commit) = &commit
        && !commit.ready(&db).await?
    {
        if let Some(previous) = mutation(&db, &owner.account_id, &operation).await? {
            if !receipt_authorized(&db, &owner, &root, approved).await? {
                return error(409, "owner_key_changed");
            }
            return outcome(previous, &hash);
        }
        return error(409, "approval_unavailable");
    }
    let limits = db.prepare("SELECT (SELECT COUNT(*) FROM vault_owner_record_mutation WHERE account_id=?1 AND created_at>unixepoch()-60) AS recent,(SELECT COUNT(*) FROM vault_owner_record_head WHERE account_id=?1) AS slots")
        .bind(&[JsValue::from_str(&owner.account_id)])?.first::<Limits>(None).await?.ok_or_else(||worker::Error::RustError("record_limits_unavailable".into()))?;
    if limits.recent >= 20 || (expected == -1 && limits.slots >= 256) {
        if let Some(previous) = mutation(&db, &owner.account_id, &operation).await? {
            if !receipt_authorized(&db, &owner, &root, approved).await? {
                return error(409, "owner_key_changed");
            }
            return outcome(previous, &hash);
        }
        return if limits.recent >= 20 {
            error(429, "write_rate_exceeded")
        } else {
            error(409, "record_limit_exceeded")
        };
    }
    let (object_key, digest) = if let Some(ciphertext) = ciphertext {
        let digest = URL_SAFE_NO_PAD.encode(Sha256::digest(&ciphertext));
        let mut random = [0; 32];
        WorkersCryptoRandom
            .fill(&mut random)
            .map_err(|_| worker::Error::RustError("server_error".into()))?;
        let key = format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(random));
        db.prepare(
            "INSERT INTO vault_gc_candidate(object_key,eligible_at) VALUES(?1,unixepoch()+86400)",
        )
        .bind(&[JsValue::from_str(&key)])?
        .run()
        .await?;
        // Even an accidental random-key collision must never replace stored bytes.
        if !matches!(
            bucket
                .put(&key, ciphertext)
                .only_if(worker::Conditional {
                    etag_does_not_match: Some("*".into()),
                    ..Default::default()
                })
                .execute()
                .await,
            Ok(Some(_))
        ) {
            return error(503, "storage_unavailable");
        }
        (Some(key), Some(digest))
    } else {
        (None, None)
    };
    let statement = db
        .prepare(include_str!("../sql/commit-owner-record-head.sql"))
        .bind(&[
            JsValue::from_str(&owner.account_id),
            JsValue::from_str(&root.vault_id),
            JsValue::from_str(collection),
            JsValue::from_str(record),
            JsValue::from_str(&value.kind),
            JsValue::from_f64(revision as f64),
            JsValue::from_f64(root.key_generation as f64),
            object_key
                .as_deref()
                .map_or(JsValue::NULL, JsValue::from_str),
            digest.as_deref().map_or(JsValue::NULL, JsValue::from_str),
            envelope.as_deref().map_or(JsValue::NULL, JsValue::from_str),
            JsValue::from_f64(i64::from(deleted) as f64),
            JsValue::from_f64(expected as f64),
            JsValue::from_str(&owner.secret_hash),
            JsValue::from_str(&owner.credential_id),
            JsValue::from_f64(root.revision as f64),
            JsValue::from_str(&origin),
            JsValue::from_str(SUITE),
            JsValue::from_f64(root.observed_at as f64),
            JsValue::from_str(&operation),
        ])?;
    let ledger = db
        .prepare(include_str!("../sql/commit-owner-record-mutation.sql"))
        .bind(&[
            JsValue::from_str(&owner.account_id),
            JsValue::from_str(&operation),
            JsValue::from_str(&hash),
            JsValue::from_f64(revision as f64),
            JsValue::from_f64(i64::from(deleted) as f64),
        ])?;
    let mut statements = Vec::new();
    if let Some(commit) = &commit {
        statements.push(commit.consume(&db)?);
    }
    // Keep head and ledger adjacent: the latter uses changes() from the head.
    statements.extend([statement, ledger]);
    if let Some(commit) = &commit {
        statements.extend(commit.finish(&db)?);
    }
    let committed = db.batch(statements).await;
    let previous = mutation(&db, &owner.account_id, &operation).await?;
    if approved && previous.is_some() {
        if !crate::vault_owner_approved::retry_owner(&db, &owner).await? {
            return error(401, "authentication_required");
        }
    } else if !still_authorized(&db, &owner, &root).await? {
        return error(409, "owner_key_changed");
    }
    if let Some(previous) = previous {
        return outcome(previous, &hash);
    }
    if committed.is_err() {
        return error(503, "storage_unavailable");
    }
    error(409, "revision_conflict")
}

/// One bounded page per existing minute cron. Backlog/abuse qualification is separate.
#[cfg(feature = "worker-entry")]
pub async fn collect(env: &worker::Env, scheduled_ms: u64) -> worker::Result<()> {
    let db = env.d1("DB")?;
    let _ = scheduled_ms;
    // Logical retry expiry uses DB time too; physical cleanup may lag bounded work.
    db.prepare("DELETE FROM vault_owner_record_mutation WHERE rowid IN (SELECT rowid FROM vault_owner_record_mutation WHERE created_at<unixepoch()-7776000 ORDER BY created_at LIMIT 1000)").run().await?;
    Ok(())
}
