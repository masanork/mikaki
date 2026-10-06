//! Immutable first-generation bootstrap. Rotation activation is a separate protocol.
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use wasm_bindgen::JsValue;
use worker::{Request, Response, RouteContext};

use crate::vault_http::{error, expected_revision, operation_id, owner, request_hash, same_origin};
use crate::{now_seconds, read_bounded_body};

const SUITE: &str = "PRF-HKDF-SHA256-AES256GCM-v2";
const MAX_BODY: usize = 4096;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    format_version: u8,
    kind: String,
    credential_id: String,
    prf_input: String,
    salt: String,
    nonce: String,
    wrapped_key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Create {
    format_version: u8,
    suite: String,
    vault_id: String,
    key_generation: i64,
    owner_envelope: Envelope,
}

#[derive(Deserialize)]
struct Head {
    vault_id: String,
    origin: String,
    key_generation: i64,
    revision: i64,
    format_version: u8,
    suite: String,
    operation_id: String,
    request_hash: String,
    envelope: Option<String>,
}

#[derive(Serialize)]
struct KeyResponse<'a> {
    format_version: u8,
    suite: &'a str,
    owner_id: &'a str,
    vault_id: &'a str,
    origin: &'a str,
    key_generation: i64,
    revision: i64,
    owner_envelope: Envelope,
}

fn canonical(value: &str, min: usize, max: usize) -> bool {
    if value.len() > (max * 4).div_ceil(3) {
        return false;
    }
    URL_SAFE_NO_PAD.decode(value).is_ok_and(|bytes| {
        (min..=max).contains(&bytes.len()) && URL_SAFE_NO_PAD.encode(bytes) == value
    })
}

impl Create {
    fn valid(&self, credential: &str) -> bool {
        self.format_version == 2
            && self.suite == SUITE
            && self.key_generation == 1
            && !self.vault_id.is_empty()
            && self.vault_id.len() <= 128
            && self
                .vault_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            && self.owner_envelope.valid(credential)
    }
}

impl Envelope {
    fn valid(&self, credential: &str) -> bool {
        let e = self;
        e.format_version == 2
            && e.kind == "owner-key"
            && e.credential_id == credential
            && canonical(&e.credential_id, 1, 512)
            && canonical(&e.prf_input, 32, 32)
            && canonical(&e.salt, 32, 32)
            && canonical(&e.nonce, 12, 12)
            && canonical(&e.wrapped_key, 48, 48)
    }
}

async fn head(
    db: &worker::D1Database,
    account: &str,
    credential: &str,
) -> worker::Result<Option<Head>> {
    db.prepare("SELECT h.vault_id,h.origin,h.key_generation,h.revision,h.format_version,h.suite,h.operation_id,h.request_hash,w.envelope \
        FROM vault_owner_key_head h LEFT JOIN vault_owner_key_wrap w ON w.account_id=h.account_id \
        AND w.key_generation=h.key_generation AND w.credential_id=?2 WHERE h.account_id=?1")
        .bind(&[JsValue::from_str(account),JsValue::from_str(credential)])?.first::<Head>(None).await
}

fn response(head: Head, account: &str, origin: &str) -> worker::Result<Response> {
    if head.format_version != 2 || head.suite != SUITE {
        return error(409, "unsupported_owner_key_format");
    }
    if head.origin != origin {
        return error(409, "owner_key_origin_mismatch");
    }
    let Some(encoded) = head.envelope else {
        return error(409, "credential_not_wrapped");
    };
    let Ok(envelope) = serde_json::from_str(&encoded) else {
        return error(503, "storage_unavailable");
    };
    Response::builder()
        .with_header("Cache-Control", "no-store")?
        .with_header("ETag", &format!("\"{}\"", head.revision))?
        .from_json(&KeyResponse {
            format_version: head.format_version,
            suite: &head.suite,
            owner_id: account,
            vault_id: &head.vault_id,
            origin: &head.origin,
            key_generation: head.key_generation,
            revision: head.revision,
            owner_envelope: envelope,
        })
}

pub async fn get(request: Request, context: RouteContext<()>) -> worker::Result<Response> {
    if context.env.bucket("VAULT_BLOBS").is_err() {
        return error(404, "not_found");
    }
    let db = context.env.d1("DB")?;
    let Some(owner) = owner(&request, &db).await? else {
        return error(401, "authentication_required");
    };
    let Some(head) = head(&db, &owner.account_id, &owner.credential_id).await? else {
        return error(404, "owner_key_missing");
    };
    response(
        head,
        &owner.account_id,
        &request.url()?.origin().ascii_serialization(),
    )
}

pub async fn create(mut request: Request, context: RouteContext<()>) -> worker::Result<Response> {
    if context.env.bucket("VAULT_BLOBS").is_err() {
        return error(404, "not_found");
    }
    if !same_origin(&request)? {
        return error(403, "origin_required");
    }
    // No overwrite/rotation/reset endpoint. Initial creation has one exact precondition.
    if expected_revision(&request)? != Some(-1) {
        return error(428, "create_precondition_required");
    }
    let Some(operation) = operation_id(&request)? else {
        return error(400, "operation_id_required");
    };
    let db = context.env.d1("DB")?;
    let Some(owner) = owner(&request, &db).await? else {
        return error(401, "authentication_required");
    };
    if request.headers().get("Content-Type")?.as_deref() != Some("application/json") {
        return error(415, "json_required");
    }
    let body = match read_bounded_body(&mut request, MAX_BODY).await {
        Ok(body) => body,
        Err(_) => return error(413, "body_too_large_or_invalid"),
    };
    let Ok(value) = serde_json::from_str::<Create>(&body) else {
        return error(400, "invalid_body");
    };
    if !value.valid(&owner.credential_id) {
        return error(400, "invalid_owner_key");
    }
    let hash = request_hash("CREATE-OWNER-KEY", "owner-key", -1, body.as_bytes());
    if let Some(previous) = head(&db, &owner.account_id, &owner.credential_id).await? {
        return retry(
            previous,
            &operation,
            &hash,
            &owner.account_id,
            &request.url()?.origin().ascii_serialization(),
        );
    }
    let now = now_seconds().ok_or_else(|| worker::Error::RustError("server_error".into()))? as i64;
    let origin = request.url()?.origin().ascii_serialization();
    let envelope = serde_json::to_string(&value.owner_envelope)
        .map_err(|_| worker::Error::RustError("server_error".into()))?;
    let insert=db.prepare("INSERT INTO vault_owner_key_head(account_id,vault_id,origin,key_generation,revision,format_version,suite,operation_id,request_hash,created_at) \
      SELECT ?1,?2,?3,1,1,2,?4,?5,?6,?7 WHERE NOT EXISTS(SELECT 1 FROM vault_owner_key_head WHERE account_id=?1) \
      AND EXISTS(SELECT 1 FROM sso_context sx JOIN sso_session ss ON ss.sso_id=sx.sso_id \
        JOIN account_security a ON a.account_id=ss.account_id \
        JOIN credential c ON c.credential_id=ss.credential_id AND c.account_id=ss.account_id \
        WHERE sx.secret_hash=?8 AND ss.account_id=?1 AND ss.credential_id=?9 AND ss.revoked=0 AND ss.expires_at>?7 \
        AND a.active=1 AND a.epoch=ss.epoch AND c.active=1)")
      .bind(&[JsValue::from_str(&owner.account_id),JsValue::from_str(&value.vault_id),JsValue::from_str(&origin),JsValue::from_str(SUITE),
        JsValue::from_str(&operation),JsValue::from_str(&hash),JsValue::from_f64(now as f64),JsValue::from_str(&owner.secret_hash),JsValue::from_str(&owner.credential_id)])?;
    let wrap=db.prepare("INSERT INTO vault_owner_key_wrap(account_id,key_generation,credential_id,envelope) SELECT ?1,1,?2,?3 WHERE changes()=1")
      .bind(&[JsValue::from_str(&owner.account_id),JsValue::from_str(&owner.credential_id),JsValue::from_str(&envelope)])?;
    if db.batch(vec![insert, wrap]).await.is_err() {
        if let Some(previous) = head(&db, &owner.account_id, &owner.credential_id).await? {
            return retry(previous, &operation, &hash, &owner.account_id, &origin);
        }
        return error(503, "storage_unavailable");
    }
    if let Some(previous) = head(&db, &owner.account_id, &owner.credential_id).await? {
        return retry(previous, &operation, &hash, &owner.account_id, &origin);
    }
    error(409, "creation_unavailable")
}

fn retry(
    previous: Head,
    operation: &str,
    hash: &str,
    account: &str,
    origin: &str,
) -> worker::Result<Response> {
    if previous.operation_id != operation {
        return error(409, "owner_key_exists");
    }
    if previous.request_hash != hash {
        return error(409, "operation_id_reused");
    }
    response(previous, account, origin)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RemoveWrap {
    format_version: u8,
    suite: String,
    vault_id: String,
    key_generation: i64,
    credential_id: String,
}

#[derive(Deserialize, Serialize)]
struct WrapReceipt {
    operation_id: String,
    #[serde(skip_serializing)]
    request_hash: String,
    action: String,
    credential_id: String,
    vault_id: String,
    key_generation: i64,
    previous_revision: i64,
    revision: i64,
}

async fn receipt(
    db: &worker::D1Database,
    actor: &crate::vault_http::Owner,
    operation: &str,
) -> worker::Result<Option<WrapReceipt>> {
    let now = now_seconds().ok_or_else(|| worker::Error::RustError("server_error".into()))?;
    db.prepare("SELECT o.operation_id,o.request_hash,o.action,o.credential_id,o.vault_id,o.key_generation,o.previous_revision,o.revision \
      FROM vault_owner_key_wrap_operation o JOIN sso_context sx ON sx.secret_hash=?3 \
      JOIN sso_session ss ON ss.sso_id=sx.sso_id AND ss.account_id=o.account_id \
      JOIN account_security a ON a.account_id=ss.account_id JOIN credential c ON c.credential_id=ss.credential_id AND c.account_id=ss.account_id \
      JOIN vault_owner_key_head h ON h.account_id=o.account_id AND h.vault_id=o.vault_id AND h.key_generation=o.key_generation \
      JOIN vault_owner_key_wrap w ON w.account_id=h.account_id AND w.key_generation=h.key_generation AND w.credential_id=ss.credential_id \
      WHERE o.account_id=?1 AND o.operation_id=?2 AND ss.credential_id=?4 \
      AND ss.revoked=0 AND ss.expires_at>?5 AND a.active=1 AND a.epoch=ss.epoch AND c.active=1")
      .bind(&[JsValue::from_str(&actor.account_id),JsValue::from_str(operation),JsValue::from_str(&actor.secret_hash),JsValue::from_str(&actor.credential_id),JsValue::from_f64(now as f64)])?.first::<WrapReceipt>(None).await
}

fn receipt_response(value: WrapReceipt, hash: &str) -> worker::Result<Response> {
    if value.request_hash != hash {
        return error(409, "operation_id_reused");
    }
    Response::builder()
        .with_header("Cache-Control", "no-store")?
        .with_header("ETag", &format!("\"{}\"", value.revision))?
        .from_json(&value)
}

#[derive(Deserialize, Serialize)]
struct WrappedCredential {
    credential_id: String,
    active: i64,
}

pub async fn wrappers(request: Request, context: RouteContext<()>) -> worker::Result<Response> {
    if context.env.bucket("VAULT_BLOBS").is_err() {
        return error(404, "not_found");
    }
    let db = context.env.d1("DB")?;
    let Some(owner) = owner(&request, &db).await? else {
        return error(401, "authentication_required");
    };
    let Some(head) = head(&db, &owner.account_id, &owner.credential_id).await? else {
        return error(404, "owner_key_missing");
    };
    if head.envelope.is_none() {
        return error(409, "credential_not_wrapped");
    }
    if head.format_version != 2
        || head.suite != SUITE
        || head.origin != request.url()?.origin().ascii_serialization()
    {
        return error(409, "owner_key_context_mismatch");
    }
    let credentials=db.prepare("SELECT w.credential_id,c.active FROM vault_owner_key_wrap w JOIN credential c \
      ON c.credential_id=w.credential_id AND c.account_id=w.account_id WHERE w.account_id=?1 AND w.key_generation=?2 ORDER BY w.credential_id LIMIT 11")
      .bind(&[JsValue::from_str(&owner.account_id),JsValue::from_f64(head.key_generation as f64)])?
      .all().await?.results::<WrappedCredential>()?;
    if credentials.len() > 10 {
        return error(503, "storage_unavailable");
    }
    Response::builder().with_header("Cache-Control","no-store")?
      .with_header("ETag", &format!("\"{}\"",head.revision))?
      .from_json(&serde_json::json!({"vault_id":head.vault_id,"key_generation":head.key_generation,"revision":head.revision,"credentials":credentials}))
}

pub async fn add_wrapper(request: Request, context: RouteContext<()>) -> worker::Result<Response> {
    mutate_wrapper(request, context, true).await
}

pub async fn remove_wrapper(
    request: Request,
    context: RouteContext<()>,
) -> worker::Result<Response> {
    mutate_wrapper(request, context, false).await
}

async fn mutate_wrapper(
    mut request: Request,
    context: RouteContext<()>,
    add: bool,
) -> worker::Result<Response> {
    if context.env.bucket("VAULT_BLOBS").is_err() {
        return error(404, "not_found");
    }
    if !same_origin(&request)? {
        return error(403, "origin_required");
    }
    let Some(expected) = expected_revision(&request)?.filter(|r| *r > 0) else {
        return error(428, "revision_required");
    };
    let Some(operation) = operation_id(&request)? else {
        return error(400, "operation_id_required");
    };
    let db = context.env.d1("DB")?;
    let Some(actor) = owner(&request, &db).await? else {
        return error(401, "authentication_required");
    };
    if request.headers().get("Content-Type")?.as_deref() != Some("application/json") {
        return error(415, "json_required");
    }
    let body = match read_bounded_body(&mut request, MAX_BODY).await {
        Ok(body) => body,
        Err(_) => return error(413, "body_too_large_or_invalid"),
    };
    let (vault, generation, target, envelope) = if add {
        let Ok(value) = serde_json::from_str::<Create>(&body) else {
            return error(400, "invalid_body");
        };
        // Bootstrap's generation-one restriction does not apply to wrapper operations.
        if value.format_version != 2
            || value.suite != SUITE
            || !value
                .owner_envelope
                .valid(&value.owner_envelope.credential_id)
        {
            return error(400, "invalid_owner_key");
        }
        let envelope = serde_json::to_string(&value.owner_envelope)
            .map_err(|_| worker::Error::RustError("server_error".into()))?;
        (
            value.vault_id,
            value.key_generation,
            value.owner_envelope.credential_id,
            Some(envelope),
        )
    } else {
        let Ok(value) = serde_json::from_str::<RemoveWrap>(&body) else {
            return error(400, "invalid_body");
        };
        if value.format_version != 2
            || value.suite != SUITE
            || !canonical(&value.credential_id, 1, 512)
        {
            return error(400, "invalid_owner_key");
        }
        (
            value.vault_id,
            value.key_generation,
            value.credential_id,
            None,
        )
    };
    let origin = request.url()?.origin().ascii_serialization();
    let Some(current) = head(&db, &actor.account_id, &actor.credential_id).await? else {
        return error(404, "owner_key_missing");
    };
    if current.envelope.is_none() {
        return error(409, "credential_not_wrapped");
    }
    if current.format_version != 2
        || current.suite != SUITE
        || current.origin != origin
        || current.vault_id != vault
        || current.key_generation != generation
    {
        return error(409, "owner_key_context_mismatch");
    }
    let action = if add { "add" } else { "remove" };
    let hash = request_hash(
        if add {
            "ADD-OWNER-WRAP"
        } else {
            "REMOVE-OWNER-WRAP"
        },
        &format!("owner-key-wrappers:{}", actor.credential_id),
        expected,
        body.as_bytes(),
    );
    if let Some(previous) = receipt(&db, &actor, &operation).await? {
        return receipt_response(previous, &hash);
    }
    if current.revision != expected {
        return error(409, "owner_key_changed");
    }
    if target == actor.credential_id {
        return error(409, "source_wrapper_required");
    }
    let now = now_seconds().ok_or_else(|| worker::Error::RustError("server_error".into()))? as i64;
    // Recheck session epoch, credential ownership and both wrapper states within the CAS.
    // Baseline head-update triggers revoke grants in this same transaction.
    let update=db.prepare("UPDATE vault_owner_key_head SET revision=revision+1 \
      WHERE account_id=?1 AND revision=?2 AND revision<9007199254740991 AND vault_id=?3 AND key_generation=?4 \
      AND origin=?5 AND format_version=2 AND suite=?6 \
      AND EXISTS(SELECT 1 FROM sso_context sx JOIN sso_session ss ON ss.sso_id=sx.sso_id \
        JOIN account_security a ON a.account_id=ss.account_id \
        JOIN credential c ON c.credential_id=ss.credential_id AND c.account_id=ss.account_id \
        WHERE sx.secret_hash=?7 AND ss.account_id=?1 AND ss.credential_id=?8 AND ss.revoked=0 AND ss.expires_at>?9 \
        AND a.active=1 AND a.epoch=ss.epoch AND c.active=1) \
      AND EXISTS(SELECT 1 FROM vault_owner_key_wrap WHERE account_id=?1 AND key_generation=?4 AND credential_id=?8) \
      AND EXISTS(SELECT 1 FROM credential WHERE account_id=?1 AND credential_id=?10 AND (?11=0 OR active=1)) \
      AND ?8!=?10 \
      AND (?11=0 OR (SELECT count(*) FROM vault_owner_key_wrap WHERE account_id=?1 AND key_generation=?4)<10) \
      AND (SELECT count(*) FROM vault_owner_key_wrap_operation WHERE account_id=?1 AND created_at>unixepoch()-60)<20 \
      AND (?11=1 AND NOT EXISTS(SELECT 1 FROM vault_owner_key_wrap WHERE account_id=?1 AND key_generation=?4 AND credential_id=?10) \
        OR ?11=0 AND EXISTS(SELECT 1 FROM vault_owner_key_wrap WHERE account_id=?1 AND key_generation=?4 AND credential_id=?10)) \
      AND NOT EXISTS(SELECT 1 FROM vault_owner_key_wrap_operation WHERE account_id=?1 AND operation_id=?12)")
      .bind(&[JsValue::from_str(&actor.account_id),JsValue::from_f64(expected as f64),JsValue::from_str(&vault),JsValue::from_f64(generation as f64),
        JsValue::from_str(&origin),JsValue::from_str(SUITE),JsValue::from_str(&actor.secret_hash),JsValue::from_str(&actor.credential_id),
        JsValue::from_f64(now as f64),JsValue::from_str(&target),JsValue::from_f64(if add {1.0} else {0.0}),JsValue::from_str(&operation)])?;
    let guard = db
        .prepare("INSERT INTO atomic_guard(operation_id,passed) VALUES(?1,changes())")
        .bind(&[JsValue::from_str(&operation)])?;
    let change = if let Some(envelope) = envelope {
        db.prepare("INSERT INTO vault_owner_key_wrap(account_id,key_generation,credential_id,envelope) VALUES(?1,?2,?3,?4)")
          .bind(&[JsValue::from_str(&actor.account_id),JsValue::from_f64(generation as f64),JsValue::from_str(&target),JsValue::from_str(&envelope)])?
    } else {
        db.prepare("DELETE FROM vault_owner_key_wrap WHERE account_id=?1 AND key_generation=?2 AND credential_id=?3")
          .bind(&[JsValue::from_str(&actor.account_id),JsValue::from_f64(generation as f64),JsValue::from_str(&target)])?
    };
    let changed = db
        .prepare("UPDATE atomic_guard SET passed=changes() WHERE operation_id=?1")
        .bind(&[JsValue::from_str(&operation)])?;
    let audit=db.prepare("INSERT INTO vault_owner_key_wrap_operation(account_id,operation_id,request_hash,action,source_credential_id,credential_id,vault_id,key_generation,previous_revision,revision,created_at) \
      VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?9+1,?10)")
      .bind(&[JsValue::from_str(&actor.account_id),JsValue::from_str(&operation),JsValue::from_str(&hash),JsValue::from_str(action),
        JsValue::from_str(&actor.credential_id),JsValue::from_str(&target),JsValue::from_str(&vault),JsValue::from_f64(generation as f64),JsValue::from_f64(expected as f64),JsValue::from_f64(now as f64)])?;
    let clear = db
        .prepare("DELETE FROM atomic_guard WHERE operation_id=?1")
        .bind(&[JsValue::from_str(&operation)])?;
    let result = db
        .batch(vec![update, guard, change, changed, audit, clear])
        .await;
    if let Some(previous) = receipt(&db, &actor, &operation).await? {
        return receipt_response(previous, &hash);
    }
    if result.is_err() {
        if owner(&request, &db).await?.is_none() {
            return error(401, "authentication_required");
        }
        let latest = head(&db, &actor.account_id, &actor.credential_id).await?;
        if !latest.is_some_and(|h| {
            h.revision == expected
                && h.envelope.is_some()
                && h.vault_id == vault
                && h.key_generation == generation
                && h.origin == origin
                && h.format_version == 2
                && h.suite == SUITE
        }) {
            return error(409, "owner_key_changed");
        }
        #[derive(Deserialize)]
        struct Recent {
            count: i64,
        }
        let recent=db.prepare("SELECT count(*) AS count FROM vault_owner_key_wrap_operation WHERE account_id=?1 AND created_at>unixepoch()-60")
          .bind(&[JsValue::from_str(&actor.account_id)])?.first::<Recent>(None).await?;
        if recent.is_some_and(|r| r.count >= 20) {
            return error(429, "write_rate_exceeded");
        }
        #[derive(Deserialize)]
        struct Admission {
            passed: i64,
        }
        let admission=db.prepare("SELECT 1 AS passed WHERE EXISTS(SELECT 1 FROM credential WHERE account_id=?1 AND credential_id=?2 AND (?3=0 OR active=1)) \
          AND (?3=1 AND NOT EXISTS(SELECT 1 FROM vault_owner_key_wrap WHERE account_id=?1 AND key_generation=?4 AND credential_id=?2) \
            AND (SELECT count(*) FROM vault_owner_key_wrap WHERE account_id=?1 AND key_generation=?4)<10 \
            OR ?3=0 AND EXISTS(SELECT 1 FROM vault_owner_key_wrap WHERE account_id=?1 AND key_generation=?4 AND credential_id=?2))")
          .bind(&[JsValue::from_str(&actor.account_id),JsValue::from_str(&target),JsValue::from_f64(if add{1.0}else{0.0}),JsValue::from_f64(generation as f64)])?
          .first::<Admission>(None).await?;
        return error(
            if admission.is_some_and(|a| a.passed == 1) {
                503
            } else {
                409
            },
            "wrapper_change_unconfirmed",
        );
    }
    error(503, "storage_unavailable")
}
