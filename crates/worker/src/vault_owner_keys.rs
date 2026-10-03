//! Immutable first-generation bootstrap. Rotation activation is a separate protocol.
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use wasm_bindgen::JsValue;
use worker::{Request, Response, RouteContext};

use crate::vault_attributes::{
    error, expected_revision, operation_id, owner, request_hash, same_origin,
};
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
        let e = &self.owner_envelope;
        self.format_version == 2
            && self.suite == SUITE
            && self.key_generation == 1
            && !self.vault_id.is_empty()
            && self.vault_id.len() <= 128
            && self
                .vault_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            && e.format_version == 2
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
