//! Owner-only opaque Vault attribute storage. No attribute plaintext is handled here.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use mikaki_oidc::CryptographicRandom;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use wasm_bindgen::JsValue;
use worker::{D1Database, Request, Response, RouteContext};

use crate::{WorkersCryptoRandom, browser_cookie, now_seconds, read_bounded_body};

const MAX_REQUEST_BYTES: usize = 48 * 1024;
const MAX_CIPHERTEXT_BYTES: usize = 24 * 1024;
const MAX_ENVELOPE_BYTES: usize = 8 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PutBody {
    format_version: u8,
    ciphertext: String,
    owner_envelope: String,
}

#[derive(Deserialize)]
struct Head {
    revision: i64,
    format_version: u8,
    object_key: Option<String>,
    ciphertext_sha256: Option<String>,
    owner_envelope: Option<String>,
    deleted: i64,
}

#[derive(Deserialize)]
struct Mutation {
    request_hash: String,
    attribute_id: String,
    result_revision: i64,
    deleted: i64,
}

#[derive(Deserialize)]
struct Owner {
    account_id: String,
    secret_hash: String,
}

#[derive(Serialize)]
struct AttributeResponse<'a> {
    format_version: u8,
    revision: i64,
    ciphertext: &'a str,
    owner_envelope: &'a str,
}

#[derive(Serialize)]
struct RevisionResponse {
    revision: i64,
    deleted: bool,
}

fn error(status: u16, code: &str) -> worker::Result<Response> {
    Response::builder()
        .with_status(status)
        .with_header("Cache-Control", "no-store")?
        .from_json(&serde_json::json!({ "error": code }))
}

fn attribute_id(context: &RouteContext<()>) -> Option<&str> {
    let id = context.param("attribute")?.as_str();
    if id.is_empty()
        || id.len() > 64
        || !id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
    {
        return None;
    }
    Some(id)
}

async fn owner(request: &Request, db: &D1Database) -> worker::Result<Option<Owner>> {
    let Some(cookie) = browser_cookie(request, "__Host-op-sso")? else {
        return Ok(None);
    };
    let now = now_seconds().ok_or_else(|| worker::Error::RustError("server_error".into()))?;
    let hash = URL_SAFE_NO_PAD.encode(Sha256::digest(cookie.as_bytes()));
    db.prepare(
        "SELECT ss.account_id,sx.secret_hash FROM sso_context sx \
         JOIN sso_session ss ON ss.sso_id=sx.sso_id \
         JOIN account_security a ON a.account_id=ss.account_id \
         JOIN credential c ON c.credential_id=ss.credential_id AND c.account_id=ss.account_id \
         WHERE sx.secret_hash=?1 AND ss.revoked=0 AND ss.expires_at>?2 \
         AND a.active=1 AND a.epoch=ss.epoch AND c.active=1",
    )
    .bind(&[JsValue::from_str(&hash), JsValue::from_f64(now as f64)])?
    .first::<Owner>(None)
    .await
}

fn same_origin(request: &Request) -> worker::Result<bool> {
    let Some(origin) = request.headers().get("Origin")? else {
        return Ok(false);
    };
    Ok(origin == request.url()?.origin().ascii_serialization())
}

fn expected_revision(request: &Request) -> worker::Result<Option<i64>> {
    let none_match = request.headers().get("If-None-Match")?;
    let match_header = request.headers().get("If-Match")?;
    if none_match.is_some() && match_header.is_some() {
        return Ok(None);
    }
    if none_match.as_deref() == Some("*") {
        return Ok(Some(-1));
    }
    let Some(value) = match_header else {
        return Ok(None);
    };
    let Some(digits) = value.strip_prefix('"').and_then(|x| x.strip_suffix('"')) else {
        return Ok(None);
    };
    let Ok(revision) = digits.parse::<i64>() else {
        return Ok(None);
    };
    Ok((revision > 0).then_some(revision))
}

fn operation_id(request: &Request) -> worker::Result<Option<String>> {
    let Some(id) = request.headers().get("X-Operation-ID")? else {
        return Ok(None);
    };
    if id.len() != 43
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Ok(None);
    }
    Ok(Some(id))
}

fn request_hash(method: &str, attribute: &str, expected: i64, body: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(method.as_bytes());
    hash.update([0]);
    hash.update(attribute.as_bytes());
    hash.update([0]);
    hash.update(expected.to_be_bytes());
    hash.update(body);
    URL_SAFE_NO_PAD.encode(hash.finalize())
}

async fn mutation(
    db: &D1Database,
    owner: &str,
    operation: &str,
) -> worker::Result<Option<Mutation>> {
    db.prepare(
        "SELECT request_hash,attribute_id,result_revision,deleted FROM vault_attribute_mutation \
         WHERE account_id=?1 AND operation_id=?2",
    )
    .bind(&[JsValue::from_str(owner), JsValue::from_str(operation)])?
    .first::<Mutation>(None)
    .await
}

fn mutation_response(
    previous: Mutation,
    attribute: &str,
    hash: &str,
    deleted: bool,
) -> worker::Result<Response> {
    if previous.request_hash != hash
        || previous.attribute_id != attribute
        || previous.deleted != i64::from(deleted)
    {
        return error(409, "operation_id_reused");
    }
    revision_response(previous.result_revision, deleted, 200)
}

fn revision_response(revision: i64, deleted: bool, status: u16) -> worker::Result<Response> {
    Response::builder()
        .with_status(status)
        .with_header("Cache-Control", "no-store")?
        .with_header("ETag", &format!("\"{revision}\""))?
        .from_json(&RevisionResponse { revision, deleted })
}

pub async fn get(request: Request, context: RouteContext<()>) -> worker::Result<Response> {
    if context.env.bucket("VAULT_BLOBS").is_err() {
        return error(404, "not_found");
    }
    let Some(attribute) = attribute_id(&context) else {
        return error(400, "invalid_attribute");
    };
    let db = context.env.d1("DB")?;
    let Some(owner) = owner(&request, &db).await? else {
        return error(401, "authentication_required");
    };
    let head = db
        .prepare(
            "SELECT revision,format_version,object_key,ciphertext_sha256,owner_envelope,deleted \
             FROM vault_attribute_head WHERE account_id=?1 AND attribute_id=?2",
        )
        .bind(&[
            JsValue::from_str(&owner.account_id),
            JsValue::from_str(attribute),
        ])?
        .first::<Head>(None)
        .await?;
    let Some(head) = head.filter(|head| head.deleted == 0) else {
        return error(404, "not_found");
    };
    let (Some(object_key), Some(digest), Some(envelope)) =
        (head.object_key, head.ciphertext_sha256, head.owner_envelope)
    else {
        return error(503, "storage_unavailable");
    };
    let bucket = context.env.bucket("VAULT_BLOBS")?;
    let Some(object) = bucket.get(object_key).execute().await? else {
        return error(503, "storage_unavailable");
    };
    let Some(body) = object.body() else {
        return error(503, "storage_unavailable");
    };
    let bytes = body.bytes().await?;
    if bytes.len() > MAX_CIPHERTEXT_BYTES
        || URL_SAFE_NO_PAD.encode(Sha256::digest(&bytes)) != digest
    {
        return error(503, "storage_unavailable");
    }
    let ciphertext = URL_SAFE_NO_PAD.encode(bytes);
    Response::builder()
        .with_header("Cache-Control", "no-store")?
        .with_header("ETag", &format!("\"{}\"", head.revision))?
        .from_json(&AttributeResponse {
            format_version: head.format_version,
            revision: head.revision,
            ciphertext: &ciphertext,
            owner_envelope: &envelope,
        })
}

pub async fn put(mut request: Request, context: RouteContext<()>) -> worker::Result<Response> {
    write(&mut request, &context, false).await
}

pub async fn delete(mut request: Request, context: RouteContext<()>) -> worker::Result<Response> {
    write(&mut request, &context, true).await
}

async fn write(
    request: &mut Request,
    context: &RouteContext<()>,
    deleted: bool,
) -> worker::Result<Response> {
    if context.env.bucket("VAULT_BLOBS").is_err() {
        return error(404, "not_found");
    }
    let Some(attribute) = attribute_id(context) else {
        return error(400, "invalid_attribute");
    };
    if !same_origin(request)? {
        return error(403, "origin_required");
    }
    let Some(expected) = expected_revision(request)? else {
        return error(428, "precondition_required");
    };
    if deleted && expected == -1 {
        return error(428, "precondition_required");
    }
    let Some(operation) = operation_id(request)? else {
        return error(400, "operation_id_required");
    };
    let db = context.env.d1("DB")?;
    let Some(owner) = owner(request, &db).await? else {
        return error(401, "authentication_required");
    };
    let body = if deleted {
        String::new()
    } else {
        if request.headers().get("Content-Type")?.as_deref() != Some("application/json") {
            return error(415, "json_required");
        }
        match read_bounded_body(request, MAX_REQUEST_BYTES).await {
            Ok(body) => body,
            Err(_) => return error(413, "body_too_large_or_invalid"),
        }
    };
    let hash = request_hash(
        if deleted { "DELETE" } else { "PUT" },
        attribute,
        expected,
        body.as_bytes(),
    );
    if let Some(previous) = mutation(&db, &owner.account_id, &operation).await? {
        return mutation_response(previous, attribute, &hash, deleted);
    }
    let now = now_seconds().ok_or_else(|| worker::Error::RustError("server_error".into()))? as i64;
    let (object_key, digest, envelope) = if deleted {
        (None, None, None)
    } else {
        let Ok(value) = serde_json::from_str::<PutBody>(&body) else {
            return error(400, "invalid_body");
        };
        if value.format_version != 1 {
            return error(400, "unsupported_format");
        }
        let (Ok(ciphertext), Ok(wrap)) = (
            URL_SAFE_NO_PAD.decode(&value.ciphertext),
            URL_SAFE_NO_PAD.decode(&value.owner_envelope),
        ) else {
            return error(400, "invalid_body");
        };
        if ciphertext.is_empty()
            || ciphertext.len() > MAX_CIPHERTEXT_BYTES
            || wrap.is_empty()
            || wrap.len() > MAX_ENVELOPE_BYTES
            || URL_SAFE_NO_PAD.encode(&ciphertext) != value.ciphertext
            || URL_SAFE_NO_PAD.encode(&wrap) != value.owner_envelope
        {
            return error(400, "invalid_body");
        }
        let digest = URL_SAFE_NO_PAD.encode(Sha256::digest(&ciphertext));
        let mut random = [0u8; 32];
        let mut rng = WorkersCryptoRandom;
        rng.fill(&mut random)
            .map_err(|_| worker::Error::RustError("server_error".into()))?;
        let key = format!("vault-attribute/{}", URL_SAFE_NO_PAD.encode(random));
        context
            .env
            .bucket("VAULT_BLOBS")?
            .put(&key, ciphertext)
            .execute()
            .await?;
        (Some(key), Some(digest), Some(value.owner_envelope))
    };
    let revision = if expected == -1 { 1 } else { expected + 1 };
    let values = [
        JsValue::from_str(&owner.account_id),
        JsValue::from_str(attribute),
        JsValue::from_f64(revision as f64),
        object_key
            .as_deref()
            .map_or(JsValue::NULL, JsValue::from_str),
        digest.as_deref().map_or(JsValue::NULL, JsValue::from_str),
        envelope.as_deref().map_or(JsValue::NULL, JsValue::from_str),
        JsValue::from_f64(i64::from(deleted) as f64),
        JsValue::from_f64(now as f64),
        JsValue::from_f64(expected as f64),
        JsValue::from_str(&owner.secret_hash),
    ];
    let statement = db.prepare(
        "INSERT INTO vault_attribute_head(account_id,attribute_id,revision,format_version,object_key,ciphertext_sha256,owner_envelope,deleted,updated_at) \
         SELECT ?1,?2,?3,1,?4,?5,?6,?7,?8 WHERE ( \
           (?9=-1 AND NOT EXISTS (SELECT 1 FROM vault_attribute_head WHERE account_id=?1 AND attribute_id=?2)) \
           OR (?9>0 AND EXISTS (SELECT 1 FROM vault_attribute_head WHERE account_id=?1 AND attribute_id=?2 AND revision=?9))) \
         AND EXISTS (SELECT 1 FROM sso_context sx JOIN sso_session ss ON ss.sso_id=sx.sso_id \
           JOIN account_security a ON a.account_id=ss.account_id \
           JOIN credential c ON c.credential_id=ss.credential_id AND c.account_id=ss.account_id \
           WHERE sx.secret_hash=?10 AND ss.account_id=?1 AND ss.revoked=0 AND ss.expires_at>?8 \
           AND a.active=1 AND a.epoch=ss.epoch AND c.active=1) \
         ON CONFLICT(account_id,attribute_id) DO UPDATE SET \
           revision=excluded.revision,object_key=excluded.object_key, \
           ciphertext_sha256=excluded.ciphertext_sha256,owner_envelope=excluded.owner_envelope, \
           deleted=excluded.deleted,updated_at=excluded.updated_at WHERE vault_attribute_head.revision=?9",
    ).bind(&values)?;
    let ledger = db.prepare(
        "INSERT INTO vault_attribute_mutation(account_id,operation_id,request_hash,attribute_id,result_revision,deleted,created_at) \
         SELECT ?1,?2,?3,?4,?5,?6,?7 WHERE changes()=1",
    ).bind(&[
        JsValue::from_str(&owner.account_id),
        JsValue::from_str(&operation),
        JsValue::from_str(&hash),
        JsValue::from_str(attribute),
        JsValue::from_f64(revision as f64),
        JsValue::from_f64(i64::from(deleted) as f64),
        JsValue::from_f64(now as f64),
    ])?;
    if db.batch(vec![statement, ledger]).await.is_err() {
        if let Some(previous) = mutation(&db, &owner.account_id, &operation).await? {
            return mutation_response(previous, attribute, &hash, deleted);
        }
        return error(503, "storage_unavailable");
    }
    if let Some(previous) = mutation(&db, &owner.account_id, &operation).await? {
        return mutation_response(previous, attribute, &hash, deleted);
    }
    error(409, "revision_conflict")
}
