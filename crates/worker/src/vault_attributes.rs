//! Owner-only opaque Vault attribute storage. No attribute plaintext is handled here.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use mikaki_oidc::CryptographicRandom;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use wasm_bindgen::JsValue;
use worker::{D1Database, Request, Response, RouteContext};

use crate::vault_authzen;
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
struct WriteLimits {
    revision: Option<i64>,
    recent: i64,
    slots: i64,
}

#[derive(Deserialize)]
pub(crate) struct Owner {
    pub(crate) account_id: String,
    pub(crate) secret_hash: String,
    credential_id: String,
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

pub(crate) fn error(status: u16, code: &str) -> worker::Result<Response> {
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

pub(crate) async fn owner(request: &Request, db: &D1Database) -> worker::Result<Option<Owner>> {
    let Some(cookie) = browser_cookie(request, "__Host-op-sso")? else {
        return Ok(None);
    };
    let now = now_seconds().ok_or_else(|| worker::Error::RustError("server_error".into()))?;
    let hash = URL_SAFE_NO_PAD.encode(Sha256::digest(cookie.as_bytes()));
    db.prepare(
        "SELECT ss.account_id,sx.secret_hash,ss.credential_id FROM sso_context sx \
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

#[derive(Serialize)]
struct SessionResponse<'a> {
    credential_id: &'a str,
    account_id: &'a str,
}

#[derive(Deserialize)]
struct RecipientKey {
    key_id: String,
    public_key: Vec<u8>,
    generation: i64,
    revision: i64,
}

#[derive(Serialize)]
struct RecipientKeyResponse<'a> {
    service_id: &'static str,
    algorithm: &'static str,
    envelope_suite: &'static str,
    key_id: &'a str,
    public_key: String,
    generation: i64,
    revision: i64,
}

pub async fn recipient_key(
    request: Request,
    context: RouteContext<()>,
) -> worker::Result<Response> {
    if context.env.bucket("VAULT_BLOBS").is_err() {
        return error(404, "not_found");
    }
    let db = context.env.d1("DB")?;
    if owner(&request, &db).await?.is_none() {
        return error(401, "authentication_required");
    }
    let key = db
        .prepare(
            "SELECT key_id,public_key,generation,revision FROM vault_recipient_key \
             WHERE service_id='userinfo' AND state='active'",
        )
        .first::<RecipientKey>(None)
        .await?;
    let Some(key) = key else {
        return error(404, "recipient_unavailable");
    };
    if key.public_key.len() != 1184
        || key.key_id != URL_SAFE_NO_PAD.encode(Sha256::digest(&key.public_key))
    {
        return error(503, "recipient_unavailable");
    }
    let Ok(claims) = context.env.service("USERINFO_CLAIMS") else {
        return error(503, "recipient_unavailable");
    };
    let verification = claims
        .fetch(
            format!(
                "https://userinfo.internal/internal/recipient-keys/{}/verify",
                key.key_id
            ),
            None,
        )
        .await;
    if !matches!(verification, Ok(response) if response.status_code() == 204) {
        return error(503, "recipient_unavailable");
    }
    let still_active = db
        .prepare(
            "SELECT 1 AS present FROM vault_recipient_key \
             WHERE key_id=? AND state='active' AND revision=?",
        )
        .bind(&[
            wasm_bindgen::JsValue::from_str(&key.key_id),
            wasm_bindgen::JsValue::from_f64(key.revision as f64),
        ])?
        .first::<serde_json::Value>(None)
        .await?;
    if still_active.is_none() {
        return error(503, "recipient_unavailable");
    }
    Response::builder()
        .with_header("Cache-Control", "no-store")?
        .from_json(&RecipientKeyResponse {
            service_id: "userinfo",
            algorithm: "ML-KEM-768",
            envelope_suite: "ML-KEM-768-HKDF-SHA256-AES-256-GCM-draft04-v1",
            key_id: &key.key_id,
            public_key: URL_SAFE_NO_PAD.encode(&key.public_key),
            generation: key.generation,
            revision: key.revision,
        })
}

pub async fn session(request: Request, context: RouteContext<()>) -> worker::Result<Response> {
    if context.env.bucket("VAULT_BLOBS").is_err() {
        return error(404, "not_found");
    }
    let db = context.env.d1("DB")?;
    let Some(owner) = owner(&request, &db).await? else {
        return error(401, "authentication_required");
    };
    Response::builder()
        .with_header("Cache-Control", "no-store")?
        .from_json(&SessionResponse {
            credential_id: &owner.credential_id,
            account_id: &owner.account_id,
        })
}

pub async fn page(request: Request, context: RouteContext<()>) -> worker::Result<Response> {
    if context.env.bucket("VAULT_BLOBS").is_err() {
        return error(404, "not_found");
    }
    let db = context.env.d1("DB")?;
    if owner(&request, &db).await?.is_none() {
        return error(401, "authentication_required");
    }
    let strings = crate::i18n::catalog(crate::i18n::select(&request, None)?);
    let mut html = include_str!("../ui/vault.html").to_owned();
    let replacements = [
        ("{{locale}}", strings.locale),
        ("{{title}}", strings.message("vaultTitle")),
    ];
    for (key, value) in replacements {
        html = html.replace(key, &crate::i18n::html_escape(value));
    }
    Response::builder()
        .with_header("Cache-Control", "no-store")?
        .with_header("Referrer-Policy", "no-referrer")?
        .with_header("Content-Security-Policy", "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")?
        .from_html(html)
}

pub async fn script(_request: Request, context: RouteContext<()>) -> worker::Result<Response> {
    if context.env.bucket("VAULT_BLOBS").is_err() {
        return error(404, "not_found");
    }
    let script = include_str!(concat!(env!("OUT_DIR"), "/vault.js"));
    Ok(Response::builder()
        .with_header("Content-Type", "text/javascript; charset=utf-8")?
        .with_header("Cache-Control", "no-store")?
        .with_header("X-Content-Type-Options", "nosniff")?
        .fixed(script.as_bytes().to_vec()))
}

pub(crate) fn same_origin(request: &Request) -> worker::Result<bool> {
    let Some(origin) = request.headers().get("Origin")? else {
        return Ok(false);
    };
    Ok(origin == request.url()?.origin().ascii_serialization())
}

pub(crate) fn expected_revision(request: &Request) -> worker::Result<Option<i64>> {
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
    Ok((revision > 0 && revision < 9_007_199_254_740_991).then_some(revision))
}

pub(crate) fn operation_id(request: &Request) -> worker::Result<Option<String>> {
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

pub(crate) fn request_hash(method: &str, attribute: &str, expected: i64, body: &[u8]) -> String {
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
    if !owner_allowed(&owner.account_id, attribute, vault_authzen::READ_CIPHERTEXT)
        || !owner_allowed(
            &owner.account_id,
            attribute,
            vault_authzen::READ_OWNER_ENVELOPE,
        )
    {
        return error(403, "access_denied");
    }
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
    let Some(head) = head else {
        return error(404, "not_found");
    };
    if head.deleted != 0 {
        return Ok(Response::builder()
            .with_status(404)
            .with_header("Cache-Control", "no-store")?
            .with_header("ETag", &format!("\"{}\"", head.revision))?
            .with_header("Content-Type", "application/json")?
            .fixed(b"{\"error\":\"not_found\"}".to_vec()));
    }
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
    let action = if deleted {
        vault_authzen::DELETE
    } else {
        vault_authzen::WRITE
    };
    if !owner_allowed(&owner.account_id, attribute, action) {
        return error(403, "access_denied");
    }
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
    let limits = db
        .prepare(
            "SELECT \
             (SELECT revision FROM vault_attribute_head WHERE account_id=?1 AND attribute_id=?2) AS revision, \
             (SELECT COUNT(*) FROM vault_attribute_mutation WHERE account_id=?1 AND created_at>?3-60) AS recent, \
             (SELECT COUNT(*) FROM vault_attribute_head WHERE account_id=?1) AS slots",
        )
        .bind(&[
            JsValue::from_str(&owner.account_id),
            JsValue::from_str(attribute),
            JsValue::from_f64(now as f64),
        ])?
        .first::<WriteLimits>(None)
        .await?
        .ok_or_else(|| worker::Error::RustError("write_limits_unavailable".into()))?;
    if (expected == -1 && limits.revision.is_some())
        || (expected > 0 && limits.revision != Some(expected))
    {
        return error(409, "revision_conflict");
    }
    if limits.recent >= 20 {
        return error(429, "write_rate_exceeded");
    }
    if expected == -1 && limits.slots >= 32 {
        return error(409, "attribute_limit_exceeded");
    }
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
         AND (SELECT COUNT(*) FROM vault_attribute_mutation WHERE account_id=?1 AND created_at>?8-60)<20 \
         AND (?9>0 OR (SELECT COUNT(*) FROM vault_attribute_head WHERE account_id=?1)<32) \
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

pub(crate) fn owner_allowed(account: &str, attribute: &str, action: &str) -> bool {
    let evaluation = vault_authzen::owner_evaluation(account, action, account, attribute);
    vault_authzen::evaluate_owner(&evaluation, account, attribute).decision
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ShareBody {
    frame: String,
    key_id: String,
    generation: i64,
    directory_revision: i64,
    ciphertext_sha256: String,
}

#[derive(Deserialize)]
struct SharePolicy {
    enabled: i64,
    grant_ttl_seconds: i64,
    revision: i64,
}

#[derive(Deserialize)]
struct ShareHead {
    revision: i64,
    ciphertext_sha256: Option<String>,
    object_key: Option<String>,
    deleted: i64,
}

#[derive(Deserialize)]
struct ShareGrant {
    version: i64,
    status: String,
    expires_at: i64,
}

#[derive(Deserialize)]
struct ShareAudit {
    request_hash: String,
    action: String,
    attribute_revision: i64,
    grant_version: i64,
}

#[derive(Serialize)]
struct ShareStatus {
    enabled: bool,
    grant_ttl_seconds: i64,
    policy_revision: i64,
    active: bool,
    grant_version: Option<i64>,
    expires_at: Option<i64>,
}

#[derive(Serialize)]
struct ShareResult {
    grant_version: i64,
    attribute_revision: i64,
}

async fn share_policy(db: &D1Database) -> worker::Result<SharePolicy> {
    db.prepare("SELECT enabled,grant_ttl_seconds,revision FROM vault_share_policy WHERE id=1")
        .first::<SharePolicy>(None)
        .await?
        .ok_or_else(|| worker::Error::RustError("share_policy_unavailable".into()))
}

async fn share_audit(
    db: &D1Database,
    account: &str,
    operation: &str,
) -> worker::Result<Option<ShareAudit>> {
    db.prepare(
        "SELECT request_hash,action,attribute_revision,grant_version \
         FROM vault_attribute_share_audit WHERE account_id=?1 AND operation_id=?2",
    )
    .bind(&[JsValue::from_str(account), JsValue::from_str(operation)])?
    .first::<ShareAudit>(None)
    .await
}

pub async fn share_status(request: Request, context: RouteContext<()>) -> worker::Result<Response> {
    if context.env.bucket("VAULT_BLOBS").is_err() {
        return error(404, "not_found");
    }
    let db = context.env.d1("DB")?;
    let Some(owner) = owner(&request, &db).await? else {
        return error(401, "authentication_required");
    };
    let policy = share_policy(&db).await?;
    let now = now_seconds().ok_or_else(|| worker::Error::RustError("server_error".into()))?;
    let grant = db
        .prepare(
            "SELECT g.version,g.status,g.expires_at \
         FROM vault_attribute_grant g JOIN vault_attribute_head h \
         ON h.account_id=g.account_id AND h.attribute_id=g.attribute_id \
         JOIN vault_attribute_recipient_envelope e ON e.envelope_id=g.envelope_id \
         JOIN vault_recipient_key k ON k.key_id=e.recipient_key_id \
         WHERE g.account_id=?1 AND g.attribute_id='name' AND g.recipient_service='userinfo' \
         AND g.purpose='oidc.userinfo.name' AND k.state IN ('active','decrypt_only') \
         AND h.revision=g.attribute_revision AND h.deleted=0 \
         AND h.ciphertext_sha256=e.ciphertext_sha256",
        )
        .bind(&[JsValue::from_str(&owner.account_id)])?
        .first::<ShareGrant>(None)
        .await?;
    let active = policy.enabled == 1
        && grant
            .as_ref()
            .is_some_and(|value| value.status == "active" && value.expires_at > now as i64);
    Response::builder()
        .with_header("Cache-Control", "no-store")?
        .from_json(&ShareStatus {
            enabled: policy.enabled == 1,
            grant_ttl_seconds: policy.grant_ttl_seconds,
            policy_revision: policy.revision,
            active,
            grant_version: grant.as_ref().map(|value| value.version),
            expires_at: grant.as_ref().map(|value| value.expires_at),
        })
}

pub async fn share(mut request: Request, context: RouteContext<()>) -> worker::Result<Response> {
    if context.env.bucket("VAULT_BLOBS").is_err() {
        return error(404, "not_found");
    }
    if !same_origin(&request)? {
        return error(403, "origin_required");
    }
    let Some(expected) = expected_revision(&request)?.filter(|revision| *revision > 0) else {
        return error(428, "precondition_required");
    };
    let Some(operation) = operation_id(&request)? else {
        return error(400, "operation_id_required");
    };
    if request.headers().get("Content-Type")?.as_deref() != Some("application/json") {
        return error(415, "json_required");
    }
    let body = match read_bounded_body(&mut request, 4096).await {
        Ok(body) => body,
        Err(_) => return error(413, "body_too_large_or_invalid"),
    };
    let hash = request_hash("SHARE", "name", expected, body.as_bytes());
    let db = context.env.d1("DB")?;
    let Some(owner) = owner(&request, &db).await? else {
        return error(401, "authentication_required");
    };
    if !owner_allowed(&owner.account_id, "name", vault_authzen::SHARE_SYSTEM) {
        return error(403, "access_denied");
    }
    if let Some(previous) = share_audit(&db, &owner.account_id, &operation).await? {
        return if previous.request_hash == hash
            && previous.action == "share"
            && previous.attribute_revision == expected
        {
            Response::builder()
                .with_header("Cache-Control", "no-store")?
                .from_json(&ShareResult {
                    grant_version: previous.grant_version,
                    attribute_revision: expected,
                })
        } else {
            error(409, "operation_id_reused")
        };
    }
    let Ok(value) = serde_json::from_str::<ShareBody>(&body) else {
        return error(400, "invalid_body");
    };
    let (Ok(frame), Ok(key_id)) = (
        URL_SAFE_NO_PAD.decode(&value.frame),
        URL_SAFE_NO_PAD.decode(&value.key_id),
    ) else {
        return error(400, "invalid_body");
    };
    if frame.len() != 1187
        || key_id.len() != 32
        || URL_SAFE_NO_PAD.encode(&frame) != value.frame
        || URL_SAFE_NO_PAD.encode(&key_id) != value.key_id
        || frame[..11] != [b'M', b'K', b'V', b'E', 1, 0, 0x41, 0, 1, 0, 2]
        || frame[11..43] != key_id
        || value.generation < 1
        || frame[43..51] != (value.generation as u64).to_be_bytes()
        || value.directory_revision < 1
        || value.ciphertext_sha256.len() != 43
    {
        return error(400, "invalid_body");
    }
    let policy = share_policy(&db).await?;
    if policy.enabled != 1 {
        return error(403, "sharing_disabled");
    }
    let head = db
        .prepare(
            "SELECT revision,ciphertext_sha256,object_key,deleted FROM vault_attribute_head \
         WHERE account_id=?1 AND attribute_id='name'",
        )
        .bind(&[JsValue::from_str(&owner.account_id)])?
        .first::<ShareHead>(None)
        .await?;
    if !head.as_ref().is_some_and(|head| {
        head.revision == expected
            && head.deleted == 0
            && head.ciphertext_sha256.as_deref() == Some(&value.ciphertext_sha256)
    }) {
        return error(409, "revision_conflict");
    }
    let Some(object_key) = head.and_then(|head| head.object_key) else {
        return error(503, "storage_unavailable");
    };
    let Some(blob) = context
        .env
        .bucket("VAULT_BLOBS")?
        .get(object_key)
        .execute()
        .await?
    else {
        return error(503, "storage_unavailable");
    };
    let Some(blob_body) = blob.body() else {
        return error(503, "storage_unavailable");
    };
    let ciphertext = blob_body.bytes().await?;
    if ciphertext.len() > MAX_CIPHERTEXT_BYTES
        || URL_SAFE_NO_PAD.encode(Sha256::digest(&ciphertext)) != value.ciphertext_sha256
    {
        return error(503, "storage_unavailable");
    }
    let Ok(claims) = context.env.service("USERINFO_CLAIMS") else {
        return error(503, "recipient_unavailable");
    };
    let origin = request.url()?.origin().ascii_serialization();
    let validation = serde_json::json!({
        "origin": origin,
        "account_id": owner.account_id,
        "revision": expected,
        "ciphertext": URL_SAFE_NO_PAD.encode(&ciphertext),
        "frame": value.frame,
    })
    .to_string();
    let mut init = worker::RequestInit::new();
    init.with_method(worker::Method::Post)
        .with_body(Some(JsValue::from_str(&validation)));
    init.headers.set("Content-Type", "application/json")?;
    let validation = claims
        .fetch(
            format!(
                "https://userinfo.internal/internal/recipient-keys/{}/validate-envelope",
                value.key_id
            ),
            Some(init),
        )
        .await;
    if !matches!(validation, Ok(response) if response.status_code() == 204) {
        return error(503, "recipient_unavailable");
    }
    let now = now_seconds().ok_or_else(|| worker::Error::RustError("server_error".into()))? as i64;
    let expires_at = now + policy.grant_ttl_seconds;
    let envelope = db.prepare(
        "INSERT INTO vault_attribute_recipient_envelope \
         (envelope_id,account_id,attribute_id,attribute_revision,recipient_service, \
          recipient_key_id,recipient_generation,suite,ciphertext_sha256,frame,created_at) \
         SELECT ?1,?2,'name',?3,'userinfo',?4,?5, \
          'ML-KEM-768-HKDF-SHA256-AES-256-GCM-draft04-v1',?6,?7,?8 \
         WHERE EXISTS (SELECT 1 FROM vault_share_policy WHERE id=1 AND enabled=1 AND revision=?9) \
         AND EXISTS (SELECT 1 FROM vault_attribute_head WHERE account_id=?2 AND attribute_id='name' \
                     AND revision=?3 AND deleted=0 AND ciphertext_sha256=?6) \
         AND EXISTS (SELECT 1 FROM vault_recipient_key WHERE key_id=?4 AND service_id='userinfo' \
                     AND generation=?5 AND revision=?10 AND state='active') \
         AND EXISTS (SELECT 1 FROM sso_context sx JOIN sso_session ss ON ss.sso_id=sx.sso_id \
           JOIN account_security a ON a.account_id=ss.account_id \
           JOIN credential c ON c.credential_id=ss.credential_id AND c.account_id=ss.account_id \
           WHERE sx.secret_hash=?11 AND ss.account_id=?2 AND ss.revoked=0 AND ss.expires_at>?8 \
           AND a.active=1 AND a.epoch=ss.epoch AND c.active=1)",
    ).bind(&[
        JsValue::from_str(&operation), JsValue::from_str(&owner.account_id),
        JsValue::from_f64(expected as f64), JsValue::from_str(&value.key_id),
        JsValue::from_f64(value.generation as f64), JsValue::from_str(&value.ciphertext_sha256),
        JsValue::from(frame), JsValue::from_f64(now as f64),
        JsValue::from_f64(policy.revision as f64),
        JsValue::from_f64(value.directory_revision as f64),
        JsValue::from_str(&owner.secret_hash),
    ])?;
    let guard = db
        .prepare(
            "INSERT INTO vault_share_atomic_guard(operation_id,passed) \
         VALUES(?1,CASE WHEN changes()=1 THEN 1 ELSE 0 END)",
        )
        .bind(&[JsValue::from_str(&operation)])?;
    let grant = db
        .prepare(
            "INSERT INTO vault_attribute_grant \
         (account_id,attribute_id,recipient_service,purpose,envelope_id,attribute_revision, \
          version,status,expires_at,updated_at) \
         VALUES(?1,'name','userinfo','oidc.userinfo.name',?2,?3,1,'active',?4,?5) \
         ON CONFLICT(account_id,attribute_id,recipient_service,purpose) DO UPDATE SET \
          envelope_id=excluded.envelope_id,attribute_revision=excluded.attribute_revision, \
          version=vault_attribute_grant.version+1,status='active', \
          expires_at=excluded.expires_at,updated_at=excluded.updated_at",
        )
        .bind(&[
            JsValue::from_str(&owner.account_id),
            JsValue::from_str(&operation),
            JsValue::from_f64(expected as f64),
            JsValue::from_f64(expires_at as f64),
            JsValue::from_f64(now as f64),
        ])?;
    let audit = db.prepare(
        "INSERT INTO vault_attribute_share_audit \
         (account_id,operation_id,request_hash,attribute_id,action,attribute_revision,grant_version,occurred_at) \
         SELECT ?1,?2,?3,'name','share',?4,version,?5 FROM vault_attribute_grant \
         WHERE account_id=?1 AND attribute_id='name' AND recipient_service='userinfo' \
         AND purpose='oidc.userinfo.name' AND envelope_id=?2",
    ).bind(&[
        JsValue::from_str(&owner.account_id), JsValue::from_str(&operation),
        JsValue::from_str(&hash), JsValue::from_f64(expected as f64),
        JsValue::from_f64(now as f64),
    ])?;
    if db.batch(vec![envelope, guard, grant, audit]).await.is_err() {
        if share_audit(&db, &owner.account_id, &operation)
            .await?
            .is_some()
        {
            return error(409, "operation_id_reused");
        }
        return error(409, "share_conflict");
    }
    let Some(audit) = share_audit(&db, &owner.account_id, &operation).await? else {
        return error(503, "storage_unavailable");
    };
    Response::builder()
        .with_header("Cache-Control", "no-store")?
        .from_json(&ShareResult {
            grant_version: audit.grant_version,
            attribute_revision: expected,
        })
}

pub async fn revoke_share(request: Request, context: RouteContext<()>) -> worker::Result<Response> {
    if context.env.bucket("VAULT_BLOBS").is_err() {
        return error(404, "not_found");
    }
    if !same_origin(&request)? {
        return error(403, "origin_required");
    }
    let Some(expected_version) = expected_revision(&request)?.filter(|version| *version > 0) else {
        return error(428, "precondition_required");
    };
    let Some(operation) = operation_id(&request)? else {
        return error(400, "operation_id_required");
    };
    let hash = request_hash("REVOKE", "name", expected_version, &[]);
    let db = context.env.d1("DB")?;
    let Some(owner) = owner(&request, &db).await? else {
        return error(401, "authentication_required");
    };
    if !owner_allowed(&owner.account_id, "name", vault_authzen::REVOKE_SYSTEM) {
        return error(403, "access_denied");
    }
    if let Some(previous) = share_audit(&db, &owner.account_id, &operation).await? {
        return if previous.request_hash == hash && previous.action == "revoke" {
            Response::builder()
                .with_header("Cache-Control", "no-store")?
                .from_json(&ShareResult {
                    grant_version: previous.grant_version,
                    attribute_revision: previous.attribute_revision,
                })
        } else {
            error(409, "operation_id_reused")
        };
    }
    let now = now_seconds().ok_or_else(|| worker::Error::RustError("server_error".into()))? as i64;
    let update = db
        .prepare(
            "UPDATE vault_attribute_grant SET status='revoked',version=version+1,updated_at=?1 \
         WHERE account_id=?2 AND attribute_id='name' AND recipient_service='userinfo' \
         AND purpose='oidc.userinfo.name' AND version=?3 AND status='active' \
         AND EXISTS (SELECT 1 FROM sso_context sx JOIN sso_session ss ON ss.sso_id=sx.sso_id \
           JOIN account_security a ON a.account_id=ss.account_id \
           JOIN credential c ON c.credential_id=ss.credential_id AND c.account_id=ss.account_id \
           WHERE sx.secret_hash=?4 AND ss.account_id=?2 AND ss.revoked=0 AND ss.expires_at>?1 \
           AND a.active=1 AND a.epoch=ss.epoch AND c.active=1)",
        )
        .bind(&[
            JsValue::from_f64(now as f64),
            JsValue::from_str(&owner.account_id),
            JsValue::from_f64(expected_version as f64),
            JsValue::from_str(&owner.secret_hash),
        ])?;
    let guard = db
        .prepare(
            "INSERT INTO vault_share_atomic_guard(operation_id,passed) \
         VALUES(?1,CASE WHEN changes()=1 THEN 1 ELSE 0 END)",
        )
        .bind(&[JsValue::from_str(&operation)])?;
    let audit = db.prepare(
        "INSERT INTO vault_attribute_share_audit \
         (account_id,operation_id,request_hash,attribute_id,action,attribute_revision,grant_version,occurred_at) \
         SELECT ?1,?2,?3,'name','revoke',attribute_revision,version,?4 \
         FROM vault_attribute_grant WHERE account_id=?1 AND attribute_id='name' \
         AND recipient_service='userinfo' AND purpose='oidc.userinfo.name' \
         AND version=?5 AND status='revoked'",
    ).bind(&[
        JsValue::from_str(&owner.account_id), JsValue::from_str(&operation),
        JsValue::from_str(&hash), JsValue::from_f64(now as f64),
        JsValue::from_f64((expected_version + 1) as f64),
    ])?;
    if db.batch(vec![update, guard, audit]).await.is_err() {
        if share_audit(&db, &owner.account_id, &operation)
            .await?
            .is_some()
        {
            return error(409, "operation_id_reused");
        }
        return error(409, "share_conflict");
    }
    let Some(audit) = share_audit(&db, &owner.account_id, &operation).await? else {
        return error(503, "storage_unavailable");
    };
    Response::builder()
        .with_header("Cache-Control", "no-store")?
        .from_json(&ShareResult {
            grant_version: audit.grant_version,
            attribute_revision: audit.attribute_revision,
        })
}
