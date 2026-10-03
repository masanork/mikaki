//! Explicit v2 saved-name sharing. The OP handles only ciphertext and routing metadata.
use crate::vault_attributes::{
    Owner, error, expected_revision, operation_id, owner, owner_allowed, request_hash, same_origin,
};
use crate::{conformance_deployment, read_bounded_body, vault_authzen};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use wasm_bindgen::JsValue;
use worker::{D1Database, Request, Response, RouteContext};

pub(crate) const SUITE: &str = "ML-KEM-768-HKDF-SHA256-AES-256-GCM-draft04-record-v2";
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Source {
    pub storage_version: u8,
    pub origin: String,
    pub owner_id: String,
    pub vault_id: String,
    pub collection_id: String,
    pub record_id: String,
    pub kind: String,
    pub revision: i64,
    pub ciphertext_sha256: String,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Authority {
    pub key_generation: i64,
    pub owner_key_revision: i64,
}
impl Source {
    pub fn valid(&self, account: &str, origin: &str) -> bool {
        self.storage_version == 2
            && self.owner_id == account
            && self.origin == origin
            && self.origin.starts_with("https://")
            && identifier(&self.vault_id)
            && self.collection_id == "personal"
            && self.record_id == "name"
            && self.kind == "name"
            && positive(self.revision)
            && decode(&self.ciphertext_sha256, 32).is_some()
    }
}
impl Authority {
    pub fn valid(&self) -> bool {
        positive(self.key_generation) && positive(self.owner_key_revision)
    }
}
fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
fn positive(n: i64) -> bool {
    (1..=9_007_199_254_740_991).contains(&n)
}
fn decode(s: &str, n: usize) -> Option<Vec<u8>> {
    if s.len() != (n * 4).div_ceil(3) {
        return None;
    }
    let b = URL_SAFE_NO_PAD.decode(s).ok()?;
    (b.len() == n && URL_SAFE_NO_PAD.encode(&b) == s).then_some(b)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ShareBody {
    source: Source,
    authority: Authority,
    key_id: String,
    generation: i64,
    directory_revision: i64,
    policy_revision: i64,
    expected_grant_version: i64,
    frame: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RevokeBody {
    source: Source,
    authority: Authority,
}
#[derive(Deserialize)]
struct Policy {
    enabled: i64,
    grant_ttl_seconds: i64,
    revision: i64,
}
#[derive(Deserialize)]
struct Head {
    object_key: String,
}
#[derive(Deserialize)]
struct Audit {
    request_hash: String,
    action: String,
    grant_version: i64,
    record_revision: i64,
}
#[derive(Deserialize)]
struct Recipient {
    key_id: String,
    public_key: Vec<u8>,
    generation: i64,
    revision: i64,
}
async fn audit(db: &D1Database, account: &str, operation: &str) -> worker::Result<Option<Audit>> {
    db.prepare("SELECT a.request_hash,a.action,a.grant_version,e.record_revision FROM vault_record_share_audit a JOIN vault_record_recipient_envelope e ON e.envelope_id=a.envelope_id AND e.account_id=a.account_id WHERE a.account_id=?1 AND a.operation_id=?2")
 .bind(&[JsValue::from_str(account),JsValue::from_str(operation)])?.first::<Audit>(None).await
}
fn result(a: &Audit) -> worker::Result<Response> {
    Response::builder().with_header("Cache-Control","no-store")?.from_json(&serde_json::json!({"grant_version":a.grant_version,"record_revision":a.record_revision,"acknowledged":true}))
}
pub async fn recipient(request: Request, context: RouteContext<()>) -> worker::Result<Response> {
    let db = context.env.d1("DB")?;
    if owner(&request, &db).await?.is_none() {
        return error(401, "authentication_required");
    }
    let key=db.prepare("SELECT key_id,public_key,generation,revision FROM vault_recipient_key WHERE service_id='userinfo' AND algorithm='ML-KEM-768' AND state='active'").first::<Recipient>(None).await?;
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
    let verified = claims
        .fetch(
            format!(
                "https://userinfo.internal/internal/recipient-keys/{}/verify",
                key.key_id
            ),
            None,
        )
        .await;
    if !matches!(verified,Ok(response) if response.status_code()==204) {
        return error(503, "recipient_unavailable");
    }
    let current=db.prepare("SELECT 1 AS present FROM vault_recipient_key WHERE key_id=?1 AND generation=?2 AND revision=?3 AND state='active'").bind(&[JsValue::from_str(&key.key_id),JsValue::from_f64(key.generation as f64),JsValue::from_f64(key.revision as f64)])?.first::<serde_json::Value>(None).await?;
    if current.is_none() {
        return error(503, "recipient_unavailable");
    }
    Response::builder().with_header("Cache-Control","no-store")?.from_json(&serde_json::json!({"service_id":"userinfo","algorithm":"ML-KEM-768","envelope_suite":SUITE,"key_id":key.key_id,"public_key":URL_SAFE_NO_PAD.encode(&key.public_key),"generation":key.generation,"revision":key.revision}))
}
pub async fn status(request: Request, context: RouteContext<()>) -> worker::Result<Response> {
    let db = context.env.d1("DB")?;
    let Some(owner) = owner(&request, &db).await? else {
        return error(401, "authentication_required");
    };
    let policy = db
        .prepare(
            "SELECT enabled,grant_ttl_seconds,revision FROM vault_record_share_policy WHERE id=1",
        )
        .first::<Policy>(None)
        .await?;
    let Some(policy) = policy else {
        return error(503, "policy_unavailable");
    };
    let grant = db
        .prepare(include_str!("../sql/select-record-share-status.sql"))
        .bind(&[JsValue::from_str(&owner.account_id)])?
        .first::<serde_json::Value>(None)
        .await?;
    Response::builder().with_header("Cache-Control","no-store")?.from_json(&serde_json::json!({"enabled":policy.enabled==1&&!conformance_deployment(&context.env)?,"policy_revision":policy.revision,"grant_ttl_seconds":policy.grant_ttl_seconds,"grant":grant}))
}

// Shared with RP consent: no root or key envelope is included in this query/result.
pub(crate) const LIVE_SOURCE: &str = include_str!("../sql/select-record-share-source.sql");
pub(crate) fn source_params(source: &Source, authority: &Authority, owner: &Owner) -> Vec<JsValue> {
    vec![
        JsValue::from_str(&source.owner_id),
        JsValue::from_str(&source.origin),
        JsValue::from_str(&source.vault_id),
        JsValue::from_str(&source.collection_id),
        JsValue::from_str(&source.record_id),
        JsValue::from_str(&source.kind),
        JsValue::from_f64(source.revision as f64),
        JsValue::from_str(&source.ciphertext_sha256),
        JsValue::from_f64(authority.key_generation as f64),
        JsValue::from_f64(authority.owner_key_revision as f64),
        JsValue::from_str(&owner.credential_id),
        JsValue::from_str(&owner.secret_hash),
    ]
}
pub async fn share(mut request: Request, context: RouteContext<()>) -> worker::Result<Response> {
    if conformance_deployment(&context.env)? {
        return error(403, "sharing_disabled");
    }
    if !same_origin(&request)? {
        return error(403, "origin_required");
    }
    let Some(expected) = expected_revision(&request)?.filter(|n| positive(*n)) else {
        return error(428, "precondition_required");
    };
    let Some(operation) = operation_id(&request)? else {
        return error(400, "operation_id_required");
    };
    if request.headers().get("Content-Type")?.as_deref() != Some("application/json") {
        return error(415, "json_required");
    }
    let body = match read_bounded_body(&mut request, 8192).await {
        Ok(body) => body,
        Err(_) => return error(413, "body_too_large_or_invalid"),
    };
    let hash = request_hash("SHARE_RECORD", "personal/name", expected, body.as_bytes());
    let db = context.env.d1("DB")?;
    let Some(owner) = owner(&request, &db).await? else {
        return error(401, "authentication_required");
    };
    if !owner_allowed(&owner.account_id, "name", vault_authzen::SHARE_SYSTEM) {
        return error(403, "access_denied");
    }
    if let Some(old) = audit(&db, &owner.account_id, &operation).await? {
        return if old.request_hash == hash && old.action == "share" {
            result(&old)
        } else {
            error(409, "operation_id_reused")
        };
    }
    let Ok(value) = serde_json::from_str::<ShareBody>(&body) else {
        return error(400, "invalid_body");
    };
    let origin = request.url()?.origin().ascii_serialization();
    if !value.source.valid(&owner.account_id, &origin)
        || !value.authority.valid()
        || value.source.revision != expected
        || !positive(value.generation)
        || !positive(value.directory_revision)
        || !positive(value.policy_revision)
        || value.expected_grant_version < 0
        || value.expected_grant_version >= 9_007_199_254_740_991
    {
        return error(400, "invalid_body");
    }
    let Some(frame) = decode(&value.frame, 1187) else {
        return error(400, "invalid_envelope");
    };
    let Some(key_id) = decode(&value.key_id, 32) else {
        return error(400, "invalid_envelope");
    };
    if &frame[..5] != b"MKVR\x02"
        || frame[5..11] != [0, 0x41, 0, 1, 0, 2]
        || frame[11..43] != key_id
        || frame[43..51] != (value.generation as u64).to_be_bytes()
    {
        return error(400, "invalid_envelope");
    }
    let policy = db
        .prepare(
            "SELECT enabled,grant_ttl_seconds,revision FROM vault_record_share_policy WHERE id=1",
        )
        .first::<Policy>(None)
        .await?;
    let Some(policy) = policy.filter(|p| p.enabled == 1 && p.revision == value.policy_revision)
    else {
        return error(403, "sharing_disabled_or_changed");
    };
    let params = source_params(&value.source, &value.authority, &owner);
    let head = db
        .prepare(format!("SELECT h.object_key {LIVE_SOURCE}"))
        .bind(&params)?
        .first::<Head>(None)
        .await?;
    let Some(head) = head else {
        return error(409, "source_changed");
    };
    let Some(object) = context
        .env
        .bucket("VAULT_BLOBS")?
        .get(&head.object_key)
        .execute()
        .await?
    else {
        return error(503, "storage_unavailable");
    };
    let Some(blob) = object.body() else {
        return error(503, "storage_unavailable");
    };
    let ciphertext = blob.bytes().await?;
    if ciphertext.len() < 29
        || ciphertext.len() > 24 * 1024
        || ciphertext[0] != 2
        || URL_SAFE_NO_PAD.encode(Sha256::digest(&ciphertext)) != value.source.ciphertext_sha256
    {
        return error(503, "storage_unavailable");
    }
    let Ok(claims) = context.env.service("USERINFO_CLAIMS") else {
        return error(503, "recipient_unavailable");
    };
    let validation=serde_json::json!({"source":value.source,"authority":value.authority,"ciphertext":URL_SAFE_NO_PAD.encode(ciphertext),"frame":value.frame}).to_string();
    let mut init = worker::RequestInit::new();
    init.with_method(worker::Method::Post)
        .with_body(Some(JsValue::from_str(&validation)));
    init.headers.set("Content-Type", "application/json")?;
    if !matches!(claims.fetch(format!("https://userinfo.internal/internal/recipient-keys/{}/validate-record-envelope",value.key_id),Some(init)).await,Ok(response) if response.status_code()==204)
    {
        return error(503, "recipient_unavailable");
    }
    let mut params = params;
    params.extend([
        JsValue::from_str(&operation),
        JsValue::from_str(&value.key_id),
        JsValue::from_f64(value.generation as f64),
        JsValue::from_f64(value.directory_revision as f64),
        JsValue::from_f64(value.policy_revision as f64),
        JsValue::from(frame),
        JsValue::from_f64(value.expected_grant_version as f64),
    ]);
    let envelope = db
        .prepare(
            include_str!("../sql/commit-record-recipient-envelope.sql")
                .replace("{LIVE_SOURCE}", LIVE_SOURCE)
                .replace("{SUITE}", SUITE),
        )
        .bind(&params)?;
    let guard = |suffix: &str| {
        db.prepare("INSERT INTO vault_record_share_guard(account_id,operation_id,passed) VALUES(?1,?2,CASE WHEN changes()=1 THEN 1 ELSE 0 END)").bind(&[JsValue::from_str(&owner.account_id),JsValue::from_str(&format!("{operation}:{suffix}"))])
    };
    let grant = db
        .prepare(include_str!("../sql/commit-record-recipient-grant.sql"))
        .bind(&[
            JsValue::from_str(&owner.account_id),
            JsValue::from_str(&operation),
            JsValue::from_f64(policy.grant_ttl_seconds as f64),
        ])?;
    let record_audit = db
        .prepare(include_str!("../sql/commit-record-share-audit.sql"))
        .bind(&[
            JsValue::from_str(&owner.account_id),
            JsValue::from_str(&operation),
            JsValue::from_str(&hash),
        ])?;
    if db
        .batch(vec![
            envelope,
            guard("envelope")?,
            grant,
            guard("grant")?,
            record_audit,
            guard("audit")?,
        ])
        .await
        .is_err()
    {
        if let Some(previous) = audit(&db, &owner.account_id, &operation).await? {
            if previous.request_hash == hash && previous.action == "share" {
                return result(&previous);
            }
        }
        return error(409, "share_conflict");
    }
    let Some(accepted) = audit(&db, &owner.account_id, &operation).await? else {
        return error(503, "storage_unavailable");
    };
    result(&accepted)
}

pub async fn revoke(mut request: Request, context: RouteContext<()>) -> worker::Result<Response> {
    if !same_origin(&request)? {
        return error(403, "origin_required");
    }
    let Some(expected) =
        expected_revision(&request)?.filter(|n| (1..9_007_199_254_740_991).contains(n))
    else {
        return error(428, "precondition_required");
    };
    let Some(operation) = operation_id(&request)? else {
        return error(400, "operation_id_required");
    };
    if request.headers().get("Content-Type")?.as_deref() != Some("application/json") {
        return error(415, "json_required");
    }
    let body = match read_bounded_body(&mut request, 2048).await {
        Ok(b) => b,
        Err(_) => return error(413, "body_too_large_or_invalid"),
    };
    let hash = request_hash("REVOKE_RECORD", "personal/name", expected, body.as_bytes());
    let db = context.env.d1("DB")?;
    let Some(owner) = owner(&request, &db).await? else {
        return error(401, "authentication_required");
    };
    if !owner_allowed(&owner.account_id, "name", vault_authzen::REVOKE_SYSTEM) {
        return error(403, "access_denied");
    }
    if let Some(old) = audit(&db, &owner.account_id, &operation).await? {
        return if old.request_hash == hash && old.action == "revoke" {
            result(&old)
        } else {
            error(409, "operation_id_reused")
        };
    }
    let Ok(value) = serde_json::from_str::<RevokeBody>(&body) else {
        return error(400, "invalid_body");
    };
    if !value.source.valid(
        &owner.account_id,
        &request.url()?.origin().ascii_serialization(),
    ) || !value.authority.valid()
    {
        return error(400, "invalid_body");
    }
    let mut params = source_params(&value.source, &value.authority, &owner);
    params.push(JsValue::from_f64(expected as f64));
    let update = db
        .prepare(include_str!("../sql/revoke-record-recipient-grant.sql"))
        .bind(&params)?;
    let guard=db.prepare("INSERT INTO vault_record_share_guard VALUES(?1,?2,CASE WHEN changes()=1 THEN 1 ELSE 0 END)").bind(&[JsValue::from_str(&owner.account_id),JsValue::from_str(&operation)])?;
    let record_audit=db.prepare("INSERT INTO vault_record_share_audit(account_id,operation_id,request_hash,action,envelope_id,grant_version,occurred_at) SELECT account_id,?2,?3,'revoke',envelope_id,version,unixepoch() FROM vault_record_grant WHERE account_id=?1 AND vault_id=?4 AND collection_id='personal' AND record_id='name' AND recipient_service='userinfo' AND purpose='oidc.userinfo.name' AND version=?5 AND status='revoked'").bind(&[JsValue::from_str(&owner.account_id),JsValue::from_str(&operation),JsValue::from_str(&hash),JsValue::from_str(&value.source.vault_id),JsValue::from_f64((expected+1) as f64)])?;
    let audit_guard=db.prepare("INSERT INTO vault_record_share_guard VALUES(?1,?2,CASE WHEN changes()=1 THEN 1 ELSE 0 END)").bind(&[JsValue::from_str(&owner.account_id),JsValue::from_str(&format!("{operation}:audit"))])?;
    if db
        .batch(vec![update, guard, record_audit, audit_guard])
        .await
        .is_err()
    {
        if let Some(previous) = audit(&db, &owner.account_id, &operation).await? {
            if previous.request_hash == hash && previous.action == "revoke" {
                return result(&previous);
            }
        }
        return error(409, "share_conflict");
    }
    let Some(accepted) = audit(&db, &owner.account_id, &operation).await? else {
        return error(503, "storage_unavailable");
    };
    result(&accepted)
}
