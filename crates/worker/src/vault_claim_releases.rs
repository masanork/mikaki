//! Owner-managed RP claim consent. This does not release plaintext to UserInfo.

use serde::Deserialize;
use wasm_bindgen::JsValue;
use worker::{D1Database, Request, Response, RouteContext};

use crate::vault_http::{
    error, expected_revision, operation_id, owner, owner_allowed, request_hash, same_origin,
};
use crate::{conformance_deployment, now_seconds, read_bounded_body, vault_authzen};

#[derive(Deserialize)]
struct ReleasePolicy {
    enabled: i64,
    revision: i64,
}

#[derive(Deserialize)]
struct ReleaseAudit {
    request_hash: String,
    client_id: String,
    action: String,
    release_version: i64,
}

fn valid_client_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && !value.bytes().any(|byte| byte.is_ascii_control())
}

async fn policy(db: &D1Database) -> worker::Result<ReleasePolicy> {
    db.prepare("SELECT enabled,revision FROM vault_claim_release_policy WHERE id=1")
        .first::<ReleasePolicy>(None)
        .await?
        .ok_or_else(|| worker::Error::RustError("claim_release_policy_unavailable".into()))
}

async fn audit(
    db: &D1Database,
    account: &str,
    operation: &str,
) -> worker::Result<Option<ReleaseAudit>> {
    db.prepare(
        "SELECT request_hash,client_id,action,release_version \
         FROM vault_claim_release_audit WHERE account_id=?1 AND operation_id=?2",
    )
    .bind(&[JsValue::from_str(account), JsValue::from_str(operation)])?
    .first::<ReleaseAudit>(None)
    .await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordRevokeBody {
    client_id: String,
}

pub async fn revoke_record(
    mut request: Request,
    context: RouteContext<()>,
) -> worker::Result<Response> {
    if context.env.bucket("VAULT_BLOBS").is_err() {
        return error(404, "not_found");
    }
    if !same_origin(&request)? {
        return error(403, "origin_required");
    }
    let Some(expected) = expected_revision(&request)?.filter(|version| *version > 0) else {
        return error(428, "precondition_required");
    };
    let Some(operation) = operation_id(&request)? else {
        return error(400, "operation_id_required");
    };
    if request.headers().get("Content-Type")?.as_deref() != Some("application/json") {
        return error(415, "json_required");
    }
    let body = match read_bounded_body(&mut request, 512).await {
        Ok(body) => body,
        Err(_) => return error(413, "body_too_large_or_invalid"),
    };
    let hash = request_hash("REVOKE_RP", "name", expected, body.as_bytes());
    let db = context.env.d1("DB")?;
    let Some(owner) = owner(&request, &db).await? else {
        return error(401, "authentication_required");
    };
    if !owner_allowed(&owner.account_id, "name", vault_authzen::REVOKE_RP) {
        return error(403, "access_denied");
    }
    if let Some(previous) = audit(&db, &owner.account_id, &operation).await? {
        return if previous.request_hash == hash && previous.action == "revoke" {
            record_result(&previous)
        } else {
            error(409, "operation_id_reused")
        };
    }
    let Ok(value) = serde_json::from_str::<RecordRevokeBody>(&body) else {
        return error(400, "invalid_body");
    };
    if !valid_client_id(&value.client_id) {
        return error(400, "invalid_body");
    }
    let now = now_seconds().ok_or_else(|| worker::Error::RustError("server_error".into()))? as i64;
    let statement = db
        .prepare(
            "UPDATE vault_claim_release SET status='revoked',version=version+1,updated_at=?1 \
         WHERE account_id=?2 AND client_id=?3 AND claim='name' \
           AND version=?4 AND status='active' AND source_storage_version=2 \
           AND EXISTS (SELECT 1 FROM sso_context sx \
             JOIN sso_session ss ON ss.sso_id=sx.sso_id \
             JOIN account_security a ON a.account_id=ss.account_id \
             JOIN credential cr ON cr.credential_id=ss.credential_id \
               AND cr.account_id=ss.account_id \
             WHERE sx.secret_hash=?5 AND ss.account_id=?2 AND ss.revoked=0 \
               AND ss.expires_at>?1 AND a.active=1 AND a.epoch=ss.epoch AND cr.active=1)",
        )
        .bind(&[
            JsValue::from_f64(now as f64),
            JsValue::from_str(&owner.account_id),
            JsValue::from_str(&value.client_id),
            JsValue::from_f64(expected as f64),
            JsValue::from_str(&owner.secret_hash),
        ])?;
    let guard = db
        .prepare(
            "INSERT INTO vault_claim_release_atomic_guard(operation_id,passed) \
         VALUES(?1,CASE WHEN changes()=1 THEN 1 ELSE 0 END)",
        )
        .bind(&[JsValue::from_str(&operation)])?;
    let audit_statement = db
        .prepare(
            "INSERT INTO vault_claim_release_audit \
         (account_id,operation_id,request_hash,client_id,claim,action,release_version,occurred_at,source_storage_version,source_json) \
         SELECT ?1,?2,?3,?4,'name','revoke',version,?5,source_storage_version, \
         CASE WHEN source_storage_version=2 THEN json_object('storage_version',2,'owner_id',account_id,'origin',source_origin,'vault_id',source_vault_id, \
         'collection_id',source_collection_id,'record_id',source_record_id,'kind',source_kind, \
         'revision',attribute_revision,'ciphertext_sha256',source_ciphertext_sha256, \
         'key_generation',source_key_generation,'owner_key_revision',source_owner_key_revision) ELSE NULL END FROM vault_claim_release \
         WHERE account_id=?1 AND client_id=?4 AND claim='name' \
           AND version=?6 AND status='revoked'",
        )
        .bind(&[
            JsValue::from_str(&owner.account_id),
            JsValue::from_str(&operation),
            JsValue::from_str(&hash),
            JsValue::from_str(&value.client_id),
            JsValue::from_f64(now as f64),
            JsValue::from_f64((expected + 1) as f64),
        ])?;
    if db
        .batch(vec![statement, guard, audit_statement])
        .await
        .is_err()
    {
        return error(409, "release_conflict");
    }
    let Some(audit) = audit(&db, &owner.account_id, &operation).await? else {
        return error(503, "storage_unavailable");
    };
    record_result(&audit)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordGrantBody {
    expected_release_version: i64,
    source: crate::vault_record_sharing::Source,
    authority: crate::vault_record_sharing::Authority,
    client_id: String,
    client_revision: i64,
    connection_grant_version: i64,
    policy_revision: i64,
}

fn record_result(value: &ReleaseAudit) -> worker::Result<Response> {
    Response::builder().with_header("Cache-Control", "no-store")?.from_json(&serde_json::json!({
        "client_id": value.client_id, "release_version": value.release_version, "acknowledged": true,
    }))
}

// Consent still lives in vault_claim_release: this action explicitly replaces
// that RP's selected source. Merely having a v2 saved name never selects it.
pub async fn grant_record(
    mut request: Request,
    context: RouteContext<()>,
) -> worker::Result<Response> {
    if conformance_deployment(&context.env)? {
        return error(403, "release_disabled");
    }
    if !same_origin(&request)? {
        return error(403, "origin_required");
    }
    let Some(expected) = expected_revision(&request)?.filter(|n| *n > 0) else {
        return error(428, "precondition_required");
    };
    let Some(operation) = operation_id(&request)? else {
        return error(400, "operation_id_required");
    };
    if request.headers().get("Content-Type")?.as_deref() != Some("application/json") {
        return error(415, "json_required");
    }
    let body = match read_bounded_body(&mut request, 4096).await {
        Ok(b) => b,
        Err(_) => return error(413, "body_too_large_or_invalid"),
    };
    let hash = request_hash(
        "GRANT_RECORD_RP",
        "personal/name",
        expected,
        body.as_bytes(),
    );
    let db = context.env.d1("DB")?;
    let Some(owner) = owner(&request, &db).await? else {
        return error(401, "authentication_required");
    };
    if !owner_allowed(&owner.account_id, "name", vault_authzen::GRANT_RP) {
        return error(403, "access_denied");
    }
    if let Some(previous) = audit(&db, &owner.account_id, &operation).await? {
        return if previous.request_hash == hash && previous.action == "grant" {
            record_result(&previous)
        } else {
            error(409, "operation_id_reused")
        };
    }
    let Ok(value) = serde_json::from_str::<RecordGrantBody>(&body) else {
        return error(400, "invalid_body");
    };
    if !value.source.valid(
        &owner.account_id,
        &request.url()?.origin().ascii_serialization(),
    ) || !value.authority.valid()
        || !valid_client_id(&value.client_id)
        || value.client_revision < 0
        || value.connection_grant_version < 0
        || value.policy_revision < 1
        || value.client_revision > 9_007_199_254_740_991
        || value.connection_grant_version > 9_007_199_254_740_991
        || value.policy_revision > 9_007_199_254_740_991
        || value.expected_release_version < 0
        || value.expected_release_version >= 9_007_199_254_740_991
        || expected > 9_007_199_254_740_991
    {
        return error(400, "invalid_body");
    }
    let mut params =
        crate::vault_record_sharing::source_params(&value.source, &value.authority, &owner);
    params.extend([
        JsValue::from_str(&value.client_id),
        JsValue::from_f64(value.client_revision as f64),
        JsValue::from_f64(value.connection_grant_version as f64),
        JsValue::from_f64(value.policy_revision as f64),
        JsValue::from_f64(expected as f64),
        JsValue::from_f64(value.expected_release_version as f64),
    ]);
    let statement = db
        .prepare(
            include_str!("../sql/commit-record-claim-release.sql")
                .replace("{LIVE_SOURCE}", crate::vault_record_sharing::LIVE_SOURCE),
        )
        .bind(&params)?;
    let guard=db.prepare("INSERT INTO vault_claim_release_atomic_guard(operation_id,passed) VALUES(?1,CASE WHEN changes()=1 THEN 1 ELSE 0 END)").bind(&[JsValue::from_str(&operation)])?;
    let source_json =
        serde_json::json!({"source":value.source,"authority":value.authority}).to_string();
    let audit_statement=db.prepare("INSERT INTO vault_claim_release_audit(account_id,operation_id,request_hash,client_id,claim,action,release_version,occurred_at,source_storage_version,source_json) SELECT ?1,?2,?3,?4,'name','grant',version,unixepoch(),2,?5 FROM vault_claim_release WHERE account_id=?1 AND client_id=?4 AND claim='name' AND status='active' AND source_storage_version=2").bind(&[JsValue::from_str(&owner.account_id),JsValue::from_str(&operation),JsValue::from_str(&hash),JsValue::from_str(&value.client_id),JsValue::from_str(&source_json)])?;
    let audit_guard=db.prepare("INSERT INTO vault_claim_release_atomic_guard(operation_id,passed) VALUES(?1,CASE WHEN changes()=1 THEN 1 ELSE 0 END)").bind(&[JsValue::from_str(&format!("{operation}:audit"))])?;
    if db
        .batch(vec![statement, guard, audit_statement, audit_guard])
        .await
        .is_err()
    {
        if let Some(previous) = audit(&db, &owner.account_id, &operation).await?
            && previous.request_hash == hash
            && previous.action == "grant"
        {
            return record_result(&previous);
        }
        return error(409, "release_conflict");
    }
    let Some(accepted) = audit(&db, &owner.account_id, &operation).await? else {
        return error(503, "storage_unavailable");
    };
    record_result(&accepted)
}

pub async fn status_record(
    request: Request,
    context: RouteContext<()>,
) -> worker::Result<Response> {
    let db = context.env.d1("DB")?;
    let Some(owner) = owner(&request, &db).await? else {
        return error(401, "authentication_required");
    };
    let policy = policy(&db).await?;
    let share = db
        .prepare("SELECT enabled FROM vault_record_share_policy WHERE id=1")
        .first::<serde_json::Value>(None)
        .await?;
    let clients=db.prepare("SELECT c.client_id,c.sector_identifier,c.revision AS client_revision,a.grant_version AS connection_grant_version,r.version AS release_version,r.status AS release_status,r.expires_at,r.source_storage_version,r.source_origin,r.source_vault_id,r.source_collection_id,r.source_record_id,r.source_kind,r.attribute_revision,r.source_ciphertext_sha256,r.source_key_generation,r.source_owner_key_revision,r.system_grant_version FROM app_connection a JOIN client c ON c.client_id=a.client_id LEFT JOIN vault_claim_release r ON r.account_id=a.account_id AND r.client_id=a.client_id AND r.claim='name' WHERE a.account_id=?1 AND a.active=1 AND c.active=1 AND c.auth_method='private_key_jwt' ORDER BY c.client_id LIMIT 100").bind(&[JsValue::from_str(&owner.account_id)])?.all().await?.results::<serde_json::Value>()?;
    Response::builder().with_header("Cache-Control","no-store")?.from_json(&serde_json::json!({"enabled":policy.enabled==1&&share.as_ref().and_then(|p|p.get("enabled")).and_then(serde_json::Value::as_i64)==Some(1)&&!conformance_deployment(&context.env)?,"policy_revision":policy.revision,"clients":clients}))
}
