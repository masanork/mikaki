//! Owner-managed RP claim consent. This does not release plaintext to UserInfo.

use serde::{Deserialize, Serialize};
use wasm_bindgen::JsValue;
use worker::{D1Database, Request, Response, RouteContext};

use crate::vault_attributes::{
    error, expected_revision, operation_id, owner, owner_allowed, request_hash, same_origin,
};
use crate::{conformance_deployment, now_seconds, read_bounded_body, vault_authzen};

#[derive(Deserialize)]
struct ReleasePolicy {
    enabled: i64,
    ttl_seconds: i64,
    revision: i64,
}

#[derive(Deserialize)]
struct SystemGrant {
    version: i64,
    attribute_revision: i64,
    status: String,
    expires_at: i64,
}

#[derive(Deserialize)]
struct ClientRow {
    client_id: String,
    sector_identifier: String,
    client_revision: i64,
    connection_grant_version: i64,
    release_version: Option<i64>,
    release_status: Option<String>,
    release_expires_at: Option<i64>,
    release_system_grant_version: Option<i64>,
    release_attribute_revision: Option<i64>,
    release_client_revision: Option<i64>,
    release_connection_grant_version: Option<i64>,
}

#[derive(Serialize)]
struct ClientStatus {
    client_id: String,
    sector_identifier: String,
    client_revision: i64,
    connection_grant_version: i64,
    release_active: bool,
    release_version: Option<i64>,
    expires_at: Option<i64>,
}

#[derive(Serialize)]
struct ReleaseStatus {
    enabled: bool,
    ttl_seconds: i64,
    policy_revision: i64,
    share_active: bool,
    share_grant_version: Option<i64>,
    clients: Vec<ClientStatus>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantBody {
    client_id: String,
    client_revision: i64,
    connection_grant_version: i64,
    policy_revision: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RevokeBody {
    client_id: String,
}

#[derive(Deserialize)]
struct ReleaseAudit {
    request_hash: String,
    client_id: String,
    action: String,
    release_version: i64,
}

#[derive(Serialize)]
struct ReleaseResult<'a> {
    client_id: &'a str,
    release_version: i64,
    active: bool,
}

fn valid_client_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && !value.bytes().any(|byte| byte.is_ascii_control())
}

async fn policy(db: &D1Database) -> worker::Result<ReleasePolicy> {
    db.prepare("SELECT enabled,ttl_seconds,revision FROM vault_claim_release_policy WHERE id=1")
        .first::<ReleasePolicy>(None)
        .await?
        .ok_or_else(|| worker::Error::RustError("claim_release_policy_unavailable".into()))
}

async fn system_grant(db: &D1Database, account: &str) -> worker::Result<Option<SystemGrant>> {
    db.prepare(
        "SELECT g.version,g.attribute_revision,g.status,g.expires_at \
         FROM vault_attribute_grant g \
         JOIN vault_attribute_recipient_envelope e ON e.envelope_id=g.envelope_id \
         JOIN vault_attribute_head h ON h.account_id=g.account_id AND h.attribute_id=g.attribute_id \
         JOIN vault_recipient_key k ON k.key_id=e.recipient_key_id \
         WHERE g.account_id=?1 AND g.attribute_id='name' AND g.recipient_service='userinfo' \
         AND g.purpose='oidc.userinfo.name' AND h.deleted=0 \
         AND h.revision=g.attribute_revision AND e.attribute_revision=g.attribute_revision \
         AND h.ciphertext_sha256=e.ciphertext_sha256 \
         AND k.state='active'",
    )
    .bind(&[JsValue::from_str(account)])?
    .first::<SystemGrant>(None)
    .await
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

fn result(value: &ReleaseAudit, active: bool) -> worker::Result<Response> {
    Response::builder()
        .with_header("Cache-Control", "no-store")?
        .from_json(&ReleaseResult {
            client_id: &value.client_id,
            release_version: value.release_version,
            active,
        })
}

pub async fn status(request: Request, context: RouteContext<()>) -> worker::Result<Response> {
    if context.env.bucket("VAULT_BLOBS").is_err() {
        return error(404, "not_found");
    }
    let db = context.env.d1("DB")?;
    let Some(owner) = owner(&request, &db).await? else {
        return error(401, "authentication_required");
    };
    let policy = policy(&db).await?;
    let share_policy = db
        .prepare("SELECT enabled FROM vault_share_policy WHERE id=1")
        .first::<serde_json::Value>(None)
        .await?;
    let share_enabled = share_policy
        .and_then(|value| value.get("enabled").and_then(serde_json::Value::as_i64))
        == Some(1);
    let grant = system_grant(&db, &owner.account_id).await?;
    let now = now_seconds().ok_or_else(|| worker::Error::RustError("server_error".into()))? as i64;
    let share_active = share_enabled
        && grant
            .as_ref()
            .is_some_and(|grant| grant.status == "active" && grant.expires_at > now);
    let rows = db.prepare(
        "SELECT c.client_id,c.sector_identifier,c.revision AS client_revision, \
         ac.grant_version AS connection_grant_version, \
         r.version AS release_version,r.status AS release_status,r.expires_at AS release_expires_at, \
         r.system_grant_version AS release_system_grant_version, \
         r.attribute_revision AS release_attribute_revision, \
         r.client_revision AS release_client_revision, \
         r.connection_grant_version AS release_connection_grant_version \
         FROM app_connection ac JOIN client c ON c.client_id=ac.client_id \
         LEFT JOIN vault_claim_release r ON r.account_id=ac.account_id \
           AND r.client_id=ac.client_id AND r.claim='name' \
         WHERE ac.account_id=?1 AND ac.active=1 AND c.active=1 \
           AND c.auth_method='private_key_jwt' \
         ORDER BY c.client_id LIMIT 100",
    ).bind(&[JsValue::from_str(&owner.account_id)])?
        .all().await?.results::<ClientRow>()?;
    let clients = rows
        .into_iter()
        .map(|row| ClientStatus {
            release_active: policy.enabled == 1
                && share_active
                && row.release_status.as_deref() == Some("active")
                && row.release_expires_at.is_some_and(|expiry| expiry > now)
                && row.release_system_grant_version == grant.as_ref().map(|grant| grant.version)
                && row.release_attribute_revision
                    == grant.as_ref().map(|grant| grant.attribute_revision)
                && row.release_client_revision == Some(row.client_revision)
                && row.release_connection_grant_version == Some(row.connection_grant_version),
            client_id: row.client_id,
            sector_identifier: row.sector_identifier,
            client_revision: row.client_revision,
            connection_grant_version: row.connection_grant_version,
            release_version: row.release_version,
            expires_at: row.release_expires_at,
        })
        .collect();
    Response::builder()
        .with_header("Cache-Control", "no-store")?
        .from_json(&ReleaseStatus {
            enabled: policy.enabled == 1 && !conformance_deployment(&context.env)?,
            ttl_seconds: policy.ttl_seconds,
            policy_revision: policy.revision,
            share_active,
            share_grant_version: grant.as_ref().map(|grant| grant.version),
            clients,
        })
}

pub async fn grant(mut request: Request, context: RouteContext<()>) -> worker::Result<Response> {
    if context.env.bucket("VAULT_BLOBS").is_err() {
        return error(404, "not_found");
    }
    if conformance_deployment(&context.env)? {
        return error(403, "release_disabled");
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
    let body = match read_bounded_body(&mut request, 1024).await {
        Ok(body) => body,
        Err(_) => return error(413, "body_too_large_or_invalid"),
    };
    let hash = request_hash("GRANT_RP", "name", expected, body.as_bytes());
    let db = context.env.d1("DB")?;
    let Some(owner) = owner(&request, &db).await? else {
        return error(401, "authentication_required");
    };
    if !owner_allowed(&owner.account_id, "name", vault_authzen::GRANT_RP) {
        return error(403, "access_denied");
    }
    if let Some(previous) = audit(&db, &owner.account_id, &operation).await? {
        return if previous.request_hash == hash && previous.action == "grant" {
            result(&previous, true)
        } else {
            error(409, "operation_id_reused")
        };
    }
    let Ok(value) = serde_json::from_str::<GrantBody>(&body) else {
        return error(400, "invalid_body");
    };
    if !valid_client_id(&value.client_id)
        || value.client_revision < 0
        || value.connection_grant_version < 0
        || value.policy_revision < 1
    {
        return error(400, "invalid_body");
    }
    let policy = policy(&db).await?;
    if policy.enabled != 1 || policy.revision != value.policy_revision {
        return error(403, "release_disabled_or_changed");
    }
    let now = now_seconds().ok_or_else(|| worker::Error::RustError("server_error".into()))? as i64;
    let Some(grant) = system_grant(&db, &owner.account_id).await? else {
        return error(409, "share_required");
    };
    if grant.status != "active" || grant.version != expected || grant.expires_at <= now {
        return error(409, "share_changed");
    }
    let expires_at = (now + policy.ttl_seconds).min(grant.expires_at);
    let statement = db
        .prepare(
            "INSERT INTO vault_claim_release \
         (account_id,client_id,claim,attribute_revision,system_grant_version,client_revision, \
          connection_grant_version,version,status,expires_at,updated_at) \
         SELECT ?1,c.client_id,'name',g.attribute_revision,g.version,c.revision, \
           ac.grant_version,1,'active',?6,?7 \
         FROM client c JOIN app_connection ac ON ac.client_id=c.client_id AND ac.account_id=?1 \
         JOIN vault_attribute_grant g ON g.account_id=?1 AND g.attribute_id='name' \
           AND g.recipient_service='userinfo' AND g.purpose='oidc.userinfo.name' \
         JOIN vault_claim_release_policy rp ON rp.id=1 \
         JOIN vault_share_policy sp ON sp.id=1 \
         WHERE c.client_id=?2 AND c.revision=?4 AND c.active=1 \
           AND c.auth_method='private_key_jwt' AND ac.active=1 AND ac.grant_version=?5 \
           AND g.version=?3 AND g.status='active' AND g.expires_at>=?6 \
           AND rp.enabled=1 AND rp.revision=?8 AND sp.enabled=1 \
           AND EXISTS (SELECT 1 FROM sso_context sx \
             JOIN sso_session ss ON ss.sso_id=sx.sso_id \
             JOIN account_security a ON a.account_id=ss.account_id \
             JOIN credential cr ON cr.credential_id=ss.credential_id \
               AND cr.account_id=ss.account_id \
             WHERE sx.secret_hash=?9 AND ss.account_id=?1 AND ss.revoked=0 \
               AND ss.expires_at>?7 AND a.active=1 AND a.epoch=ss.epoch AND cr.active=1) \
         ON CONFLICT(account_id,client_id,claim) DO UPDATE SET \
           attribute_revision=excluded.attribute_revision, \
           system_grant_version=excluded.system_grant_version, \
           client_revision=excluded.client_revision, \
           connection_grant_version=excluded.connection_grant_version, \
           version=vault_claim_release.version+1,status='active', \
           expires_at=excluded.expires_at,updated_at=excluded.updated_at",
        )
        .bind(&[
            JsValue::from_str(&owner.account_id),
            JsValue::from_str(&value.client_id),
            JsValue::from_f64(expected as f64),
            JsValue::from_f64(value.client_revision as f64),
            JsValue::from_f64(value.connection_grant_version as f64),
            JsValue::from_f64(expires_at as f64),
            JsValue::from_f64(now as f64),
            JsValue::from_f64(policy.revision as f64),
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
         (account_id,operation_id,request_hash,client_id,claim,action,release_version,occurred_at) \
         SELECT ?1,?2,?3,?4,'name','grant',version,?5 FROM vault_claim_release \
         WHERE account_id=?1 AND client_id=?4 AND claim='name' AND status='active'",
        )
        .bind(&[
            JsValue::from_str(&owner.account_id),
            JsValue::from_str(&operation),
            JsValue::from_str(&hash),
            JsValue::from_str(&value.client_id),
            JsValue::from_f64(now as f64),
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
    result(&audit, true)
}

pub async fn revoke(mut request: Request, context: RouteContext<()>) -> worker::Result<Response> {
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
            result(&previous, false)
        } else {
            error(409, "operation_id_reused")
        };
    }
    let Ok(value) = serde_json::from_str::<RevokeBody>(&body) else {
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
           AND version=?4 AND status='active' \
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
         (account_id,operation_id,request_hash,client_id,claim,action,release_version,occurred_at) \
         SELECT ?1,?2,?3,?4,'name','revoke',version,?5 FROM vault_claim_release \
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
    result(&audit, false)
}
