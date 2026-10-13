//! Experimental custom age delivery, bound to authenticated PAR and an exact release.
use super::*;
use mikaki_identity::op_age::{AgeRequest, Error as AgeError};
use worker::{D1Database, D1PreparedStatement};

pub(crate) fn enabled(env: &worker::Env) -> bool {
    claims::enabled(env)
        && env
            .var("IDENTITY_AGE_REQUESTS_ENABLED")
            .is_ok_and(|v| v.to_string() == "true")
}
pub(crate) fn parse(env: &worker::Env, raw: &str, scope: &str) -> Option<AgeRequest> {
    if !enabled(env) || !matches!(scope, "openid profile" | "profile openid") {
        return None;
    }
    AgeRequest::parse_linked(raw.as_bytes()).ok()
}

#[derive(Deserialize)]
pub(crate) struct ReleaseSnapshot {
    document_id: String,
    document_json: String,
    fields_json: String,
    version: i64,
    policy_hash: String,
}
pub(crate) enum AuthorizationSnapshot {
    Granted(ReleaseSnapshot),
    ConsentRequired,
    Unavailable,
}
fn document_deadline(
    env: &worker::Env,
    raw: &str,
    at: u64,
) -> worker::Result<Option<(VerifiedDocument, u64)>> {
    if raw.len() > 8192 {
        return Err(server_error());
    }
    let document: VerifiedDocument = serde_json::from_str(raw).map_err(|_| server_error())?;
    let (trust, _) = trust_policy(env)?;
    let Some(key) = trust.iter().find(|key| {
        key.id == document.trusted_key_id
            && key.document_type == document.attributes.document_type
            && key.not_before <= at
            && at < key.not_after
    }) else {
        return Ok(None);
    };
    let mut deadline = key.not_after;
    if let Some(date) = &document.attributes.expiry_date {
        deadline =
            deadline.min(mikaki_identity::evidence::date_end(date).ok_or_else(server_error)?);
    }
    if deadline <= at {
        return Ok(None);
    }
    Ok(Some((document, deadline)))
}
pub(crate) async fn authorization_snapshot(
    env: &worker::Env,
    db: &D1Database,
    account: &str,
    client: &str,
    request: &AgeRequest,
) -> worker::Result<AuthorizationSnapshot> {
    let (_, policy) = trust_policy(env)?;
    let row=db.prepare("SELECT r.document_id,d.document_json,r.fields_json,r.version,d.policy_hash \
        FROM identity_claim_release r JOIN identity_document d ON d.document_id=r.document_id AND d.account_id=r.account_id \
        JOIN account_security a ON a.account_id=r.account_id JOIN client c ON c.client_id=r.client_id \
        JOIN app_connection g ON g.account_id=r.account_id AND g.client_id=r.client_id \
        WHERE r.account_id=?1 AND r.client_id=?2 AND r.active=1 AND r.expires_at>unixepoch() \
        AND a.active=1 AND a.epoch=r.epoch AND a.epoch=d.epoch AND c.active=1 AND c.revision=r.client_revision \
        AND g.active=1 AND g.grant_version=r.connection_grant_version \
        AND d.revoked=0 AND d.valid_until>unixepoch() AND d.policy_hash=?3")
        .bind(&[js(account),js(client),js(&policy)])?.first::<ReleaseSnapshot>(None).await?;
    let Some(row) = row else {
        return Ok(AuthorizationSnapshot::ConsentRequired);
    };
    let at = now()?;
    let Some((document, _)) = document_deadline(env, &row.document_json, at)? else {
        return Ok(AuthorizationSnapshot::Unavailable);
    };
    if row.fields_json.len() > 256 {
        return Err(server_error());
    }
    let consent: Vec<String> =
        serde_json::from_str(&row.fields_json).map_err(|_| server_error())?;
    match request.project(&document, &consent, at) {
        Ok(_) => Ok(AuthorizationSnapshot::Granted(row)),
        Err(AgeError::ConsentRequired) => Ok(AuthorizationSnapshot::ConsentRequired),
        Err(_) => Ok(AuthorizationSnapshot::Unavailable),
    }
}
impl ReleaseSnapshot {
    pub(crate) fn insert(
        self,
        db: &D1Database,
        code: &str,
        raw: &str,
        request: &AgeRequest,
    ) -> worker::Result<D1PreparedStatement> {
        let fields =
            serde_json::to_string(&request.consent_fields()).map_err(|_| server_error())?;
        db.prepare("INSERT INTO identity_age_request \
            SELECT ac.code_hash,?2,?3,r.document_id,r.version,?4 FROM authorization_code ac \
            JOIN eligible_client_session v ON v.client_id=ac.client_id AND v.sid=ac.sid \
            JOIN identity_claim_release r ON r.account_id=v.account_id AND r.client_id=v.client_id \
            JOIN identity_document d ON d.document_id=r.document_id AND d.account_id=r.account_id \
            JOIN account_security a ON a.account_id=v.account_id \
            JOIN client c ON c.client_id=v.client_id JOIN app_connection g ON g.account_id=v.account_id AND g.client_id=v.client_id \
            WHERE ac.code_hash=?1 AND r.document_id=?5 AND r.version=?6 AND r.fields_json=?7 \
            AND d.document_json=?8 AND d.policy_hash=?9 AND r.active=1 AND r.expires_at>unixepoch() \
            AND d.revoked=0 AND d.valid_until>unixepoch() AND a.epoch=r.epoch AND a.epoch=d.epoch \
            AND c.revision=ac.client_revision AND c.revision=r.client_revision AND g.grant_version=r.connection_grant_version")
            .bind(&[js(code),js(raw),js(&hash(raw)),js(&fields),js(&self.document_id),
                JsValue::from_f64(self.version as f64),js(&self.fields_json),js(&self.document_json),js(&self.policy_hash)])
    }
}

#[derive(Deserialize)]
struct Eligible {
    code_hash: String,
    request_json: String,
    request_hash: String,
    fields_json: String,
    document_id: String,
    release_version: i64,
    document_json: String,
    deadline: u64,
    client_id: String,
    sub: String,
}
#[derive(Deserialize)]
struct SigningKey {
    generation: i64,
    public_jwk: String,
}
pub(crate) async fn userinfo(
    env: &worker::Env,
    db: &D1Database,
    token: &str,
    sub: &str,
) -> worker::Result<Option<Response>> {
    // Check the immutable request even when eligibility or the feature has been revoked.
    // A bound token must never fall back to the broader legacy JSON response.
    let bound=db.prepare("SELECT 1 AS present FROM token_issue ti JOIN identity_age_request q ON q.code_hash=ti.code_hash WHERE ti.access_hash=?1")
        .bind(&[js(token)])?.first::<Value>(None).await?.is_some();
    if !bound {
        return Ok(None);
    }
    let refused = || crate::oauth_error_response("insufficient_scope", 403, true).map(Some);
    if !enabled(env) {
        return refused();
    }
    let (_, policy) = trust_policy(env)?;
    let row = db
        .prepare("SELECT * FROM identity_age_eligible WHERE access_hash=?1 AND policy_hash=?2")
        .bind(&[js(token), js(&policy)])?
        .first::<Eligible>(None)
        .await?;
    let Some(row) = row else { return refused() };
    if row.sub != sub || row.request_hash != hash(&row.request_json) {
        return Err(server_error());
    }
    let request =
        AgeRequest::parse_linked(row.request_json.as_bytes()).map_err(|_| server_error())?;
    let at = now()?;
    let Some((document, document_expiry)) = document_deadline(env, &row.document_json, at)? else {
        return refused();
    };
    let consent: Vec<String> =
        serde_json::from_str(&row.fields_json).map_err(|_| server_error())?;
    let Ok(attributes) = request.project(&document, &consent, at) else {
        return refused();
    };
    let linked = json!({"attributes":attributes,"evidence":mikaki_identity::op_age::consumer_evidence(&document,at).map_err(|_|server_error())?});
    let expiry = (at + 300).min(row.deadline).min(document_expiry);
    if expiry <= at {
        return refused();
    }
    let signer =
        crate::WorkerTokenSigner::from_secret(&env.secret("OP_PRIVATE_JWK")?.to_string()).await?;
    let key=db.prepare("SELECT generation,public_jwk FROM signing_key WHERE kid=?1 AND algorithm=?2 AND active=1")
        .bind(&[js(signer.kid()),js(signer.algorithm())])?.first::<SigningKey>(None).await?.ok_or_else(server_error)?;
    if !signer.matches_public_jwk(&key.public_jwk) {
        return Err(server_error());
    }
    let issuer =
        configured_issuer(&env.var("MIKAKI_ISSUER")?.to_string()).ok_or_else(server_error)?;
    let compact = signer
        .sign_userinfo(&issuer, sub, &row.client_id, at, expiry, &linked)
        .await?;
    let receipt = random()?;
    // Revalidate after signing, atomically with the mandatory audit. Bound snapshots,
    // current permissions, token lifetime and signing generation must still agree.
    let result=db.prepare("INSERT INTO identity_age_audit \
        SELECT ?1,e.code_hash,e.client_id,e.request_hash,e.document_id,e.release_version,?3,sk.kid,sk.generation,'issuer_signed_static_data',?4,?5 \
        FROM identity_age_eligible e JOIN signing_key sk ON sk.kid=?6 \
        WHERE e.access_hash=?2 AND e.code_hash=?7 AND e.request_hash=?8 AND e.request_json=?9 \
        AND e.document_id=?10 AND e.release_version=?11 AND e.fields_json=?12 AND e.document_json=?13 \
        AND e.policy_hash=?14 AND e.sub=?15 AND e.client_id=?16 \
        AND e.deadline>=?5 AND ?5>unixepoch() AND ?4<=unixepoch() AND ?4>=unixepoch()-30 \
        AND sk.active=1 AND sk.algorithm=?17 AND sk.generation=?18 AND sk.public_jwk=?19 \
        AND (SELECT count(*) FROM identity_age_audit WHERE code_hash=e.code_hash)<100 RETURNING receipt_id")
        .bind(&[js(&receipt),js(token),js(&hash(&compact)),JsValue::from_f64(at as f64),JsValue::from_f64(expiry as f64),
            js(signer.kid()),js(&row.code_hash),js(&row.request_hash),js(&row.request_json),js(&row.document_id),
            JsValue::from_f64(row.release_version as f64),js(&row.fields_json),js(&row.document_json),js(&policy),js(sub),js(&row.client_id),
            js(signer.algorithm()),JsValue::from_f64(key.generation as f64),js(&key.public_jwk)])?
        .first::<Value>(None).await?;
    if result.is_none() {
        return refused();
    }
    Ok(Some(
        Response::builder()
            .with_header("Cache-Control", "no-store")?
            .with_header("Pragma", "no-cache")?
            .with_header("Content-Type", "application/jwt")?
            .fixed(compact.into_bytes()),
    ))
}
