//! Admin invitation issuance requires the current admin's UV passkey proof.

use super::*;
use wasm_bindgen::JsValue;

#[derive(Deserialize)]
struct AdminRow {
    account_id: String,
    credential_id: String,
    user_handle: String,
    public_key: String,
    counter: u32,
    backup_eligible: i64,
    revision: i64,
}

#[derive(Deserialize)]
struct ManagementPolicy {
    management_ttl_seconds: u64,
}

#[derive(Deserialize)]
struct TransactionRow {
    challenge: String,
    expires_at: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FinishInput {
    operation_id: String,
    response: mikaki_webauthn::Assertion,
}

#[derive(Serialize)]
struct StartOutput {
    operation_id: String,
    challenge: String,
    credential_id: String,
    rp_id: String,
}

#[derive(Serialize)]
struct FinishOutput {
    invitation: String,
    expires_at: i64,
}

fn reject(status: u16) -> worker::Result<worker::Response> {
    Ok(worker::Response::builder()
        .with_status(status)
        .with_header("Cache-Control", "no-store")?
        .empty())
}

pub async fn page(
    request: worker::Request,
    context: worker::RouteContext<()>,
) -> worker::Result<worker::Response> {
    let Some(cookie) = browser_cookie(&request, "__Host-op-sso")? else {
        return reject(401);
    };
    let db = context.env.d1("DB")?;
    if admin(&db, &passkey_login::hash(&cookie)).await?.is_none() {
        return reject(403);
    }
    let strings = i18n::catalog(i18n::select(&request, None)?);
    let html = format!(
        "<!doctype html><html lang=\"{}\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>{}</title></head><body><div id=\"app\"></div><script type=\"module\" src=\"/admin/admin.js\"></script></body></html>",
        strings.locale,
        i18n::html_escape(strings.message("adminTitle")),
    );
    worker::Response::builder()
        .with_header("Cache-Control", "no-store")?
        .with_header("Referrer-Policy", "no-referrer")?
        .with_header("Content-Security-Policy", "default-src 'none'; script-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")?
        .from_html(html)
}

pub async fn script(
    _request: worker::Request,
    _context: worker::RouteContext<()>,
) -> worker::Result<worker::Response> {
    Ok(worker::Response::builder()
        .with_header("Content-Type", "text/javascript; charset=utf-8")?
        .with_header("Cache-Control", "no-store")?
        .with_header("X-Content-Type-Options", "nosniff")?
        .fixed(
            include_str!(concat!(env!("OUT_DIR"), "/admin.js"))
                .as_bytes()
                .to_vec(),
        ))
}

async fn admin(db: &worker::d1::D1Database, secret_hash: &str) -> worker::Result<Option<AdminRow>> {
    db.prepare(
        "SELECT ss.account_id,ss.credential_id,p.user_handle,p.public_key,p.counter,p.backup_eligible,p.revision \
         FROM sso_context sx JOIN sso_session ss ON ss.sso_id=sx.sso_id \
         JOIN account_security a ON a.account_id=ss.account_id \
         JOIN account_role ar ON ar.account_id=ss.account_id AND ar.role='admin' AND ar.active=1 \
         JOIN credential c ON c.credential_id=ss.credential_id AND c.account_id=ss.account_id AND c.active=1 \
         JOIN passkey_credential p ON p.credential_id=c.credential_id \
         WHERE sx.secret_hash=?1 AND ss.revoked=0 AND ss.expires_at>CAST(strftime('%s','now') AS INTEGER) \
         AND a.active=1 AND a.epoch=ss.epoch",
    )
    .bind(&[JsValue::from_str(secret_hash)])?
    .first::<AdminRow>(None)
    .await
}

pub async fn start(
    request: worker::Request,
    context: worker::RouteContext<()>,
) -> worker::Result<worker::Response> {
    let issuer = enrollment::issuer(&context)?;
    if !enrollment::origin_matches(&request, &issuer)? {
        return reject(403);
    }
    let Some(cookie) = browser_cookie(&request, "__Host-op-sso")? else {
        return reject(403);
    };
    let db = context.env.d1("DB")?;
    let browser_hash = passkey_login::hash(&cookie);
    let Some(admin) = admin(&db, &browser_hash).await? else {
        return reject(403);
    };
    let policy = db
        .prepare("SELECT management_ttl_seconds FROM enrollment_policy WHERE id=1")
        .first::<ManagementPolicy>(None)
        .await?
        .ok_or_else(|| worker::Error::RustError("enrollment policy unavailable".into()))?;
    let now = now_seconds().ok_or_else(|| worker::Error::RustError("server_error".into()))?;
    let mut random = WorkersCryptoRandom;
    let operation_id = passkey_login::random_secret(&mut random)?;
    let challenge = passkey_login::random_secret(&mut random)?;
    db.prepare("INSERT INTO admin_invitation_transaction(operation_id,account_id,credential_id,browser_hash,challenge,expires_at) VALUES(?1,?2,?3,?4,?5,?6)")
        .bind(&[JsValue::from_str(&operation_id),JsValue::from_str(&admin.account_id),JsValue::from_str(&admin.credential_id),JsValue::from_str(&browser_hash),JsValue::from_str(&challenge),JsValue::from_f64((now+policy.management_ttl_seconds) as f64)])?
        .run().await?;
    worker::Response::builder()
        .with_header("Cache-Control", "no-store")?
        .from_json(&StartOutput {
            operation_id,
            challenge,
            credential_id: admin.credential_id,
            rp_id: enrollment::rp_id(&issuer)?,
        })
}

pub async fn finish(
    mut request: worker::Request,
    context: worker::RouteContext<()>,
) -> worker::Result<worker::Response> {
    let issuer = enrollment::issuer(&context)?;
    if !enrollment::origin_matches(&request, &issuer)? {
        return reject(403);
    }
    let Some(cookie) = browser_cookie(&request, "__Host-op-sso")? else {
        return reject(403);
    };
    let db = context.env.d1("DB")?;
    let policy = WorkerRuntimePolicy::from_db(&db).await?;
    let body = read_bounded_body(&mut request, policy.form_body_bytes).await?;
    mikaki_webauthn::strict_json(&body, policy.form_body_bytes, 16)
        .map_err(|_| worker::Error::RustError("invalid_request".into()))?;
    let input: FinishInput = serde_json::from_str(&body)
        .map_err(|_| worker::Error::RustError("invalid_request".into()))?;
    if !passkey_login::valid_tx(&input.operation_id) {
        return reject(400);
    }
    let browser_hash = passkey_login::hash(&cookie);
    let Some(admin) = admin(&db, &browser_hash).await? else {
        return reject(403);
    };
    let row = db.prepare("SELECT challenge,expires_at FROM admin_invitation_transaction WHERE operation_id=?1 AND account_id=?2 AND credential_id=?3 AND browser_hash=?4 AND consumed=0 AND failures<5 AND expires_at>CAST(strftime('%s','now') AS INTEGER)")
        .bind(&[JsValue::from_str(&input.operation_id),JsValue::from_str(&admin.account_id),JsValue::from_str(&admin.credential_id),JsValue::from_str(&browser_hash)])?
        .first::<TransactionRow>(None).await?;
    let Some(row) = row else { return reject(400) };
    let now = now_seconds().ok_or_else(|| worker::Error::RustError("server_error".into()))?;
    let rp_id = enrollment::rp_id(&issuer)?;
    let context = mikaki_webauthn::Context {
        challenge: row.challenge,
        origin: issuer,
        rp_id,
        max_bytes: policy.form_body_bytes,
        max_depth: 16,
        user_verification: Default::default(),
        authentication: mikaki_webauthn::Authentication::Identified {
            user_handle: admin.user_handle.clone(),
            allowed_credentials: vec![admin.credential_id.clone()],
        },
        algorithms: vec![-7],
        attestation: None,
        attestation_policy: Default::default(),
    };
    let stored = mikaki_webauthn::StoredCredential {
        id: admin.credential_id.clone(),
        public_key: admin.public_key,
        user_handle: admin.user_handle,
        counter: admin.counter,
        backup_eligible: admin.backup_eligible == 1,
    };
    let proof = mikaki_webauthn::authenticate(&context, &stored, input.response);
    let proof = match proof {
        Ok(proof) if proof.user_verified() => proof,
        _ => {
            db.prepare("UPDATE admin_invitation_transaction SET failures=failures+1 WHERE operation_id=?1 AND consumed=0 AND failures<5")
                .bind(&[JsValue::from_str(&input.operation_id)])?.run().await?;
            return reject(401);
        }
    };
    if now >= row.expires_at as u64 {
        return reject(400);
    }
    let mut random = WorkersCryptoRandom;
    let invitation = passkey_login::random_secret(&mut random)?;
    let invite_hash = passkey_login::hash(&invitation);
    let guard = format!("{}-admin", input.operation_id);
    db.batch(vec![
        db.prepare("UPDATE admin_invitation_transaction SET consumed=1 WHERE operation_id=?1 AND account_id=?2 AND credential_id=?3 AND browser_hash=?4 AND consumed=0 AND failures<5 AND expires_at>?5")
            .bind(&[JsValue::from_str(&input.operation_id),JsValue::from_str(&admin.account_id),JsValue::from_str(&admin.credential_id),JsValue::from_str(&browser_hash),JsValue::from_f64(now as f64)])?,
        db.prepare("INSERT INTO atomic_guard(operation_id,passed) VALUES(?1,CASE WHEN changes()=1 THEN 1 ELSE 0 END)")
            .bind(&[JsValue::from_str(&guard)])?,
        db.prepare("UPDATE passkey_credential SET counter=?1,backup_state=?2,revision=revision+1 WHERE credential_id=?3 AND revision=?4")
            .bind(&[JsValue::from_f64(proof.counter() as f64),JsValue::from_f64(f64::from(proof.backup_state())),JsValue::from_str(&admin.credential_id),JsValue::from_f64(admin.revision as f64)])?,
        db.prepare("INSERT INTO atomic_guard(operation_id,passed) VALUES(?1,CASE WHEN changes()=1 THEN 1 ELSE 0 END)")
            .bind(&[JsValue::from_str(&format!("{guard}-key"))])?,
        db.prepare("INSERT INTO enrollment_invite(invite_hash,kind,issuer_account_id,issued_at,expires_at) SELECT ?1,'normal',?2,?3,?3+p.invite_ttl_seconds FROM enrollment_policy p JOIN account_role ar ON ar.account_id=?2 AND ar.role='admin' AND ar.active=1 JOIN account_security a ON a.account_id=ar.account_id AND a.active=1 WHERE p.id=1")
            .bind(&[JsValue::from_str(&invite_hash),JsValue::from_str(&admin.account_id),JsValue::from_f64(now as f64)])?,
        db.prepare("INSERT INTO atomic_guard(operation_id,passed) VALUES(?1,CASE WHEN changes()=1 THEN 1 ELSE 0 END)")
            .bind(&[JsValue::from_str(&format!("{guard}-invite"))])?,
        db.prepare("INSERT INTO enrollment_invite_audit(operation_id,invite_hash,action,actor,reason,occurred_at) VALUES(?1,?2,'issue-normal',?3,'admin UV invitation',?4)")
            .bind(&[JsValue::from_str(&input.operation_id),JsValue::from_str(&invite_hash),JsValue::from_str(&admin.account_id),JsValue::from_f64(now as f64)])?,
        db.prepare("DELETE FROM atomic_guard WHERE operation_id=?1").bind(&[JsValue::from_str(&guard)])?,
        db.prepare("DELETE FROM atomic_guard WHERE operation_id=?1").bind(&[JsValue::from_str(&format!("{guard}-key"))])?,
        db.prepare("DELETE FROM atomic_guard WHERE operation_id=?1").bind(&[JsValue::from_str(&format!("{guard}-invite"))])?,
    ]).await?;
    let policy_row = db
        .prepare("SELECT expires_at FROM enrollment_invite WHERE invite_hash=?1")
        .bind(&[JsValue::from_str(&invite_hash)])?
        .first::<ExpiryRow>(None)
        .await?
        .ok_or_else(|| worker::Error::RustError("invite unavailable".into()))?;
    worker::Response::builder()
        .with_header("Cache-Control", "no-store")?
        .with_header("Referrer-Policy", "no-referrer")?
        .from_json(&FinishOutput {
            invitation,
            expires_at: policy_row.expires_at,
        })
}

#[derive(Deserialize)]
struct ExpiryRow {
    expires_at: i64,
}
