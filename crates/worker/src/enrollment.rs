//! Invitation-bound account creation. The browser never chooses account or role.

use super::*;
use wasm_bindgen::JsValue;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StartInput {
    tx: String,
    invitation: String,
}

#[derive(Serialize)]
struct StartOutput {
    challenge: String,
    user_handle: String,
    rp_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FinishInput {
    tx: String,
    consent: bool,
    response: mikaki_webauthn::Registration,
}

#[derive(Deserialize)]
struct RegistrationRow {
    invite_hash: String,
    kind: String,
    challenge: String,
    user_handle: String,
    expires_at: i64,
    failures: u32,
}

#[derive(Deserialize)]
struct CompletionRow {
    is_admin: i64,
}

#[derive(Deserialize)]
struct EnrollmentPolicy {
    registration_ttl_seconds: u64,
}

pub(super) fn rp_id(issuer: &str) -> worker::Result<String> {
    url::Url::parse(issuer)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .ok_or_else(|| worker::Error::RustError("server_error".into()))
}

pub(super) fn issuer(context: &worker::RouteContext<()>) -> worker::Result<String> {
    let value = context
        .env
        .var("MIKAKI_ISSUER")
        .map_err(|_| worker::Error::RustError("server_error".into()))?
        .to_string();
    configured_issuer(&value).ok_or_else(|| worker::Error::RustError("server_error".into()))
}

pub(super) fn origin_matches(request: &worker::Request, issuer: &str) -> worker::Result<bool> {
    Ok(request.headers().get("Origin")?.as_deref() == Some(issuer))
}

fn reject(status: u16) -> worker::Result<worker::Response> {
    Ok(worker::Response::builder()
        .with_status(status)
        .with_header("Cache-Control", "no-store")?
        .empty())
}

pub async fn entry(
    request: worker::Request,
    context: worker::RouteContext<()>,
) -> worker::Result<worker::Response> {
    let issuer = issuer(&context)?;
    if request.url()?.query().is_some() {
        return reject(400);
    }
    let db = context.env.d1("DB")?;
    let policy = db
        .prepare("SELECT registration_ttl_seconds FROM enrollment_policy WHERE id=1")
        .first::<EnrollmentPolicy>(None)
        .await?
        .ok_or_else(|| worker::Error::RustError("enrollment policy unavailable".into()))?;
    let mut random = WorkersCryptoRandom;
    let tx = passkey_login::random_secret(&mut random)?;
    let browser = passkey_login::random_secret(&mut random)?;
    let challenge = passkey_login::random_secret(&mut random)?;
    let now = now_seconds().ok_or_else(|| worker::Error::RustError("server_error".into()))?;
    db.prepare("INSERT INTO login_transaction(tx_id,browser_hash,authorization_url,client_id,challenge,expires_at) VALUES(?1,?2,?3,'mikaki-internal-enrollment',?4,?5)")
        .bind(&[JsValue::from_str(&tx),JsValue::from_str(&passkey_login::hash(&browser)),JsValue::from_str(&format!("{issuer}/enroll/complete")),JsValue::from_str(&challenge),JsValue::from_f64((now+policy.registration_ttl_seconds) as f64)])?
        .run().await?;
    Ok(worker::Response::builder()
        .with_status(302)
        .with_header("Location", &format!("{issuer}/login?tx={tx}"))?
        .with_header(
            "Set-Cookie",
            &format!(
                "__Host-op-browser={browser}; Max-Age={}; Path=/; Secure; HttpOnly; SameSite=Lax",
                policy.registration_ttl_seconds
            ),
        )?
        .with_header("Cache-Control", "no-store")?
        .with_header("Referrer-Policy", "no-referrer")?
        .empty())
}

pub async fn complete(
    request: worker::Request,
    context: worker::RouteContext<()>,
) -> worker::Result<worker::Response> {
    let Some(cookie) = browser_cookie(&request, "__Host-op-sso")? else {
        return reject(401);
    };
    let db = context.env.d1("DB")?;
    let row = db.prepare("SELECT CASE WHEN ar.active=1 THEN 1 ELSE 0 END AS is_admin FROM sso_context sx JOIN sso_session ss ON ss.sso_id=sx.sso_id JOIN account_security a ON a.account_id=ss.account_id JOIN credential c ON c.credential_id=ss.credential_id AND c.account_id=ss.account_id LEFT JOIN account_role ar ON ar.account_id=ss.account_id AND ar.role='admin' WHERE sx.secret_hash=?1 AND ss.revoked=0 AND ss.expires_at>CAST(strftime('%s','now') AS INTEGER) AND a.active=1 AND a.epoch=ss.epoch AND c.active=1")
        .bind(&[JsValue::from_str(&passkey_login::hash(&cookie))])?
        .first::<CompletionRow>(None).await?;
    let Some(row) = row else { return reject(401) };
    let strings = i18n::catalog(i18n::select(&request, None)?);
    let html = format!(
        "<!doctype html><html lang=\"{}\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>{}</title></head><body><div id=\"app\" data-admin=\"{}\"></div><script type=\"module\" src=\"/enroll/complete.js\"></script></body></html>",
        strings.locale,
        i18n::html_escape(strings.message("enrollCompleteTitle")),
        if row.is_admin == 1 { "true" } else { "false" }
    );
    worker::Response::builder()
        .with_header("Cache-Control","no-store")?
        .with_header("Referrer-Policy","no-referrer")?
        .with_header("Content-Security-Policy","default-src 'none'; script-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")?
        .from_html(html)
}

pub async fn complete_script(
    _request: worker::Request,
    _context: worker::RouteContext<()>,
) -> worker::Result<worker::Response> {
    Ok(worker::Response::builder()
        .with_header("Content-Type", "text/javascript; charset=utf-8")?
        .with_header("Cache-Control", "no-store")?
        .with_header("X-Content-Type-Options", "nosniff")?
        .fixed(
            include_str!(concat!(env!("OUT_DIR"), "/complete.js"))
                .as_bytes()
                .to_vec(),
        ))
}

pub async fn start(
    mut request: worker::Request,
    context: worker::RouteContext<()>,
) -> worker::Result<worker::Response> {
    let issuer = issuer(&context)?;
    if !origin_matches(&request, &issuer)? {
        return reject(403);
    }
    let Some(browser) = browser_cookie(&request, "__Host-op-browser")? else {
        return reject(403);
    };
    let db = context.env.d1("DB")?;
    let policy = WorkerRuntimePolicy::from_db(&db).await?;
    let body = read_bounded_body(&mut request, policy.form_body_bytes).await?;
    mikaki_webauthn::strict_json(&body, policy.form_body_bytes, 16)
        .map_err(|_| worker::Error::RustError("invalid_request".into()))?;
    let input: StartInput = serde_json::from_str(&body)
        .map_err(|_| worker::Error::RustError("invalid_request".into()))?;
    if !passkey_login::valid_tx(&input.tx)
        || input.invitation.len() != 43
        || !input
            .invitation
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return reject(400);
    }
    let browser_hash = passkey_login::hash(&browser);
    let Some(login) = passkey_login::transaction(&db, &input.tx, &browser_hash).await? else {
        return reject(400);
    };
    let invite_hash = passkey_login::hash(&input.invitation);
    let mut random = WorkersCryptoRandom;
    let challenge = passkey_login::random_secret(&mut random)?;
    let user_handle = passkey_login::random_secret(&mut random)?;
    db.prepare(
        "INSERT INTO registration_transaction(tx_id,browser_hash,invite_hash,challenge,user_handle,expires_at) \
         SELECT ?1,?2,i.invite_hash,?4,?5,?6 FROM enrollment_invite i \
         WHERE i.invite_hash=?3 AND i.revoked=0 AND i.consumed_at IS NULL \
         AND i.expires_at>CAST(strftime('%s','now') AS INTEGER) \
         AND (i.kind='bootstrap' AND EXISTS(SELECT 1 FROM bootstrap_state WHERE id=1 AND closed=0) \
           OR i.kind='normal' AND EXISTS(SELECT 1 FROM account_role ar JOIN account_security a ON a.account_id=ar.account_id WHERE ar.account_id=i.issuer_account_id AND ar.role='admin' AND ar.active=1 AND a.active=1)) \
         ON CONFLICT(tx_id) DO NOTHING",
    )
    .bind(&[
        JsValue::from_str(&input.tx),
        JsValue::from_str(&browser_hash),
        JsValue::from_str(&invite_hash),
        JsValue::from_str(&challenge),
        JsValue::from_str(&user_handle),
        JsValue::from_f64(login.expires_at as f64),
    ])?
    .run()
    .await?;
    let row = db.prepare(
        "SELECT r.invite_hash,i.kind,r.challenge,r.user_handle,r.expires_at,r.failures \
         FROM registration_transaction r JOIN enrollment_invite i ON i.invite_hash=r.invite_hash \
         WHERE r.tx_id=?1 AND r.browser_hash=?2 AND r.invite_hash=?3 AND r.consumed=0 \
         AND r.expires_at>CAST(strftime('%s','now') AS INTEGER) AND r.failures<5 \
         AND i.revoked=0 AND i.consumed_at IS NULL AND i.expires_at>CAST(strftime('%s','now') AS INTEGER) \
         AND (i.kind='bootstrap' AND EXISTS(SELECT 1 FROM bootstrap_state WHERE id=1 AND closed=0) \
           OR i.kind='normal' AND EXISTS(SELECT 1 FROM account_role ar JOIN account_security a ON a.account_id=ar.account_id WHERE ar.account_id=i.issuer_account_id AND ar.role='admin' AND ar.active=1 AND a.active=1))",
    ).bind(&[JsValue::from_str(&input.tx),JsValue::from_str(&browser_hash),JsValue::from_str(&invite_hash)])?
      .first::<RegistrationRow>(None).await?;
    let Some(row) = row else { return reject(400) };
    worker::Response::builder()
        .with_header("Cache-Control", "no-store")?
        .from_json(&StartOutput {
            challenge: row.challenge,
            user_handle: row.user_handle,
            rp_id: rp_id(&issuer)?,
        })
}

pub async fn finish(
    mut request: worker::Request,
    context: worker::RouteContext<()>,
) -> worker::Result<worker::Response> {
    let issuer = issuer(&context)?;
    if !origin_matches(&request, &issuer)? {
        return reject(403);
    }
    let Some(browser) = browser_cookie(&request, "__Host-op-browser")? else {
        return reject(403);
    };
    let db = context.env.d1("DB")?;
    let policy = WorkerRuntimePolicy::from_db(&db).await?;
    let body = read_bounded_body(&mut request, policy.form_body_bytes).await?;
    mikaki_webauthn::strict_json(&body, policy.form_body_bytes, 16)
        .map_err(|_| worker::Error::RustError("invalid_request".into()))?;
    let input: FinishInput = serde_json::from_str(&body)
        .map_err(|_| worker::Error::RustError("invalid_request".into()))?;
    if !input.consent || !passkey_login::valid_tx(&input.tx) {
        return reject(400);
    }
    let browser_hash = passkey_login::hash(&browser);
    let Some(login) = passkey_login::transaction(&db, &input.tx, &browser_hash).await? else {
        return reject(400);
    };
    let row = db
        .prepare(
            "SELECT r.invite_hash,i.kind,r.challenge,r.user_handle,r.expires_at,r.failures \
         FROM registration_transaction r JOIN enrollment_invite i ON i.invite_hash=r.invite_hash \
         WHERE r.tx_id=?1 AND r.browser_hash=?2 AND r.consumed=0 AND r.failures<5 \
         AND r.expires_at>CAST(strftime('%s','now') AS INTEGER) AND i.revoked=0 \
         AND i.consumed_at IS NULL AND i.expires_at>CAST(strftime('%s','now') AS INTEGER) \
         AND (i.kind='bootstrap' AND EXISTS(SELECT 1 FROM bootstrap_state WHERE id=1 AND closed=0) \
           OR i.kind='normal' AND EXISTS(SELECT 1 FROM account_role ar JOIN account_security a ON a.account_id=ar.account_id WHERE ar.account_id=i.issuer_account_id AND ar.role='admin' AND ar.active=1 AND a.active=1))",
        )
        .bind(&[
            JsValue::from_str(&input.tx),
            JsValue::from_str(&browser_hash),
        ])?
        .first::<RegistrationRow>(None)
        .await?;
    let Some(row) = row else { return reject(400) };
    let now = now_seconds().ok_or_else(|| worker::Error::RustError("server_error".into()))?;
    let registration_rp_id = rp_id(&issuer)?;
    let context = mikaki_webauthn::Context {
        challenge: row.challenge,
        origin: issuer,
        rp_id: registration_rp_id,
        max_bytes: policy.form_body_bytes,
        max_depth: 16,
        user_verification: Default::default(),
        authentication: Default::default(),
        algorithms: vec![-7],
        attestation: None,
        attestation_policy: Default::default(),
    };
    let proof = mikaki_auth::Ceremony {
        purpose: "register".into(),
        browser_hash: browser_hash.clone(),
        expires_at: row.expires_at as u64,
        failures: row.failures,
        consumed: false,
        context,
    }
    .register(&browser_hash, now, 5, input.response);
    let proof = match proof {
        Ok(proof) if proof.user_verified() => proof,
        _ => {
            db.prepare("UPDATE registration_transaction SET failures=failures+1 WHERE tx_id=?1 AND browser_hash=?2 AND consumed=0 AND failures<5")
                .bind(&[JsValue::from_str(&input.tx),JsValue::from_str(&browser_hash)])?
                .run().await?;
            return reject(401);
        }
    };
    let mut random = WorkersCryptoRandom;
    let account_id = passkey_login::random_secret(&mut random)?;
    let sso_id = passkey_login::random_secret(&mut random)?;
    let sso_secret = passkey_login::random_secret(&mut random)?;
    let sso_hash = passkey_login::hash(&sso_secret);
    let guard = |suffix: &str| format!("{account_id}-{suffix}");
    let mut statements = vec![
        db.prepare("UPDATE enrollment_invite SET consumed_at=?1 WHERE invite_hash=?2 AND consumed_at IS NULL AND revoked=0 AND expires_at>?1 AND (kind='bootstrap' AND EXISTS(SELECT 1 FROM bootstrap_state WHERE id=1 AND closed=0) OR kind='normal' AND EXISTS(SELECT 1 FROM account_role ar JOIN account_security a ON a.account_id=ar.account_id WHERE ar.account_id=enrollment_invite.issuer_account_id AND ar.role='admin' AND ar.active=1 AND a.active=1))")
            .bind(&[JsValue::from_f64(now as f64),JsValue::from_str(&row.invite_hash)])?,
        db.prepare("INSERT INTO atomic_guard(operation_id,passed) VALUES(?1,CASE WHEN changes()=1 THEN 1 ELSE 0 END)")
            .bind(&[JsValue::from_str(&guard("invite"))])?,
        db.prepare("UPDATE registration_transaction SET consumed=1 WHERE tx_id=?1 AND browser_hash=?2 AND consumed=0 AND failures<5 AND expires_at>?3")
            .bind(&[JsValue::from_str(&input.tx),JsValue::from_str(&browser_hash),JsValue::from_f64(now as f64)])?,
        db.prepare("INSERT INTO atomic_guard(operation_id,passed) VALUES(?1,CASE WHEN changes()=1 THEN 1 ELSE 0 END)")
            .bind(&[JsValue::from_str(&guard("register"))])?,
        db.prepare("UPDATE login_transaction SET consumed=1 WHERE tx_id=?1 AND browser_hash=?2 AND consumed=0 AND failures<5 AND expires_at>?3")
            .bind(&[JsValue::from_str(&input.tx),JsValue::from_str(&browser_hash),JsValue::from_f64(now as f64)])?,
        db.prepare("INSERT INTO atomic_guard(operation_id,passed) VALUES(?1,CASE WHEN changes()=1 THEN 1 ELSE 0 END)")
            .bind(&[JsValue::from_str(&guard("login"))])?,
        db.prepare("INSERT INTO account_security(account_id,epoch,active) VALUES(?1,1,1)").bind(&[JsValue::from_str(&account_id)])?,
        db.prepare("INSERT INTO credential(credential_id,account_id,active) VALUES(?1,?2,1)").bind(&[JsValue::from_str(proof.id()),JsValue::from_str(&account_id)])?,
        db.prepare("INSERT INTO passkey_credential(credential_id,public_key,user_handle,counter,backup_eligible,backup_state,revision) VALUES(?1,?2,?3,?4,?5,?6,1)")
            .bind(&[JsValue::from_str(proof.id()),JsValue::from_str(proof.public_key()),JsValue::from_str(&row.user_handle),JsValue::from_f64(proof.counter() as f64),JsValue::from_f64(f64::from(proof.backup_eligible())),JsValue::from_f64(f64::from(proof.backup_state()))])?,
    ];
    if row.kind == "bootstrap" {
        statements.push(
            db.prepare("UPDATE bootstrap_state SET closed=1 WHERE id=1 AND closed=0")
                .bind(&[])?,
        );
        statements.push(db.prepare("INSERT INTO atomic_guard(operation_id,passed) VALUES(?1,CASE WHEN changes()=1 THEN 1 ELSE 0 END)")
            .bind(&[JsValue::from_str(&guard("bootstrap"))])?);
        statements.push(
            db.prepare("INSERT INTO account_role(account_id,role,active) VALUES(?1,'admin',1)")
                .bind(&[JsValue::from_str(&account_id)])?,
        );
    }
    statements.extend([
        db.prepare("INSERT INTO sso_session(sso_id,account_id,credential_id,epoch,expires_at,revoked) VALUES(?1,?2,?3,1,?4,0)")
            .bind(&[JsValue::from_str(&sso_id),JsValue::from_str(&account_id),JsValue::from_str(proof.id()),JsValue::from_f64((now+policy.sso_absolute_ttl_seconds()) as f64)])?,
        db.prepare("INSERT INTO sso_context(sso_id,secret_hash,auth_time) VALUES(?1,?2,?3)")
            .bind(&[JsValue::from_str(&sso_id),JsValue::from_str(&sso_hash),JsValue::from_f64(now as f64)])?,
        db.prepare("INSERT INTO app_connection(account_id,client_id,grant_version,active) VALUES(?1,?2,1,1)")
            .bind(&[JsValue::from_str(&account_id),JsValue::from_str(&login.client_id)])?,
    ]);
    for suffix in ["invite", "register", "login"] {
        statements.push(
            db.prepare("DELETE FROM atomic_guard WHERE operation_id=?1")
                .bind(&[JsValue::from_str(&guard(suffix))])?,
        );
    }
    if row.kind == "bootstrap" {
        statements.push(
            db.prepare("DELETE FROM atomic_guard WHERE operation_id=?1")
                .bind(&[JsValue::from_str(&guard("bootstrap"))])?,
        );
    }
    db.batch(statements).await?;
    worker::Response::builder()
        .with_header(
            "Set-Cookie",
            &format!(
                "__Host-op-sso={sso_secret}; Max-Age={}; Path=/; Secure; HttpOnly; SameSite=Lax",
                policy.sso_absolute_ttl_seconds()
            ),
        )?
        .with_header("Cache-Control", "no-store")?
        .with_header("Referrer-Policy", "no-referrer")?
        .from_json(&LoginFinishOutput {
            location: login.authorization_url,
        })
}
