use super::*;
use wasm_bindgen::JsValue;

pub(super) fn valid_tx(tx: &str) -> bool {
    tx.len() == 43
        && tx
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
}

pub(super) fn hash(value: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(value.as_bytes()))
}

pub(super) fn random_secret(random: &mut WorkersCryptoRandom) -> worker::Result<String> {
    let mut bytes = [0u8; 32];
    random
        .fill(&mut bytes)
        .map_err(|_| worker::Error::RustError("server_error".into()))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

pub(super) async fn start(
    request: &worker::Request,
    db: &worker::d1::D1Database,
    issuer: &str,
    client_id: &str,
) -> worker::Result<worker::Response> {
    let mut random = WorkersCryptoRandom;
    let tx = random_secret(&mut random)?;
    let browser = random_secret(&mut random)?;
    let challenge = random_secret(&mut random)?;
    let now = now_seconds().ok_or_else(|| worker::Error::RustError("server_error".into()))?;
    let requested = request.url()?;
    let mut continuation = requested.clone();
    continuation
        .query_pairs_mut()
        .clear()
        .extend_pairs(requested.query_pairs().filter(|(key, _)| key != "prompt"));
    let authorization_url = continuation.to_string();
    db.prepare(
        "INSERT INTO login_transaction(tx_id,browser_hash,authorization_url,client_id,challenge,expires_at) \
         VALUES(?1,?2,?3,?4,?5,?6)",
    )
    .bind(&[
        JsValue::from_str(&tx),
        JsValue::from_str(&hash(&browser)),
        JsValue::from_str(&authorization_url),
        JsValue::from_str(client_id),
        JsValue::from_str(&challenge),
        JsValue::from_f64((now + 300) as f64),
    ])?
    .run()
    .await?;
    Ok(worker::Response::builder()
        .with_status(302)
        .with_header("Location", &format!("{issuer}/login?tx={tx}"))?
        .with_header(
            "Set-Cookie",
            &format!(
                "__Host-op-browser={browser}; Max-Age=300; Path=/; Secure; HttpOnly; SameSite=Lax"
            ),
        )?
        .with_header("Cache-Control", "no-store")?
        .with_header("Referrer-Policy", "no-referrer")?
        .empty())
}

pub(super) async fn transaction(
    db: &worker::d1::D1Database,
    tx: &str,
    browser_hash: &str,
) -> worker::Result<Option<LoginTransactionRow>> {
    db.prepare(
        "SELECT authorization_url,client_id,challenge,expires_at,failures \
         FROM login_transaction WHERE tx_id=?1 AND browser_hash=?2 AND consumed=0 \
         AND expires_at>CAST(strftime('%s','now') AS INTEGER) AND failures<5",
    )
    .bind(&[JsValue::from_str(tx), JsValue::from_str(browser_hash)])?
    .first::<LoginTransactionRow>(None)
    .await
}

pub(super) async fn get(
    request: worker::Request,
    context: worker::RouteContext<()>,
) -> worker::Result<worker::Response> {
    let issuer = context
        .env
        .var("MIKAKI_ISSUER")
        .map_err(|_| worker::Error::RustError("server_error".into()))?
        .to_string();
    let issuer = configured_issuer(&issuer)
        .ok_or_else(|| worker::Error::RustError("server_error".into()))?;
    let request_url = request.url()?;
    let query = request_url.query_pairs().collect::<Vec<_>>();
    let tx = match query.as_slice() {
        [(key, value)] if key == "tx" && valid_tx(value) => value.as_ref(),
        [(key, value), (language, _)] if key == "tx" && language == "lang" && valid_tx(value) => {
            value.as_ref()
        }
        _ => return Ok(worker::Response::builder().with_status(400).empty()),
    };
    let Some(browser) = browser_cookie(&request, "__Host-op-browser")? else {
        return Ok(worker::Response::builder().with_status(400).empty());
    };
    let db = context.env.d1("DB")?;
    let Some(login) = transaction(&db, tx, &hash(&browser)).await? else {
        return Ok(worker::Response::builder().with_status(400).empty());
    };
    let rp_id = url::Url::parse(&issuer)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .ok_or_else(|| worker::Error::RustError("server_error".into()))?;
    let ui_locales = url::Url::parse(&login.authorization_url)
        .ok()
        .and_then(|url| {
            url.query_pairs()
                .find(|(key, _)| key == "ui_locales")
                .map(|(_, value)| value.into_owned())
        });
    let strings = crate::i18n::catalog(crate::i18n::select(&request, ui_locales.as_deref())?);
    let enrollment = login.client_id == "mikaki-internal-enrollment";
    let html = format!(
        r#"<!doctype html><html lang="{locale}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>{title}</title><link rel="stylesheet" href="/login/login.css"></head><body><div id="app" data-tx="{tx}" data-challenge="{challenge}" data-rp-id="{rp_id}" data-client="{client}" data-enrollment="{enrollment}"></div><script type="module" src="/login/login.js"></script></body></html>"#,
        locale = strings.locale,
        title = crate::i18n::html_escape(strings.message(if enrollment {
            "enrollHeading"
        } else {
            "title"
        })),
        client = crate::i18n::html_escape(if enrollment {
            "mikaki"
        } else {
            &login.client_id
        }),
        enrollment = if enrollment { "true" } else { "false" },
        challenge = login.challenge,
    );
    worker::Response::builder()
        .with_header("Cache-Control", "no-store")?
        .with_header("Referrer-Policy", "no-referrer")?
        .with_header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'",
        )?
        .from_html(html)
}

pub(super) async fn script(
    _request: worker::Request,
    _context: worker::RouteContext<()>,
) -> worker::Result<worker::Response> {
    Ok(worker::Response::builder()
        .with_header("Content-Type", "text/javascript; charset=utf-8")?
        .with_header("Cache-Control", "no-store")?
        .with_header("X-Content-Type-Options", "nosniff")?
        .fixed(
            include_str!(concat!(env!("OUT_DIR"), "/login.js"))
                .as_bytes()
                .to_vec(),
        ))
}

pub(super) async fn stylesheet(
    _request: worker::Request,
    _context: worker::RouteContext<()>,
) -> worker::Result<worker::Response> {
    Ok(worker::Response::builder()
        .with_header("Content-Type", "text/css; charset=utf-8")?
        .with_header("Cache-Control", "no-store")?
        .with_header("X-Content-Type-Options", "nosniff")?
        .fixed(
            include_str!(concat!(env!("OUT_DIR"), "/login.css"))
                .as_bytes()
                .to_vec(),
        ))
}

pub(super) async fn finish(
    mut request: worker::Request,
    context: worker::RouteContext<()>,
) -> worker::Result<worker::Response> {
    let issuer = context
        .env
        .var("MIKAKI_ISSUER")
        .map_err(|_| worker::Error::RustError("server_error".into()))?
        .to_string();
    let issuer = configured_issuer(&issuer)
        .ok_or_else(|| worker::Error::RustError("server_error".into()))?;
    if request.headers().get("origin")?.as_deref() != Some(issuer.as_str()) {
        return Ok(worker::Response::builder().with_status(403).empty());
    }
    let Some(browser) = browser_cookie(&request, "__Host-op-browser")? else {
        return Ok(worker::Response::builder().with_status(403).empty());
    };
    let db = context.env.d1("DB")?;
    let policy = WorkerRuntimePolicy::from_db(&db).await?;
    let body = read_bounded_body(&mut request, policy.form_body_bytes).await?;
    mikaki_webauthn::strict_json(&body, policy.form_body_bytes, 16)
        .map_err(|_| worker::Error::RustError("invalid_request".into()))?;
    let input: LoginFinishInput = serde_json::from_str(&body)
        .map_err(|_| worker::Error::RustError("invalid_request".into()))?;
    if !input.consent || !valid_tx(&input.tx) {
        return Ok(worker::Response::builder().with_status(400).empty());
    }
    let browser_hash = hash(&browser);
    let Some(login) = transaction(&db, &input.tx, &browser_hash).await? else {
        return Ok(worker::Response::builder().with_status(400).empty());
    };
    let credential = db
        .prepare(
            "SELECT cr.credential_id,cr.account_id,a.epoch,p.public_key,p.user_handle,p.counter, \
         p.backup_eligible,p.revision FROM credential cr \
         JOIN account_security a ON a.account_id=cr.account_id \
         JOIN passkey_credential p ON p.credential_id=cr.credential_id \
         WHERE cr.credential_id=?1 AND cr.active=1 AND a.active=1",
        )
        .bind(&[JsValue::from_str(&input.response.id)])?
        .first::<PasskeyCredentialRow>(None)
        .await?;
    let Some(credential) = credential else {
        return Ok(worker::Response::builder().with_status(401).empty());
    };
    let rp_id = url::Url::parse(&issuer)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .ok_or_else(|| worker::Error::RustError("server_error".into()))?;
    let now = now_seconds().ok_or_else(|| worker::Error::RustError("server_error".into()))?;
    let ceremony = mikaki_auth::Ceremony {
        purpose: "authenticate".into(),
        browser_hash: browser_hash.clone(),
        expires_at: login.expires_at as u64,
        failures: login.failures,
        consumed: false,
        context: mikaki_webauthn::Context {
            challenge: login.challenge.clone(),
            origin: issuer,
            rp_id,
            max_bytes: policy.form_body_bytes,
            max_depth: 16,
            user_verification: Default::default(),
            authentication: Default::default(),
            algorithms: vec![-7],
            attestation: None,
            attestation_policy: Default::default(),
        },
    };
    let stored = mikaki_webauthn::StoredCredential {
        id: credential.credential_id.clone(),
        public_key: credential.public_key,
        user_handle: credential.user_handle,
        counter: credential.counter,
        backup_eligible: credential.backup_eligible == 1,
    };
    let proof = match ceremony.authenticate(&browser_hash, now, 5, &stored, input.response) {
        Ok(proof) => proof,
        Err(_) => {
            db.prepare("UPDATE login_transaction SET failures=failures+1 WHERE tx_id=?1 AND browser_hash=?2 AND consumed=0 AND failures<5")
                .bind(&[JsValue::from_str(&input.tx),JsValue::from_str(&browser_hash)])?
                .run().await?;
            return Ok(worker::Response::builder().with_status(401).empty());
        }
    };
    if !proof.user_verified() {
        return Ok(worker::Response::builder().with_status(401).empty());
    }
    let mut random = WorkersCryptoRandom;
    let sso_id = random_secret(&mut random)?;
    let sso_secret = random_secret(&mut random)?;
    let sso_hash = hash(&sso_secret);
    db.batch(vec![
        db.prepare("UPDATE login_transaction SET consumed=1 WHERE tx_id=?1 AND browser_hash=?2 AND consumed=0 AND failures<5 AND expires_at>?3")
            .bind(&[JsValue::from_str(&input.tx),JsValue::from_str(&browser_hash),JsValue::from_f64(now as f64)])?,
        db.prepare("INSERT INTO atomic_guard(operation_id,passed) VALUES(?1,CASE WHEN changes()=1 THEN 1 ELSE 0 END)")
            .bind(&[JsValue::from_str(&sso_id)])?,
        db.prepare("UPDATE passkey_credential SET counter=?1,backup_state=?2,revision=revision+1 WHERE credential_id=?3 AND revision=?4")
            .bind(&[JsValue::from_f64(proof.counter() as f64),JsValue::from_f64(f64::from(proof.backup_state())),JsValue::from_str(&credential.credential_id),JsValue::from_f64(credential.revision as f64)])?,
        db.prepare("INSERT INTO atomic_guard(operation_id,passed) VALUES(?1,CASE WHEN changes()=1 THEN 1 ELSE 0 END)")
            .bind(&[JsValue::from_str(&format!("{sso_id}-passkey"))])?,
        db.prepare("INSERT INTO sso_session(sso_id,account_id,credential_id,epoch,expires_at,revoked) SELECT ?1,a.account_id,?3,a.epoch,?4,0 FROM account_security a JOIN credential cr ON cr.account_id=a.account_id AND cr.credential_id=?3 AND cr.active=1 WHERE a.account_id=?2 AND a.active=1 AND a.epoch=?5")
            .bind(&[JsValue::from_str(&sso_id),JsValue::from_str(&credential.account_id),JsValue::from_str(&credential.credential_id),JsValue::from_f64((now+policy.sso_absolute_ttl_seconds()) as f64),JsValue::from_f64(credential.epoch as f64)])?,
        db.prepare("INSERT INTO atomic_guard(operation_id,passed) VALUES(?1,CASE WHEN changes()=1 THEN 1 ELSE 0 END)")
            .bind(&[JsValue::from_str(&format!("{sso_id}-sso"))])?,
        db.prepare("INSERT INTO sso_context(sso_id,secret_hash,auth_time) VALUES(?1,?2,?3)")
            .bind(&[JsValue::from_str(&sso_id),JsValue::from_str(&sso_hash),JsValue::from_f64(now as f64)])?,
        db.prepare("INSERT INTO app_connection(account_id,client_id,grant_version,active) VALUES(?1,?2,1,1) ON CONFLICT(account_id,client_id) DO UPDATE SET grant_version=CASE WHEN active=0 THEN grant_version+1 ELSE grant_version END,active=1")
            .bind(&[JsValue::from_str(&credential.account_id),JsValue::from_str(&login.client_id)])?,
        db.prepare("DELETE FROM atomic_guard WHERE operation_id=?1")
            .bind(&[JsValue::from_str(&sso_id)])?,
        db.prepare("DELETE FROM atomic_guard WHERE operation_id=?1")
            .bind(&[JsValue::from_str(&format!("{sso_id}-passkey"))])?,
        db.prepare("DELETE FROM atomic_guard WHERE operation_id=?1")
            .bind(&[JsValue::from_str(&format!("{sso_id}-sso"))])?,
    ]).await?;
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
