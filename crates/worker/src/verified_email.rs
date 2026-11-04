//! Experimental account-bound email confirmation. No OIDC claims are emitted here.
use js_sys::Reflect;
use serde::Deserialize;
use wasm_bindgen::JsValue;
use worker::{Request, Response, RouteContext};
use zeroize::Zeroizing;

use crate::vault_http::{error, owner, same_origin};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Confirmation {
    token: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Release {
    client_id: String,
    action: String,
}

pub async fn remove(request: Request, context: RouteContext<()>) -> worker::Result<Response> {
    if !context
        .env
        .var("MIKAKI_VERIFIED_EMAIL")
        .is_ok_and(|v| v.to_string() == "on")
    {
        return error(404, "not_found");
    }
    if !same_origin(&request)? {
        return error(403, "origin_required");
    }
    let db = context.env.d1("DB")?;
    let Some(actor) = owner(&request, &db).await? else {
        return error(401, "authentication_required");
    };
    let operation = crate::passkey_login::random_secret(&mut crate::WorkersCryptoRandom)?;
    let result = db.batch(vec![
        db.prepare("UPDATE account_verified_email SET email='removed',active=0,revision=revision+1 WHERE account_id=?1 AND active=1 AND EXISTS(SELECT 1 FROM sso_context sx JOIN sso_session ss ON ss.sso_id=sx.sso_id JOIN account_security a ON a.account_id=ss.account_id JOIN credential c ON c.credential_id=ss.credential_id AND c.account_id=a.account_id WHERE sx.secret_hash=?2 AND a.account_id=?1 AND a.active=1 AND a.epoch=ss.epoch AND ss.revoked=0 AND ss.expires_at>unixepoch() AND c.active=1 AND NOT EXISTS(SELECT 1 FROM dbsc_session d WHERE d.sso_id=ss.sso_id AND d.cookie_expires_at<=unixepoch()))").bind(&[JsValue::from_str(&actor.account_id),JsValue::from_str(&actor.secret_hash)])?,
        db.prepare("INSERT INTO atomic_guard(operation_id,passed) VALUES(?1,CASE WHEN changes()=1 THEN 1 ELSE 0 END)").bind(&[JsValue::from_str(&operation)])?,
        db.prepare("DELETE FROM account_email_challenge WHERE account_id=?1").bind(&[JsValue::from_str(&actor.account_id)])?,
        db.prepare("DELETE FROM atomic_guard WHERE operation_id=?1").bind(&[JsValue::from_str(&operation)])?,
    ]).await;
    if result.is_err() {
        return error(409, "email_unavailable");
    }
    Response::builder()
        .with_header("Cache-Control", "no-store")?
        .from_json(&serde_json::json!({"active":false}))
}

pub async fn status(request: Request, context: RouteContext<()>) -> worker::Result<Response> {
    if !context
        .env
        .var("MIKAKI_VERIFIED_EMAIL")
        .is_ok_and(|v| v.to_string() == "on")
    {
        return error(404, "not_found");
    }
    let db = context.env.d1("DB")?;
    let Some(actor) = owner(&request, &db).await? else {
        return error(401, "authentication_required");
    };
    let email = db.prepare("SELECT e.email,e.revision,e.verified_at FROM account_verified_email e JOIN account_security a ON a.account_id=e.account_id AND a.active=1 AND a.epoch=e.account_epoch WHERE e.account_id=?1 AND e.active=1").bind(&[JsValue::from_str(&actor.account_id)])?.first::<serde_json::Value>(None).await?;
    let clients = db.prepare("SELECT c.client_id,CASE WHEN v.client_id IS NULL THEN 0 ELSE 1 END AS released FROM client c JOIN client_email_policy p ON p.client_id=c.client_id AND p.client_revision=c.revision AND p.enabled=1 JOIN app_connection g ON g.client_id=c.client_id AND g.active=1 AND g.account_id=?1 LEFT JOIN eligible_verified_email_release v ON v.account_id=g.account_id AND v.client_id=g.client_id WHERE c.active=1 ORDER BY c.client_id LIMIT 100").bind(&[JsValue::from_str(&actor.account_id)])?.all().await?.results::<serde_json::Value>()?;
    Response::builder()
        .with_header("Cache-Control", "no-store")?
        .from_json(&serde_json::json!({"email":email,"clients":clients}))
}

pub async fn release(mut request: Request, context: RouteContext<()>) -> worker::Result<Response> {
    if !context
        .env
        .var("MIKAKI_VERIFIED_EMAIL")
        .is_ok_and(|v| v.to_string() == "on")
    {
        return error(404, "not_found");
    }
    if !same_origin(&request)? {
        return error(403, "origin_required");
    }
    if request.headers().get("Content-Type")?.as_deref() != Some("application/json") {
        return error(415, "json_required");
    }
    let db = context.env.d1("DB")?;
    let Some(actor) = owner(&request, &db).await? else {
        return error(401, "authentication_required");
    };
    let body = match crate::read_bounded_body(&mut request, 512).await {
        Ok(body) => body,
        Err(_) => return error(413, "body_too_large_or_invalid"),
    };
    let Ok(body) = serde_json::from_str::<Release>(&body) else {
        return error(400, "invalid_body");
    };
    if body.client_id.is_empty()
        || body.client_id.len() > 128
        || body.client_id.bytes().any(|b| b.is_ascii_control())
        || !["grant", "revoke"].contains(&body.action.as_str())
    {
        return error(400, "invalid_body");
    }
    let args = [
        JsValue::from_str(&actor.account_id),
        JsValue::from_str(&body.client_id),
        JsValue::from_str(&actor.secret_hash),
    ];
    let session = "EXISTS(SELECT 1 FROM sso_context sx JOIN sso_session ss ON ss.sso_id=sx.sso_id JOIN account_security a ON a.account_id=ss.account_id JOIN credential cr ON cr.credential_id=ss.credential_id AND cr.account_id=a.account_id WHERE sx.secret_hash=?3 AND a.account_id=?1 AND a.active=1 AND a.epoch=ss.epoch AND ss.revoked=0 AND ss.expires_at>unixepoch() AND cr.active=1 AND NOT EXISTS(SELECT 1 FROM dbsc_session d WHERE d.sso_id=ss.sso_id AND d.cookie_expires_at<=unixepoch()))";
    let sql = if body.action == "grant" {
        format!(
            "INSERT INTO account_email_release(account_id,client_id,email_revision,account_epoch,client_revision,grant_version,active) SELECT e.account_id,c.client_id,e.revision,a.epoch,c.revision,g.grant_version,1 FROM account_verified_email e JOIN account_security a ON a.account_id=e.account_id AND a.active=1 AND a.epoch=e.account_epoch JOIN app_connection g ON g.account_id=e.account_id AND g.active=1 JOIN client c ON c.client_id=g.client_id AND c.active=1 JOIN client_email_policy p ON p.client_id=c.client_id AND p.enabled=1 AND p.client_revision=c.revision WHERE e.account_id=?1 AND c.client_id=?2 AND e.active=1 AND {session} ON CONFLICT(account_id,client_id) DO UPDATE SET email_revision=excluded.email_revision,account_epoch=excluded.account_epoch,client_revision=excluded.client_revision,grant_version=excluded.grant_version,active=1,revision=account_email_release.revision+1"
        )
    } else {
        format!(
            "UPDATE account_email_release SET active=0,revision=revision+1 WHERE account_id=?1 AND client_id=?2 AND active=1 AND {session}"
        )
    };
    let changed = db.prepare(&sql).bind(&args)?.run().await?;
    if changed.meta()?.is_none_or(|m| m.changes != Some(1)) {
        return error(409, "release_unavailable");
    }
    Response::builder()
        .with_header("Cache-Control", "no-store")?
        .from_json(&serde_json::json!({"active":body.action=="grant"}))
}

pub async fn collect(env: &worker::Env) -> worker::Result<()> {
    if !env
        .var("MIKAKI_VERIFIED_EMAIL")
        .is_ok_and(|v| v.to_string() == "on")
    {
        return Ok(());
    }
    env.d1("DB")?.prepare("DELETE FROM account_email_challenge WHERE challenge_hash IN (SELECT challenge_hash FROM account_email_challenge WHERE expires_at<unixepoch()-86400 ORDER BY expires_at LIMIT 100)").run().await?;
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Start {
    email: String,
}

pub async fn start(mut request: Request, context: RouteContext<()>) -> worker::Result<Response> {
    if !context
        .env
        .var("MIKAKI_VERIFIED_EMAIL")
        .is_ok_and(|v| v.to_string() == "on")
    {
        return error(404, "not_found");
    }
    if !same_origin(&request)? {
        return error(403, "origin_required");
    }
    if request.headers().get("Content-Type")?.as_deref() != Some("application/json") {
        return error(415, "json_required");
    }
    let db = context.env.d1("DB")?;
    let Some(actor) = owner(&request, &db).await? else {
        return error(401, "authentication_required");
    };
    let body = match crate::read_bounded_body(&mut request, 512).await {
        Ok(body) => body,
        Err(_) => return error(413, "body_too_large_or_invalid"),
    };
    let Ok(body) = serde_json::from_str::<Start>(&body) else {
        return error(400, "invalid_body");
    };
    // Reuse the conservative syntax check without folding the potentially
    // case-sensitive local part of the submitted address.
    if crate::enrollment_waitlist::email(&body.email).is_none() {
        return error(400, "invalid_email");
    }
    let email = body.email.trim();
    let from = context.env.var("MIKAKI_WAITLIST_FROM")?.to_string();
    let binding = Reflect::get(context.env.as_ref(), &"ENROLLMENT_EMAIL".into())?;
    let token = Zeroizing::new(crate::passkey_login::random_secret(
        &mut crate::WorkersCryptoRandom,
    )?);
    let hash = crate::passkey_login::hash(&token);
    let operation = crate::passkey_login::random_secret(&mut crate::WorkersCryptoRandom)?;
    let inserted = db.batch(vec![db.prepare("INSERT INTO account_email_challenge(challenge_hash,account_id,email,account_epoch,expected_revision,expires_at) SELECT ?1,a.account_id,?2,a.epoch,coalesce((SELECT revision FROM account_verified_email WHERE account_id=a.account_id),0),unixepoch()+900 FROM account_security a JOIN sso_session s ON s.account_id=a.account_id JOIN sso_context x ON x.sso_id=s.sso_id JOIN credential c ON c.credential_id=s.credential_id AND c.account_id=a.account_id WHERE a.account_id=?3 AND a.active=1 AND s.epoch=a.epoch AND s.revoked=0 AND s.expires_at>unixepoch() AND x.secret_hash=?4 AND c.active=1 AND NOT EXISTS(SELECT 1 FROM dbsc_session d WHERE d.sso_id=s.sso_id AND d.cookie_expires_at<=unixepoch()) AND NOT EXISTS(SELECT 1 FROM account_email_challenge p WHERE p.account_id=a.account_id AND p.expires_at>unixepoch()+840) LIMIT 1")
        .bind(&[JsValue::from_str(&hash),JsValue::from_str(email),JsValue::from_str(&actor.account_id),JsValue::from_str(&actor.secret_hash)])?,
        db.prepare("INSERT INTO atomic_guard(operation_id,passed) VALUES(?1,CASE WHEN changes()=1 THEN 1 ELSE 0 END)").bind(&[JsValue::from_str(&operation)])?,
        db.prepare("UPDATE account_email_challenge SET consumed_at=unixepoch() WHERE account_id=?1 AND challenge_hash<>?2 AND consumed_at IS NULL").bind(&[JsValue::from_str(&actor.account_id),JsValue::from_str(&hash)])?,
        db.prepare("DELETE FROM atomic_guard WHERE operation_id=?1").bind(&[JsValue::from_str(&operation)])?,
    ]).await;
    if inserted.is_err() {
        return error(429, "confirmation_unavailable");
    }
    let text = format!(
        "Your mikaki email confirmation code (valid for 15 minutes):\n\n{}\n\nEnter this code only in your signed-in mikaki account.",
        token.as_str()
    );
    let html = format!(
        "<p>Your mikaki email confirmation code (valid for 15 minutes):</p><p><code>{}</code></p><p>Enter this code only in your signed-in mikaki account.</p>",
        token.as_str()
    );
    let message = js_sys::JSON::parse(&serde_json::to_string(
        &serde_json::json!({"from":{"email":from,"name":"mikaki"},"to":email,"subject":"Confirm your mikaki email", "text":text,"html":html}),
    )?)?;
    let args = [message];
    let sent = futures_util::future::select(
        Box::pin(crate::enrollment_mail::call(&binding, "send", &args)),
        Box::pin(worker::Delay::from(std::time::Duration::from_secs(30))),
    )
    .await;
    match sent {
        futures_util::future::Either::Left((Ok(_), _)) => Response::builder()
            .with_status(202)
            .with_header("Cache-Control", "no-store")?
            .from_json(&serde_json::json!({"accepted":true})),
        // Delivery may have succeeded even when its response was lost. Do not
        // issue a duplicate immediately or claim that no email was sent.
        _ => error(503, "delivery_unconfirmed"),
    }
}

pub async fn confirm(mut request: Request, context: RouteContext<()>) -> worker::Result<Response> {
    if !context
        .env
        .var("MIKAKI_VERIFIED_EMAIL")
        .is_ok_and(|v| v.to_string() == "on")
    {
        return error(404, "not_found");
    }
    if !same_origin(&request)? {
        return error(403, "origin_required");
    }
    if request.headers().get("Content-Type")?.as_deref() != Some("application/json") {
        return error(415, "json_required");
    }
    let db = context.env.d1("DB")?;
    let Some(actor) = owner(&request, &db).await? else {
        return error(401, "authentication_required");
    };
    let body = match crate::read_bounded_body(&mut request, 512).await {
        Ok(body) => body,
        Err(_) => return error(413, "body_too_large_or_invalid"),
    };
    let Ok(body) = serde_json::from_str::<Confirmation>(&body) else {
        return error(400, "invalid_body");
    };
    if !crate::passkey_login::valid_tx(&body.token) {
        return error(400, "invalid_confirmation");
    }
    let hash = crate::passkey_login::hash(&body.token);
    let operation = crate::passkey_login::random_secret(&mut crate::WorkersCryptoRandom)?;
    let args = [
        JsValue::from_str(&hash),
        JsValue::from_str(&actor.account_id),
        JsValue::from_str(&actor.secret_hash),
    ];
    // The challenge, expected email revision, current account epoch, and SSO
    // validity are rechecked inside the same serialized D1 batch as the write.
    let result = db.batch(vec![
        db.prepare("UPDATE account_email_challenge SET consumed_at=unixepoch() WHERE challenge_hash=?1 AND account_id=?2 AND consumed_at IS NULL AND expires_at>unixepoch() AND expected_revision=coalesce((SELECT revision FROM account_verified_email WHERE account_id=?2),0) AND EXISTS(SELECT 1 FROM account_security a JOIN sso_session s ON s.account_id=a.account_id JOIN sso_context x ON x.sso_id=s.sso_id JOIN credential c ON c.credential_id=s.credential_id AND c.account_id=a.account_id WHERE a.account_id=?2 AND a.active=1 AND a.epoch=account_email_challenge.account_epoch AND s.epoch=a.epoch AND s.revoked=0 AND s.expires_at>unixepoch() AND x.secret_hash=?3 AND c.active=1 AND NOT EXISTS(SELECT 1 FROM dbsc_session d WHERE d.sso_id=s.sso_id AND d.cookie_expires_at<=unixepoch()))").bind(&args)?,
        db.prepare("INSERT INTO atomic_guard(operation_id,passed) VALUES(?1,CASE WHEN changes()=1 THEN 1 ELSE 0 END)").bind(&[JsValue::from_str(&operation)])?,
        db.prepare("INSERT INTO account_verified_email(account_id,email,revision,account_epoch,verified_at,active) SELECT account_id,email,expected_revision+1,account_epoch,consumed_at,1 FROM account_email_challenge WHERE challenge_hash=?1 AND account_id=?2 AND consumed_at IS NOT NULL ON CONFLICT(account_id) DO UPDATE SET email=excluded.email,revision=excluded.revision,account_epoch=excluded.account_epoch,verified_at=excluded.verified_at,active=1 WHERE account_verified_email.revision=excluded.revision-1").bind(&args[..2])?,
        db.prepare("INSERT INTO atomic_guard(operation_id,passed) VALUES(?1,CASE WHEN changes()=1 THEN 1 ELSE 0 END)").bind(&[JsValue::from_str(&format!("{operation}:email"))])?,
        db.prepare("DELETE FROM atomic_guard WHERE operation_id IN (?1,?2)").bind(&[JsValue::from_str(&operation),JsValue::from_str(&format!("{operation}:email"))])?,
    ]).await;
    if result.is_err() {
        return error(409, "invalid_or_expired_confirmation");
    }
    Response::builder()
        .with_header("Cache-Control", "no-store")?
        .from_json(&serde_json::json!({"verified":true}))
}
