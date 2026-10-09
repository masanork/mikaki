//! Durable delivery: retries derive the same opaque token; D1 retains only its hash.
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use js_sys::{Array, Function, Promise, Reflect, Uint8Array};
use serde::Deserialize;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use zeroize::Zeroizing;

fn unavailable() -> worker::Error {
    worker::Error::RustError("enrollment_mail_unavailable".into())
}
async fn call(object: &JsValue, method: &str, values: &[JsValue]) -> worker::Result<JsValue> {
    let function = Reflect::get(object, &method.into())?
        .dyn_into::<Function>()
        .map_err(|_| unavailable())?;
    let args = Array::new();
    for value in values {
        args.push(value);
    }
    // RPC method proxies interpret `.apply` as a remote method. Use the intrinsic,
    // then assimilate the RPC thenable as well as ordinary WebCrypto promises.
    let promise = Promise::resolve(&Reflect::apply(&function, object, &args)?);
    JsFuture::from(promise).await.map_err(|_| unavailable())
}
pub(crate) fn ready(env: &worker::Env) -> bool {
    env.secret("WAITLIST_MAIL_KEY").is_ok_and(|key| {
        let encoded = Zeroizing::new(key.to_string());
        URL_SAFE_NO_PAD
            .decode(encoded.as_bytes())
            .is_ok_and(|bytes| Zeroizing::new(bytes).len() == 32)
    }) && env
        .var("MIKAKI_WAITLIST_FROM")
        .is_ok_and(|from| !from.to_string().is_empty())
        && Reflect::get(env, &"ENROLLMENT_EMAIL".into())
            .is_ok_and(|v| Reflect::get(&v, &"send".into()).is_ok_and(|send| send.is_function()))
}
pub(crate) async fn token(env: &worker::Env, kind: &str, id: &str) -> worker::Result<String> {
    let encoded = Zeroizing::new(env.secret("WAITLIST_MAIL_KEY")?.to_string());
    let bytes = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(encoded.as_bytes())
            .map_err(|_| unavailable())?,
    );
    if bytes.len() != 32 {
        return Err(unavailable());
    }
    let crypto = Reflect::get(&js_sys::global(), &"crypto".into())?;
    let subtle = Reflect::get(&crypto, &"subtle".into())?;
    let key = call(
        &subtle,
        "importKey",
        &[
            "raw".into(),
            Uint8Array::from(bytes.as_slice()).into(),
            js_sys::JSON::parse(r#"{"name":"HMAC","hash":"SHA-256"}"#)?,
            false.into(),
            Array::of1(&"sign".into()).into(),
        ],
    )
    .await?;
    let input = format!("mikaki-enrollment-mail-v1:{kind}:{id}");
    let signature = call(
        &subtle,
        "sign",
        &[
            "HMAC".into(),
            key,
            Uint8Array::from(input.as_bytes()).into(),
        ],
    )
    .await?;
    Ok(URL_SAFE_NO_PAD.encode(Uint8Array::new(&signature).to_vec()))
}

#[derive(Deserialize)]
struct Mail {
    id: String,
    kind: String,
    token_hash: String,
    expires_at: i64,
    attempts: u32,
    email: String,
    locale: String,
}
pub(crate) async fn deliver(env: &worker::Env, id: &str) -> worker::Result<()> {
    let db = env.d1("DB")?;
    let now = super::now_seconds().ok_or_else(unavailable)? as i64;
    let lease = super::passkey_login::random_secret(&mut super::WorkersCryptoRandom)?;
    // Claim only the current, unconsumed capability. Concurrent requests cannot both send.
    let result = db.prepare("UPDATE enrollment_mail SET state='sending',lease_token=?2,lease_until=?3+120,attempts=attempts+1,last_attempt_at=?3 WHERE id=?1 AND attempts<5 AND expires_at>?3 AND next_attempt_at<=?3 AND (state IN ('pending','failed') OR (state='sending' AND lease_until<=?3)) AND EXISTS(SELECT 1 FROM enrollment_waitlist w WHERE w.id=waitlist_id AND (kind='confirmation' AND w.verified_at IS NULL AND w.confirmation_hash=token_hash OR kind='invitation' AND w.invite_hash=token_hash AND EXISTS(SELECT 1 FROM enrollment_invite i WHERE i.invite_hash=token_hash AND i.consumed_at IS NULL AND i.revoked=0 AND i.expires_at>?3))) RETURNING id")
        .bind(&[id.into(),lease.clone().into(),JsValue::from_f64(now as f64)])?.first::<serde_json::Value>(None).await?;
    if result.is_none() {
        return Ok(());
    }
    let row = db.prepare("SELECT m.id,m.kind,m.token_hash,m.expires_at,m.attempts,w.email,w.locale FROM enrollment_mail m JOIN enrollment_waitlist w ON w.id=m.waitlist_id WHERE m.id=?1 AND m.lease_token=?2")
        .bind(&[id.into(),lease.clone().into()])?.first::<Mail>(None).await?.ok_or_else(unavailable)?;
    let result = send(env, &row).await;
    match result {
        Ok(message_id) => {
            db.prepare("UPDATE enrollment_mail SET state='sent',message_id=?3,lease_token=NULL,lease_until=0 WHERE id=?1 AND lease_token=?2")
                .bind(&[id.into(),lease.into(),message_id.into()])?.run().await?;
        }
        Err(_) => {
            let delay = 60 * 2_i64.pow(row.attempts.min(5));
            db.prepare("UPDATE enrollment_mail SET state='failed',next_attempt_at=?3,lease_token=NULL,lease_until=0 WHERE id=?1 AND lease_token=?2")
                .bind(&[id.into(),lease.into(),JsValue::from_f64((now+delay) as f64)])?.run().await?;
            worker::console_error!("{{\"event\":\"enrollment_mail_send_failed\"}}");
        }
    }
    Ok(())
}
async fn send(env: &worker::Env, row: &Mail) -> worker::Result<String> {
    let secret = Zeroizing::new(token(env, &row.kind, &row.id).await?);
    // A key replacement must never send a token that differs from the committed verifier.
    if super::passkey_login::hash(&secret) != row.token_hash {
        return Err(unavailable());
    }
    let issuer = env.var("MIKAKI_ISSUER")?.to_string();
    let issuer = super::configured_issuer(&issuer).ok_or_else(unavailable)?;
    let from = env.var("MIKAKI_WAITLIST_FROM")?.to_string();
    let japanese = row.locale == "ja";
    let expiry: String = js_sys::Date::new(&JsValue::from_f64(row.expires_at as f64 * 1000.0))
        .to_iso_string()
        .into();
    let link = if row.kind == "confirmation" {
        format!(
            "{issuer}/waitlist?lang={}#confirm={}",
            row.locale,
            secret.as_str()
        )
    } else {
        format!("{issuer}/enroll?lang={}", row.locale)
    };
    let (subject, text) = if row.kind == "confirmation" {
        if japanese {
            (
                "mikaki 招待希望のメール確認",
                format!(
                    "mikakiへの招待を希望する場合は、次のページでメールアドレスを確認してください。\n\n{link}\n\n有効期限 (UTC): {}\n心当たりがなければ、このメールは破棄してください。",
                    expiry
                ),
            )
        } else {
            (
                "Confirm your mikaki invitation request",
                format!(
                    "Confirm your email address on this page to join the mikaki waiting list:\n\n{link}\n\nExpires at (UTC) {}. If you did not request this, ignore this message.",
                    expiry
                ),
            )
        }
    } else if japanese {
        (
            "mikakiへの招待",
            format!(
                "mikakiへの招待が承認されました。次のページで招待コードを入力し、Passkeyを作成してください。\n\n{issuer}/enroll?lang=ja\n\n招待コード: {}\n有効期限 (UTC): {}",
                secret.as_str(),
                expiry
            ),
        )
    } else {
        (
            "Your mikaki invitation",
            format!(
                "Your mikaki invitation is approved. Enter this invitation code and create a Passkey:\n\n{issuer}/enroll?lang=en\n\nInvitation code: {}\nExpires at (UTC) {}.",
                secret.as_str(),
                expiry
            ),
        )
    };
    let escaped_link = super::i18n::html_escape(&link);
    let html = format!(
        "<div style=\"white-space:pre-wrap\">{}</div>",
        super::i18n::html_escape(&text).replace(
            &escaped_link,
            &format!("<a href=\"{escaped_link}\">{escaped_link}</a>")
        )
    );
    let message = js_sys::JSON::parse(&serde_json::to_string(&serde_json::json!({
        "from":{"email":from,"name":"mikaki"},"to":row.email,"subject":subject,"text":text,"html":html,
    }))?)?;
    let binding = Reflect::get(env, &"ENROLLMENT_EMAIL".into())?;
    let sent = call(&binding, "send", &[message]).await?;
    Reflect::get(&sent, &"messageId".into())?
        .as_string()
        .filter(|id| !id.is_empty() && id.len() <= 256)
        .ok_or_else(unavailable)
}
pub(crate) async fn run_due(env: &worker::Env) -> worker::Result<()> {
    if !ready(env) {
        return Ok(());
    }
    let db = env.d1("DB")?;
    // Obsolete jobs must not occupy the bounded retry scan ahead of current mail.
    db.prepare("UPDATE enrollment_mail SET state='cancelled',lease_token=NULL,lease_until=0 WHERE state IN ('pending','failed','sending') AND (expires_at<=unixepoch() OR NOT EXISTS(SELECT 1 FROM enrollment_waitlist w WHERE w.id=waitlist_id AND (kind='confirmation' AND w.verified_at IS NULL AND w.confirmation_hash=token_hash OR kind='invitation' AND w.invite_hash=token_hash AND EXISTS(SELECT 1 FROM enrollment_invite i WHERE i.invite_hash=token_hash AND i.consumed_at IS NULL AND i.revoked=0 AND i.expires_at>unixepoch()))))")
        .run().await?;
    #[derive(Deserialize)]
    struct Id {
        id: String,
    }
    let rows = db.prepare("SELECT id FROM enrollment_mail WHERE expires_at>unixepoch() AND next_attempt_at<=unixepoch() AND attempts<5 AND (state IN ('pending','failed') OR state='sending' AND lease_until<=unixepoch()) ORDER BY created_at LIMIT 20")
        .all().await?.results::<Id>()?;
    for row in rows {
        deliver(env, &row.id).await?;
    }
    db.batch(vec![
        db.prepare("DELETE FROM enrollment_request_window WHERE window_start<unixepoch()-7200"),
        db.prepare("UPDATE enrollment_mail SET state='cancelled',lease_token=NULL,lease_until=0 WHERE expires_at<=unixepoch() AND state IN ('pending','failed','sending')"),
        db.prepare("DELETE FROM enrollment_waitlist WHERE id IN (SELECT w.id FROM enrollment_waitlist w LEFT JOIN enrollment_invite i ON i.invite_hash=w.invite_hash WHERE w.verified_at IS NULL AND w.created_at<unixepoch()-2592000 OR i.consumed_at<unixepoch()-2592000 LIMIT 100)"),
    ]).await?;
    Ok(())
}
