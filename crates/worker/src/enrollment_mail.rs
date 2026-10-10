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
    let result = db.prepare("UPDATE enrollment_mail SET state='sending',lease_token=?2,lease_until=?3+120,attempts=attempts+1,last_attempt_at=?3 WHERE id=?1 AND kind='invitation' AND attempts<5 AND expires_at>?3 AND next_attempt_at<=?3 AND (state IN ('pending','failed') OR (state='sending' AND lease_until<=?3)) AND EXISTS(SELECT 1 FROM enrollment_waitlist w WHERE w.id=waitlist_id AND (kind='confirmation' AND w.verified_at IS NULL AND w.confirmation_hash=token_hash OR kind='invitation' AND w.invite_hash=token_hash AND EXISTS(SELECT 1 FROM enrollment_invite i WHERE i.invite_hash=token_hash AND i.consumed_at IS NULL AND i.revoked=0 AND i.expires_at>?3))) RETURNING id")
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
    let link = format!(
        "{issuer}/enroll?lang={}#invite={}",
        row.locale,
        secret.as_str()
    );
    let (subject, introduction, action, fallback) = if japanese {
        (
            "mikakiへの招待",
            "招待が承認されました。次のリンクからPasskeyを作成してmikakiを始められます。",
            "mikakiを始める",
            "リンクが開けない場合の招待コード",
        )
    } else {
        (
            "Your mikaki invitation",
            "Your invitation is approved. Follow the link to create a Passkey and start using mikaki.",
            "Start using mikaki",
            "Invitation code if the link does not work",
        )
    };
    let expiry_label = if japanese {
        "有効期限 (UTC)"
    } else {
        "Expires at (UTC)"
    };
    let text = format!(
        "{introduction}\n\n{link}\n\n{expiry_label}: {expiry}\n{fallback}: {}",
        secret.as_str()
    );
    let escaped_link = super::i18n::html_escape(&link);
    let html = format!(
        "<div style=\"font-family:system-ui,sans-serif;line-height:1.6;overflow-wrap:anywhere\"><p>{}</p><p><a href=\"{escaped_link}\" style=\"display:inline-block;padding:12px 20px;background:#1f2937;color:#fff;text-decoration:none;border-radius:6px\">{}</a></p><p>{}: {}</p><p style=\"font-size:12px\">{}: <code>{}</code></p></div>",
        super::i18n::html_escape(introduction),
        super::i18n::html_escape(action),
        super::i18n::html_escape(expiry_label),
        super::i18n::html_escape(&expiry),
        super::i18n::html_escape(fallback),
        secret.as_str(),
    );
    let message = js_sys::JSON::parse(&serde_json::to_string(&serde_json::json!({
        "from":{"email":from,"name":"mikaki"},"to":row.email,"subject":subject,"text":text,"html":html,
    }))?)?;
    let binding = Reflect::get(env, &"ENROLLMENT_EMAIL".into())?;
    let args = [message];
    let sent = match futures_util::future::select(
        Box::pin(call(&binding, "send", &args)),
        Box::pin(worker::Delay::from(std::time::Duration::from_secs(30))),
    )
    .await
    {
        futures_util::future::Either::Left((sent, _)) => sent?,
        futures_util::future::Either::Right(_) => return Err(unavailable()),
    };
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
    db.prepare("UPDATE enrollment_mail SET state='cancelled',lease_token=NULL,lease_until=0 WHERE state IN ('pending','failed','sending') AND (kind='confirmation' OR expires_at<=unixepoch() OR NOT EXISTS(SELECT 1 FROM enrollment_waitlist w WHERE w.id=waitlist_id AND (kind='confirmation' AND w.verified_at IS NULL AND w.confirmation_hash=token_hash OR kind='invitation' AND w.invite_hash=token_hash AND EXISTS(SELECT 1 FROM enrollment_invite i WHERE i.invite_hash=token_hash AND i.consumed_at IS NULL AND i.revoked=0 AND i.expires_at>unixepoch()))))")
        .run().await?;
    // A Worker terminated during its final attempt must leave a manually retryable state.
    db.prepare("UPDATE enrollment_mail SET state='failed',lease_token=NULL,lease_until=0 WHERE state='sending' AND attempts>=5 AND lease_until<=unixepoch()")
        .run().await?;
    #[derive(Deserialize)]
    struct Id {
        id: String,
    }
    let rows = db.prepare("SELECT id FROM enrollment_mail WHERE kind='invitation' AND expires_at>unixepoch() AND next_attempt_at<=unixepoch() AND attempts<5 AND (state IN ('pending','failed') OR state='sending' AND lease_until<=unixepoch()) ORDER BY created_at LIMIT 20")
        .all().await?.results::<Id>()?;
    for row in rows {
        deliver(env, &row.id).await?;
    }
    db.batch(vec![
        db.prepare("DELETE FROM enrollment_request_window WHERE window_start<unixepoch()-7200"),
        db.prepare("UPDATE enrollment_mail SET state='cancelled',lease_token=NULL,lease_until=0 WHERE expires_at<=unixepoch() AND state IN ('pending','failed','sending')"),
        db.prepare("DELETE FROM enrollment_waitlist WHERE id IN (SELECT w.id FROM enrollment_waitlist w LEFT JOIN enrollment_invite i ON i.invite_hash=w.invite_hash WHERE w.verified_at IS NULL AND w.invite_hash IS NULL AND CASE WHEN w.confirmation_expires_at=0 THEN w.created_at ELSE w.confirmation_sent_at END<unixepoch()-2592000 OR i.consumed_at<unixepoch()-2592000 LIMIT 100)"),
    ]).await?;
    Ok(())
}
