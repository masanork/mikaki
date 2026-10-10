//! Reviewed invitation requests. Email possession is checked when an invitation is used.
use super::*;
use wasm_bindgen::JsValue;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestInput {
    email: String,
    locale: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfirmInput {
    token: String,
}
#[derive(Deserialize)]
struct Policy {
    source_per_hour: u64,
    deployment_per_hour: u64,
    maximum_entries: u64,
}
fn response(value: serde_json::Value, status: u16) -> worker::Result<worker::Response> {
    worker::Response::builder()
        .with_status(status)
        .with_header("Cache-Control", "no-store")?
        .with_header("Referrer-Policy", "no-referrer")?
        .from_json(&value)
}
async fn admit(
    request: &worker::Request,
    db: &worker::d1::D1Database,
    policy: &Policy,
    now: u64,
    confirmation: bool,
) -> worker::Result<bool> {
    let source = request
        .headers()
        .get("CF-Connecting-IP")?
        .unwrap_or_else(|| "unknown".into());
    let window = now / 3600 * 3600;
    let scope = if confirmation {
        "waitlist-confirm"
    } else {
        "waitlist-request"
    };
    let multiplier = if confirmation { 4 } else { 1 };
    let statements = [(passkey_login::hash(&format!("{scope}-source:{source}")),policy.source_per_hour*multiplier),(passkey_login::hash(&format!("{scope}-deployment")),policy.deployment_per_hour*multiplier)]
        .into_iter().map(|(key,limit)| db.prepare("INSERT INTO enrollment_request_window(key_hash,window_start,attempts) SELECT ?1,?2,1 WHERE (SELECT count(*) FROM enrollment_request_window)<10000 OR EXISTS(SELECT 1 FROM enrollment_request_window WHERE key_hash=?1 AND window_start=?2) ON CONFLICT(key_hash,window_start) DO UPDATE SET attempts=attempts+1 WHERE attempts<?3 RETURNING attempts")
            .bind(&[key.into(),JsValue::from_f64(window as f64),JsValue::from_f64(limit as f64)]))
        .collect::<worker::Result<Vec<_>>>()?;
    Ok(db.batch(statements).await?.iter().all(|r| {
        r.results::<serde_json::Value>()
            .is_ok_and(|rows| rows.len() == 1)
    }))
}
fn email(value: &str) -> Option<String> {
    let value = value.trim();
    if value.len() > 254 || !value.is_ascii() {
        return None;
    }
    let (local, domain) = value.split_once('@')?;
    if local.is_empty()
        || local.len() > 64
        || local.starts_with('.')
        || local.ends_with('.')
        || local.contains("..")
        || !local
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".!#$%&'*+-/=?^_`{|}~".contains(&b))
        || !domain.contains('.')
        || domain.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return None;
    }
    Some(value.to_ascii_lowercase())
}
pub async fn request(
    mut request: worker::Request,
    context: worker::RouteContext<()>,
) -> worker::Result<worker::Response> {
    let issuer = enrollment::issuer(&context)?;
    if !enrollment::origin_matches(&request, &issuer)? {
        return response(serde_json::json!({"error":"denied"}), 403);
    }
    let db = context.env.d1("DB")?;
    let policy=db.prepare("SELECT source_per_hour,deployment_per_hour,maximum_entries FROM enrollment_waitlist_policy WHERE id=1").first::<Policy>(None).await?.ok_or("waitlist_policy_missing")?;
    let now = now_seconds().ok_or("server_error")?;
    if !admit(&request, &db, &policy, now, false).await? {
        return response(serde_json::json!({"error":"try_later"}), 429);
    }
    let body = read_bounded_body(&mut request, 2048).await?;
    let input = mikaki_webauthn::strict_json(&body, 2048, 4)
        .ok()
        .and_then(|_| serde_json::from_str::<RequestInput>(&body).ok());
    let Some(input) = input else {
        return response(serde_json::json!({"error":"invalid_request"}), 400);
    };
    let Some(email) = email(&input.email) else {
        return response(serde_json::json!({"error":"invalid_email"}), 400);
    };
    if !matches!(input.locale.as_str(), "ja" | "en") {
        return response(serde_json::json!({"error":"invalid_request"}), 400);
    }
    let id = passkey_login::random_secret(&mut WorkersCryptoRandom)?;
    // Preserve the reviewed schema and previously issued confirmation links.
    // New requests have an inert legacy verifier and never create a mail job.
    let unused = passkey_login::random_secret(&mut WorkersCryptoRandom)?;
    db.prepare("INSERT INTO enrollment_waitlist(id,email,locale,created_at,confirmation_hash,confirmation_expires_at,confirmation_sent_at) SELECT ?1,?2,?3,?4,?5,0,0 WHERE (SELECT count(*) FROM enrollment_waitlist)<?6 ON CONFLICT(email) DO NOTHING")
        .bind(&[id.into(),email.into(),input.locale.into(),JsValue::from_f64(now as f64),passkey_login::hash(&unused).into(),JsValue::from_f64(policy.maximum_entries as f64)])?.run().await?;
    // Do not reveal whether an address is already waiting, invited or registered.
    response(serde_json::json!({"accepted":true}), 202)
}
pub async fn confirm(
    mut request: worker::Request,
    context: worker::RouteContext<()>,
) -> worker::Result<worker::Response> {
    if !enrollment::origin_matches(&request, &enrollment::issuer(&context)?)? {
        return response(serde_json::json!({"error":"denied"}), 403);
    }
    let db = context.env.d1("DB")?;
    let policy=db.prepare("SELECT source_per_hour,deployment_per_hour,maximum_entries FROM enrollment_waitlist_policy WHERE id=1").first::<Policy>(None).await?.ok_or("waitlist_policy_missing")?;
    if !admit(
        &request,
        &db,
        &policy,
        now_seconds().ok_or("server_error")?,
        true,
    )
    .await?
    {
        return response(serde_json::json!({"error":"try_later"}), 429);
    }
    let body = read_bounded_body(&mut request, 1024).await?;
    let input = mikaki_webauthn::strict_json(&body, 1024, 4)
        .ok()
        .and_then(|_| serde_json::from_str::<ConfirmInput>(&body).ok());
    let Some(input) = input.filter(|i| passkey_login::valid_tx(&i.token)) else {
        return response(serde_json::json!({"error":"invalid_confirmation"}), 400);
    };
    let accepted=db.prepare("UPDATE enrollment_waitlist SET verified_at=COALESCE(verified_at,unixepoch()) WHERE confirmation_hash=?1 AND (verified_at IS NOT NULL OR confirmation_expires_at>unixepoch()) RETURNING id")
        .bind(&[passkey_login::hash(&input.token).into()])?.first::<serde_json::Value>(None).await?;
    response(
        serde_json::json!({"confirmed":accepted.is_some()}),
        if accepted.is_some() { 200 } else { 400 },
    )
}
pub async fn list(
    request: worker::Request,
    context: worker::RouteContext<()>,
) -> worker::Result<worker::Response> {
    let db = context.env.d1("DB")?;
    let Some(cookie) = browser_cookie(&request, "__Host-op-sso")? else {
        return response(serde_json::json!({"error":"denied"}), 403);
    };
    if !admin_invitations::authenticated(&db, &passkey_login::hash(&cookie)).await? {
        return response(serde_json::json!({"error":"denied"}), 403);
    }
    let mut cursor = None;
    for (name, value) in request.url()?.query_pairs() {
        if name != "cursor" || cursor.is_some() {
            return response(serde_json::json!({"error":"invalid_cursor"}), 400);
        }
        cursor = value.split_once('.').and_then(|(time, id)| {
            let time = time.parse::<u32>().ok()?;
            passkey_login::valid_tx(id).then(|| (time, id.to_owned()))
        });
        if cursor.is_none() {
            return response(serde_json::json!({"error":"invalid_cursor"}), 400);
        }
    }
    let (time, id) = cursor.unwrap_or((0, String::new()));
    let mut entries=db.prepare("SELECT w.id,w.email,w.created_at,w.verified_at,i.expires_at,CASE WHEN i.consumed_at IS NOT NULL THEN 'registered' WHEN w.invite_hash IS NULL THEN 'waiting' WHEN i.revoked=1 OR i.expires_at<=unixepoch() THEN 'expired' WHEN m.state='failed' THEN 'failed' WHEN m.state IN ('pending','sending') THEN 'sending' ELSE 'invited' END AS status,CASE WHEN m.last_attempt_at>unixepoch()-60 OR m.state IN ('pending','sending') THEN 0 ELSE 1 END AS can_resend FROM enrollment_waitlist w LEFT JOIN enrollment_invite i ON i.invite_hash=w.invite_hash LEFT JOIN enrollment_mail m ON m.token_hash=w.invite_hash AND m.kind='invitation' WHERE (w.created_at>?1 OR w.created_at=?1 AND w.id>?2) ORDER BY w.created_at,w.id LIMIT 101")
        .bind(&[JsValue::from_f64(time as f64),id.into()])?.all().await?.results::<serde_json::Value>()?;
    let next_cursor = if entries.len() > 100 {
        entries.truncate(100);
        entries.last().map(|entry| {
            format!(
                "{}.{}",
                entry["created_at"],
                entry["id"].as_str().unwrap_or_default()
            )
        })
    } else {
        None
    };
    response(
        serde_json::json!({"entries":entries,"next_cursor":next_cursor,"mail_ready":enrollment_mail::ready(&context.env)}),
        200,
    )
}
pub async fn page(
    request: worker::Request,
    _context: worker::RouteContext<()>,
) -> worker::Result<worker::Response> {
    let strings = i18n::catalog(i18n::select(&request, None)?);
    let html = format!(
        "<!doctype html><html lang=\"{}\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>{}</title><link rel=\"stylesheet\" href=\"/ui/product.css\"><link rel=\"icon\" type=\"image/svg+xml\" href=\"/favicon.svg\"></head><body><div id=\"app\"></div><script type=\"module\" src=\"/waitlist/waitlist.js\"></script></body></html>",
        strings.locale,
        i18n::html_escape(strings.message("waitlistTitle"))
    );
    worker::Response::builder().with_header("Cache-Control","no-store")?.with_header("Referrer-Policy","no-referrer")?
        .with_header("Content-Security-Policy","default-src 'none'; img-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")?.from_html(html)
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
            include_str!(concat!(env!("OUT_DIR"), "/waitlist.js"))
                .as_bytes()
                .to_vec(),
        ))
}
