use super::*;
use wasm_bindgen::JsValue;

const CONFIRM_TTL_SECONDS: u64 = 300;
const DELIVERY_DEADLINE_SECONDS: u64 = 2 * 86400;

#[derive(Deserialize)]
struct HintRow {
    sso_id: String,
}

#[derive(Deserialize)]
struct TransactionRow {
    sso_id: String,
    redirect_uri: String,
    state: String,
}

fn invalid(request: &worker::Request) -> worker::Result<worker::Response> {
    let ui_locales = request
        .url()?
        .query_pairs()
        .find(|(key, _)| key == "ui_locales")
        .map(|(_, value)| value.into_owned());
    let strings = i18n::catalog(i18n::select(request, ui_locales.as_deref())?);
    Ok(worker::Response::builder()
        .with_status(400)
        .with_header("Cache-Control", "no-store")?
        .with_header("Content-Type", "text/plain; charset=utf-8")?
        .with_header("Content-Language", strings.locale)?
        .fixed(strings.message("logoutInvalidRequest").as_bytes().to_vec()))
}

fn optional_parameters(
    pairs: impl Iterator<Item = (String, String)>,
    names: &[&str],
) -> Option<HashMap<String, String>> {
    let mut values = HashMap::new();
    for (key, value) in pairs {
        if !names.contains(&key.as_str()) || values.insert(key, value).is_some() {
            return None;
        }
    }
    Some(values)
}

pub(super) async fn get(
    request: worker::Request,
    context: worker::RouteContext<()>,
) -> worker::Result<worker::Response> {
    let db = context.env.d1("DB")?;
    let policy = WorkerRuntimePolicy::from_db(&db).await?;
    let url = request.url()?;
    if url.as_str().len() > policy.request_target_bytes() {
        return invalid(&request);
    }
    let Some(params) = optional_parameters(
        url.query_pairs()
            .map(|(key, value)| (key.into_owned(), value.into_owned())),
        &[
            "id_token_hint",
            "post_logout_redirect_uri",
            "state",
            "ui_locales",
            "lang",
        ],
    ) else {
        return invalid(&request);
    };
    let hint = params.get("id_token_hint").map(String::as_str);
    let redirect = params.get("post_logout_redirect_uri").map(String::as_str);
    let state = params.get("state").map(String::as_str);
    if hint.is_some_and(|value| value.is_empty() || value.len() > policy.jwt_bytes)
        || redirect.is_some_and(|value| value.is_empty() || value.len() > 2048)
        || state
            .is_some_and(|value| value.is_empty() || value.len() > policy.state_bytes().min(2048))
        || (redirect.is_some() && hint.is_none())
    {
        return invalid(&request);
    }
    let redirect_origin = if let Some(redirect) = redirect {
        let Ok(redirect_url) = url::Url::parse(redirect) else {
            return invalid(&request);
        };
        if redirect_url.scheme() != "https" || redirect_url.host().is_none() {
            return invalid(&request);
        }
        redirect_url.origin().ascii_serialization()
    } else {
        String::new()
    };
    let Some(cookie) = browser_cookie(&request, "__Host-op-sso")? else {
        return invalid(&request);
    };
    let cookie_hash = passkey_login::hash(&cookie);
    let now = now_seconds().ok_or_else(|| worker::Error::RustError("server_error".into()))?;
    let primary = db.with_session_constraint(worker::d1::D1SessionConstraint::FirstPrimary)?;
    let matched = if let Some(hint) = hint {
        let hint_hash = passkey_login::hash(hint);
        let statement = if redirect.is_some() {
            "SELECT cs.sso_id FROM token_issue ti \
             JOIN authorization_code ac ON ac.code_hash=ti.code_hash \
             JOIN valid_client_session v ON v.client_id=ac.client_id AND v.sid=ac.sid \
             JOIN client_session cs ON cs.client_id=v.client_id AND cs.sid=v.sid \
             JOIN sso_context sx ON sx.sso_id=cs.sso_id \
             JOIN client_post_logout_redirect_uri r ON r.client_id=v.client_id \
             WHERE ti.id_token_hash=?1 AND sx.secret_hash=?2 \
               AND r.redirect_uri=?3 AND r.active=1"
        } else {
            "SELECT cs.sso_id FROM token_issue ti \
             JOIN authorization_code ac ON ac.code_hash=ti.code_hash \
             JOIN valid_client_session v ON v.client_id=ac.client_id AND v.sid=ac.sid \
             JOIN client_session cs ON cs.client_id=v.client_id AND cs.sid=v.sid \
             JOIN sso_context sx ON sx.sso_id=cs.sso_id \
             WHERE ti.id_token_hash=?1 AND sx.secret_hash=?2"
        };
        let mut bindings = vec![
            JsValue::from_str(&hint_hash),
            JsValue::from_str(&cookie_hash),
        ];
        if let Some(redirect) = redirect {
            bindings.push(JsValue::from_str(redirect));
        }
        primary
            .prepare(statement)
            .bind(&bindings)?
            .first::<HintRow>(None)
            .await?
    } else {
        primary
            .prepare(
                "SELECT ss.sso_id FROM sso_context sx \
                 JOIN sso_session ss ON ss.sso_id=sx.sso_id \
                 WHERE sx.secret_hash=?1 AND ss.revoked=0 AND ss.expires_at>?2",
            )
            .bind(&[
                JsValue::from_str(&cookie_hash),
                JsValue::from_f64(now as f64),
            ])?
            .first::<HintRow>(None)
            .await?
    };
    let Some(matched) = matched else {
        return invalid(&request);
    };
    let mut random = WorkersCryptoRandom;
    let csrf = passkey_login::random_secret(&mut random)?;
    db.prepare(
        "INSERT INTO logout_transaction(csrf_hash,sso_id,cookie_hash,redirect_uri,state,expires_at) \
         VALUES(?1,?2,?3,?4,?5,?6)",
    )
    .bind(&[
        JsValue::from_str(&passkey_login::hash(&csrf)),
        JsValue::from_str(&matched.sso_id),
        JsValue::from_str(&cookie_hash),
        JsValue::from_str(redirect.unwrap_or_default()),
        JsValue::from_str(state.unwrap_or_default()),
        JsValue::from_f64((now + CONFIRM_TTL_SECONDS) as f64),
    ])?
    .run()
    .await?;
    let strings = i18n::catalog(i18n::select(
        &request,
        params.get("ui_locales").map(String::as_str),
    )?);
    let message = |key| i18n::html_escape(strings.message(key));
    let other_locale = if strings.locale == "ja" { "en" } else { "ja" };
    let other_label = if strings.locale == "ja" {
        "English"
    } else {
        "日本語"
    };
    let mut language_url = url.clone();
    language_url.set_query(None);
    language_url
        .query_pairs_mut()
        .extend_pairs(params.iter().filter(|(key, _)| key.as_str() != "lang"))
        .append_pair("lang", other_locale);
    let language_path = format!(
        "{}?{}",
        language_url.path(),
        language_url.query().unwrap_or_default()
    );
    let language = format!(
        "<nav class=\"product-toolbar\"><a href=\"{}\" class=\"product-signout\" lang=\"{}\" aria-label=\"{}\">{}</a></nav>",
        i18n::html_escape(&language_path),
        other_locale,
        message("language"),
        other_label,
    );
    let action = format!(
        "<form method=\"post\" action=\"/logout?lang={}\"><input type=\"hidden\" name=\"csrf\" value=\"{}\"><button class=\"product-button product-primary\" type=\"submit\">{}</button></form><a class=\"product-button\" href=\"/vault?lang={}\">{}</a>",
        strings.locale,
        csrf,
        message("logoutTitle"),
        strings.locale,
        message("productLogoutCancel"),
    );
    let html = render_page(&strings, &url, false, &language, &action);
    let mut response = worker::Response::builder()
        .with_header("Content-Language", strings.locale)?
        .with_header("Content-Type", "text/html; charset=utf-8")?
        .with_header("Cache-Control", "no-store")?
        .with_header("Referrer-Policy", "origin")?
        .with_header("X-Content-Type-Options", "nosniff")?
        .with_header(
            "Content-Security-Policy",
            &format!(
                "default-src 'none'; img-src 'self'; script-src 'self'; style-src 'self'; form-action 'self' {redirect_origin}; base-uri 'none'; frame-ancestors 'none'"
            ),
        )?
        .with_header(
            "Set-Cookie",
            &format!(
                "__Host-op-logout={csrf}; Max-Age={CONFIRM_TTL_SECONDS}; Path=/; Secure; HttpOnly; SameSite=Lax"
            ),
        )?
        .from_html(html)?;
    response.headers_mut().append(
        "Set-Cookie",
        &format!(
            "__Host-op-locale={}; Max-Age=31536000; Path=/; Secure; SameSite=Lax",
            strings.locale
        ),
    )?;
    Ok(response)
}

pub(super) async fn post(
    mut request: worker::Request,
    context: worker::RouteContext<()>,
) -> worker::Result<worker::Response> {
    let Some(content_type) = request.headers().get("content-type")? else {
        return invalid(&request);
    };
    if !content_type.split(';').next().is_some_and(|value| {
        value
            .trim()
            .eq_ignore_ascii_case("application/x-www-form-urlencoded")
    }) {
        return invalid(&request);
    }
    let db = context.env.d1("DB")?;
    let policy = WorkerRuntimePolicy::from_db(&db).await?;
    let body = read_bounded_body(&mut request, policy.form_body_bytes).await?;
    let Some(values) = optional_parameters(
        url::form_urlencoded::parse(body.as_bytes())
            .map(|(key, value)| (key.into_owned(), value.into_owned())),
        &[
            "csrf",
            "id_token_hint",
            "post_logout_redirect_uri",
            "state",
            "ui_locales",
        ],
    ) else {
        return invalid(&request);
    };
    if values.contains_key("csrf") {
        if values.len() != 1 || !vault_http::same_origin(&request)? {
            return invalid(&request);
        }
        return confirm(request, context, &db, &values["csrf"]).await;
    }
    // A top-level cross-site POST does not carry the Lax SSO cookie. Convert
    // the validated form to a same-site GET before showing the confirmation.
    if request.url()?.query().is_some() {
        return invalid(&request);
    }
    let mut destination = request.url()?;
    destination.set_query(None);
    if !values.is_empty() {
        destination.query_pairs_mut().extend_pairs(values.iter());
    }
    if destination.as_str().len() > policy.request_target_bytes() {
        return invalid(&request);
    }
    Ok(worker::Response::builder()
        .with_status(303)
        .with_header("Location", destination.as_str())?
        .with_header("Cache-Control", "no-store")?
        .with_header("Referrer-Policy", "no-referrer")?
        .empty())
}

async fn confirm(
    request: worker::Request,
    context: worker::RouteContext<()>,
    db: &worker::D1Database,
    csrf: &str,
) -> worker::Result<worker::Response> {
    if !passkey_login::valid_tx(csrf) {
        return invalid(&request);
    }
    let (Some(csrf_cookie), Some(sso_cookie)) = (
        browser_cookie(&request, "__Host-op-logout")?,
        browser_cookie(&request, "__Host-op-sso")?,
    ) else {
        return invalid(&request);
    };
    if !bool::from(csrf.as_bytes().ct_eq(csrf_cookie.as_bytes())) {
        return invalid(&request);
    }
    let csrf_hash = passkey_login::hash(csrf);
    let cookie_hash = passkey_login::hash(&sso_cookie);
    let now = now_seconds().ok_or_else(|| worker::Error::RustError("server_error".into()))?;
    let primary = db.with_session_constraint(worker::d1::D1SessionConstraint::FirstPrimary)?;
    let transaction = primary
        .prepare(
            "SELECT sso_id,redirect_uri,state FROM logout_transaction \
             WHERE csrf_hash=?1 AND cookie_hash=?2 AND expires_at>?3",
        )
        .bind(&[
            JsValue::from_str(&csrf_hash),
            JsValue::from_str(&cookie_hash),
            JsValue::from_f64(now as f64),
        ])?
        .first::<TransactionRow>(None)
        .await?;
    let Some(transaction) = transaction else {
        return invalid(&request);
    };
    let mut random = WorkersCryptoRandom;
    let event_id = passkey_login::random_secret(&mut random)?;
    let values = [
        JsValue::from_str(&csrf_hash),
        JsValue::from_str(&cookie_hash),
        JsValue::from_str(&transaction.sso_id),
        JsValue::from_str(&event_id),
        JsValue::from_f64(now as f64),
        JsValue::from_f64((now + DELIVERY_DEADLINE_SECONDS) as f64),
    ];
    let guard = || {
        db.prepare(
            "INSERT INTO atomic_guard(operation_id,passed) VALUES(?4,CASE WHEN changes()=1 THEN 1 ELSE 0 END)",
        )
        .bind(&values[..4])
    };
    let result = db
        .batch(vec![
            db.prepare(
                "DELETE FROM logout_transaction WHERE csrf_hash=?1 AND cookie_hash=?2 \
                 AND sso_id=?3 AND expires_at>?5",
            )
            .bind(&values[..5])?,
            guard()?,
            db.prepare("DELETE FROM atomic_guard WHERE operation_id=?4")
                .bind(&values[..4])?,
            db.prepare(
                "INSERT INTO sso_logout_event(event_id,sso_id,created_at,deadline) \
                 SELECT ?4,sso_id,?5,?6 FROM sso_session \
                 WHERE sso_id=?3 AND revoked=0 AND expires_at>?5",
            )
            .bind(&values)?,
            guard()?,
            db.prepare("DELETE FROM atomic_guard WHERE operation_id=?4")
                .bind(&values[..4])?,
            db.prepare(
                "INSERT INTO logout_delivery(event_id,client_id,sid,sub,logout_uri,next_at) \
                 SELECT ?4,cs.client_id,cs.sid,cs.sub,b.logout_uri,?5 \
                 FROM client_session cs JOIN client_backchannel_logout_uri b \
                   ON b.client_id=cs.client_id AND b.active=1 \
                 JOIN client c ON c.client_id=cs.client_id AND c.active=1 \
                 WHERE cs.sso_id=?3 AND cs.revoked=0",
            )
            .bind(&values[..5])?,
            db.prepare(
                "UPDATE sso_session SET revoked=1 WHERE sso_id=?3 AND revoked=0 \
                 AND expires_at>?5",
            )
            .bind(&values[..5])?,
            guard()?,
            db.prepare("DELETE FROM atomic_guard WHERE operation_id=?4")
                .bind(&values[..4])?,
            db.prepare("UPDATE client_session SET revoked=1 WHERE sso_id=?3 AND revoked=0")
                .bind(&values[..3])?,
        ])
        .await;
    if result.is_err() {
        return invalid(&request);
    }
    // The SSO is already revoked. A failed notification remains leased or
    // pending in the outbox and the minute cron retries it.
    let _ = logout_delivery::run_event(&context.env, &event_id).await;
    let mut response = if transaction.redirect_uri.is_empty() {
        let strings = i18n::catalog(i18n::select(&request, None)?);
        worker::Response::builder()
            .with_header("Content-Language", strings.locale)?
            .with_header("Content-Type", "text/html; charset=utf-8")?
            .with_header("Cache-Control", "no-store")?
            .with_header("Referrer-Policy", "no-referrer")?
            .with_header(
                "Content-Security-Policy",
                "default-src 'none'; img-src 'self'; script-src 'self'; style-src 'self'; base-uri 'none'; frame-ancestors 'none'",
            )?
            .from_html(render_page(
                &strings,
                &request.url()?,
                true,
                "",
                &format!(
                    "<a class=\"product-button\" href=\"/?lang={}\">{}</a>",
                    strings.locale,
                    i18n::html_escape(strings.message("productHomeLink")),
                ),
            ))?
    } else {
        let mut destination = url::Url::parse(&transaction.redirect_uri)
            .map_err(|_| worker::Error::RustError("invalid registered redirect".into()))?;
        if !transaction.state.is_empty() {
            destination
                .query_pairs_mut()
                .append_pair("state", &transaction.state);
        }
        worker::Response::builder()
            .with_status(302)
            .with_header("Location", destination.as_str())?
            .with_header("Cache-Control", "no-store")?
            .with_header("Referrer-Policy", "no-referrer")?
            .empty()
    };
    response.headers_mut().append(
        "Set-Cookie",
        "__Host-op-sso=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax",
    )?;
    response.headers_mut().append(
        "Set-Cookie",
        "__Host-op-logout=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax",
    )?;
    Ok(response)
}

fn render_page(
    strings: &i18n::Catalog,
    page: &url::Url,
    complete: bool,
    language: &str,
    action: &str,
) -> String {
    let message = |key| i18n::html_escape(strings.message(key));
    let template = include_str!("../ui/logout.html");
    let values = [
        ("{{skip_content}}", message("productSkipContent")),
        ("{{origin_label}}", message("authOriginLabel")),
        (
            "{{page_host}}",
            i18n::html_escape(&match page.port() {
                Some(port) => format!("{}:{port}", page.host_str().unwrap_or_default()),
                None => page.host_str().unwrap_or_default().to_owned(),
            }),
        ),
        (
            "{{session_state}}",
            if complete { "ended" } else { "confirm" }.to_owned(),
        ),
        ("{{locale}}", strings.locale.to_owned()),
        (
            "{{title}}",
            message(if complete {
                "logoutCompleteTitle"
            } else {
                "logoutTitle"
            }),
        ),
        (
            "{{heading}}",
            message(if complete {
                "logoutCompleteHeading"
            } else {
                "logoutTitle"
            }),
        ),
        (
            "{{body}}",
            message(if complete {
                "productLogoutCompleteBody"
            } else {
                "logoutBody"
            }),
        ),
        (
            "{{icon_class}}",
            if complete { "is-success" } else { "" }.to_owned(),
        ),
        (
            "{{icon}}",
            if complete {
                "<path d=\"m5 12 4 4L19 6\"/>"
            } else {
                "<path d=\"M9 5H5v14h4M13 8l4 4-4 4M8 12h13\"/>"
            }
            .to_owned(),
        ),
        ("{{language}}", language.to_owned()),
        ("{{action}}", action.to_owned()),
    ];
    let mut html = String::with_capacity(template.len() + 512);
    let mut remainder = template;
    while let Some(start) = remainder.find("{{") {
        html.push_str(&remainder[..start]);
        let tail = &remainder[start..];
        let Some(end) = tail.find("}}") else {
            html.push_str(tail);
            return html;
        };
        let marker = &tail[..end + 2];
        if let Some((_, value)) = values.iter().find(|(key, _)| *key == marker) {
            html.push_str(value);
        } else {
            html.push_str(marker);
        }
        remainder = &tail[end + 2..];
    }
    html.push_str(remainder);
    html
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
            include_str!(concat!(env!("OUT_DIR"), "/logout.js"))
                .as_bytes()
                .to_vec(),
        ))
}
