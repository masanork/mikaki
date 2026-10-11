//! Private owner review shell. The bundle reads existing Native projections;
//! Optional explicit copy consent remains separate from grants, tokens and launch.
use crate::work_owner::{error, unavailable};
use crate::work_store::{StoreError, WorkStore};
use worker::{Env, Method, Request, Response};

pub async fn handle(request: Request, env: Env) -> worker::Result<Response> {
    let copy_page = request.url()?.path().starts_with("/work/copy-review");
    if copy_page
        && !env
            .var("WORK_COPY_EXECUTION_ENABLED")
            .is_ok_and(|v| v.to_string() == "true")
    {
        return error(404, "not_found");
    }
    if !["WORK_PREPARATION_REVIEW_ENABLED", "WORK_SOURCE_API_ENABLED"]
        .iter()
        .all(|key| env.var(key).is_ok_and(|v| v.to_string() == "true"))
    {
        return error(404, "not_found");
    }
    let url = request.url()?;
    if request.method() != Method::Get {
        return error(404, "not_found");
    }
    if request.headers().get("Sec-Fetch-Site")?.as_deref() == Some("cross-site")
        || (request.headers().get("Origin")?.is_some()
            && !crate::vault_http::same_origin(&request)?)
    {
        return error(403, "invalid_origin");
    }
    let page = matches!(url.path(), "/work/preparation-review" | "/work/copy-review");
    let pairs: Vec<_> = url.query_pairs().collect();
    if pairs.len() > 1
        || pairs
            .first()
            .is_some_and(|(k, v)| !(page && k == "lang" && matches!(v.as_ref(), "ja" | "en")))
    {
        return error(400, "invalid_request");
    }
    match crate::auth_resources::admit_work(&request, &env).await {
        Ok(true) => {}
        Ok(false) => return crate::auth_resources::limited(),
        Err(_) => return unavailable(),
    }
    let db = match env.d1("DB") {
        Ok(db) => db,
        Err(_) => return unavailable(),
    };
    // Authenticate before independent I/O, then again before delivering any bytes.
    match crate::vault_http::owner(&request, &db).await {
        Ok(Some(_)) => {}
        Ok(None) => return error(401, "authentication_required"),
        Err(_) => return unavailable(),
    }
    let store = match WorkStore::from_env(&env) {
        Ok(s) => s,
        Err(_) => return unavailable(),
    };
    if let Err(e) = store.require_current_authority().await {
        return match e {
            StoreError::Denied(_) => error(409, "stale_authority"),
            StoreError::Storage(_) => unavailable(),
        };
    }
    match crate::vault_http::owner(&request, &db).await {
        Ok(Some(_)) => {}
        Ok(None) => return error(401, "authentication_required"),
        Err(_) => return unavailable(),
    }
    let builder = Response::builder()
        .with_header("Cache-Control", "no-store")?
        .with_header("Vary", "Cookie, Origin")?
        .with_header("Referrer-Policy", "no-referrer")?
        .with_header("X-Content-Type-Options", "nosniff")?;
    if page {
        let strings = crate::i18n::catalog(crate::i18n::select(&request, None)?);
        let html = (if copy_page {
            include_str!("../ui/work-copy.html")
        } else {
            include_str!("../ui/work-preparations.html")
        })
        .replace(
            "{{execution}}",
            if env
                .var("WORK_COPY_EXECUTION_ENABLED")
                .is_ok_and(|v| v.to_string() == "true")
            {
                "true"
            } else {
                "false"
            },
        )
        .replace(
            "{{copy_consent}}",
            if env
                .var("WORK_COPY_CONSENT_ENABLED")
                .is_ok_and(|v| v.to_string() == "true")
            {
                "true"
            } else {
                "false"
            },
        )
        .replace("{{locale}}", strings.locale)
        .replace(
            "{{title}}",
            &crate::i18n::html_escape(strings.message(if copy_page {
                "copy_title"
            } else {
                "preparation_title"
            })),
        );
        return builder.with_header("Content-Security-Policy", "default-src 'none'; img-src 'self'; script-src 'self'; connect-src 'self'; style-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")?.from_html(html);
    }
    let (body, mime) = if copy_page && url.path().ends_with(".js") {
        (
            include_str!(concat!(env!("OUT_DIR"), "/work-copy.js")),
            "text/javascript; charset=utf-8",
        )
    } else if copy_page {
        (
            include_str!(concat!(env!("OUT_DIR"), "/work-copy.css")),
            "text/css; charset=utf-8",
        )
    } else if url.path().ends_with(".js") {
        (
            include_str!(concat!(env!("OUT_DIR"), "/work-preparations.js")),
            "text/javascript; charset=utf-8",
        )
    } else {
        (
            include_str!(concat!(env!("OUT_DIR"), "/work-preparations.css")),
            "text/css; charset=utf-8",
        )
    };
    Ok(builder
        .with_header("Content-Type", mime)?
        .fixed(body.as_bytes().to_vec()))
}
