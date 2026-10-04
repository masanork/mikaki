//! Owner Vault page, live-session projection and immutable UI assets.
use serde::Serialize;
use worker::{Request, Response, RouteContext};

use crate::vault_http::{error, owner};

#[derive(Serialize)]
struct SessionResponse<'a> {
    session_tag: String,
    credential_id: &'a str,
    account_id: &'a str,
}

pub async fn session(request: Request, context: RouteContext<()>) -> worker::Result<Response> {
    if context.env.bucket("VAULT_BLOBS").is_err() {
        return error(404, "not_found");
    }
    let db = context.env.d1("DB")?;
    let Some(owner) = owner(&request, &db).await? else {
        return error(401, "authentication_required");
    };
    Response::builder()
        .with_header("Cache-Control", "no-store")?
        .from_json(&SessionResponse {
            session_tag: crate::passkey_login::hash(&format!(
                "vault-session-v1:{}",
                owner.secret_hash
            )),
            credential_id: &owner.credential_id,
            account_id: &owner.account_id,
        })
}

pub async fn page(request: Request, context: RouteContext<()>) -> worker::Result<Response> {
    if context.env.bucket("VAULT_BLOBS").is_err() {
        return error(404, "not_found");
    }
    let db = context.env.d1("DB")?;
    let Some(_page_owner) = owner(&request, &db).await? else {
        if request
            .url()?
            .query_pairs()
            .any(|(key, _)| key == "agent_oauth_request")
        {
            return crate::passkey_login::start_owner(&request, &context, &db).await;
        }
        return crate::passkey_login::web_signin(request, context).await;
    };
    // Presentation only; every data operation still verifies live owner authority.
    let strings = crate::i18n::catalog(crate::i18n::select(&request, None)?);
    let mut html = include_str!("../ui/vault.html").to_owned();
    let replacements = [
        ("{{locale}}", strings.locale),
        ("{{title}}", strings.message("vaultTitle")),
        ("{{vault_format}}", "owner-v2"),
    ];
    for (key, value) in replacements {
        html = html.replace(key, &crate::i18n::html_escape(value));
    }
    Response::builder()
        .with_header("Cache-Control", "no-store")?
        .with_header("Referrer-Policy", "no-referrer")?
        .with_header("Content-Security-Policy", "default-src 'none'; img-src 'self'; script-src 'self'; worker-src 'self'; connect-src 'self'; style-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")?
        .from_html(html)
}

pub async fn script(_request: Request, context: RouteContext<()>) -> worker::Result<Response> {
    if context.env.bucket("VAULT_BLOBS").is_err() {
        return error(404, "not_found");
    }
    let script = include_str!(concat!(env!("OUT_DIR"), "/vault.js"));
    Ok(Response::builder()
        .with_header("Content-Type", "text/javascript; charset=utf-8")?
        .with_header("Cache-Control", "no-store")?
        .with_header("X-Content-Type-Options", "nosniff")?
        .fixed(script.as_bytes().to_vec()))
}

// Public, immutable build inputs only. No owner data or authentication material.
pub async fn search_script(
    _request: Request,
    context: RouteContext<()>,
) -> worker::Result<Response> {
    if context.env.bucket("VAULT_BLOBS").is_err() {
        return error(404, "not_found");
    }
    Ok(Response::builder()
        .with_header("Content-Type", "text/javascript; charset=utf-8")?
        .with_header("Cache-Control", "no-store")?
        .with_header("X-Content-Type-Options", "nosniff")?
        .with_header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; connect-src 'self'",
        )?
        .fixed(include_bytes!(concat!(env!("OUT_DIR"), "/search.js")).to_vec()))
}

pub async fn search_wasm(_request: Request, context: RouteContext<()>) -> worker::Result<Response> {
    if context.env.bucket("VAULT_BLOBS").is_err() {
        return error(404, "not_found");
    }
    Ok(Response::builder()
        .with_header("Content-Type", "application/wasm")?
        .with_header("Cache-Control", "no-store")?
        .with_header("X-Content-Type-Options", "nosniff")?
        .fixed(include_bytes!(concat!(env!("OUT_DIR"), "/sqlite3.wasm")).to_vec()))
}
