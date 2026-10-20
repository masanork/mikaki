//! Explicitly enabled product host for the limited same-instance chat beta.
use crate::vault_http::{error, owner, same_origin};
use worker::{Env, Method, Request, Response, RouteContext};

pub fn enabled(env: &Env) -> bool {
    cfg!(feature = "messaging-beta")
        && env
            .var("MESSAGING_BETA_ENABLED")
            .is_ok_and(|v| v.to_string() == "true")
}

pub fn page_policy(env: &Env, policy: &str) -> String {
    if enabled(env) {
        policy.replace("script-src 'self'", "script-src 'self' 'wasm-unsafe-eval'")
    } else {
        policy.to_owned()
    }
}

pub async fn config(request: Request, context: RouteContext<()>) -> worker::Result<Response> {
    match configuration(&request, &context.env).await {
        Ok(response) => Ok(response),
        Err(_) => error(503, "messaging_unavailable"),
    }
}

async fn configuration(request: &Request, env: &Env) -> worker::Result<Response> {
    if env.bucket("VAULT_BLOBS").is_err() {
        return error(404, "not_found");
    }
    if request.url()?.query().is_some()
        || (request.headers().get("Origin")?.is_some() && !same_origin(request)?)
        || request.headers().get("Sec-Fetch-Site")?.as_deref() == Some("cross-site")
    {
        return error(403, "origin_required");
    }
    let db = env.d1("DB")?;
    let Some(current) = owner(request, &db).await? else {
        return error(401, "authentication_required");
    };
    if !enabled(env) {
        return Response::builder()
            .with_header("Cache-Control", "no-store")?
            .from_json(&serde_json::json!({"enabled":false}));
    }
    #[cfg(feature = "messaging-beta")]
    {
        use serde::Deserialize;
        use wasm_bindgen::JsValue;
        use worker::D1SessionConstraint;
        #[derive(Deserialize)]
        struct Version {
            version: u8,
        }
        #[derive(Deserialize)]
        struct Device {
            device_id: String,
        }
        let issuer = env.var("MIKAKI_ISSUER")?.to_string();
        if !crate::messaging_crypto::origin(&issuer)
            || request.url()?.origin().ascii_serialization() != issuer
        {
            return error(400, "invalid_origin");
        }
        let primary = db.with_session_constraint(D1SessionConstraint::FirstPrimary)?;
        if primary
            .prepare("SELECT version FROM messaging_beta_schema WHERE id=1")
            .first::<Version>(None)
            .await?
            .is_none_or(|v| v.version != 1)
        {
            return error(503, "messaging_unavailable");
        }
        let profile = primary.prepare("SELECT h.device_id FROM messaging_device_head h JOIN messaging_account a ON a.account_id=h.account_id WHERE a.owner_id=?1")
            .bind(&[JsValue::from_str(&current.account_id)])?.first::<Device>(None).await?;
        let signer = crate::messaging_crypto::Signer::load(env).await?;
        if owner(request, &db).await?.is_none() {
            return error(401, "authentication_required");
        }
        Response::builder()
            .with_header("Cache-Control", "no-store")?
            .with_header("Vary", "Cookie, Origin")?
            .from_json(&serde_json::json!({
                "enabled":true,"issuer":issuer,"public_key":signer.public_key,
                "registered_device_id":profile.map(|p|p.device_id)
            }))
    }
    #[cfg(not(feature = "messaging-beta"))]
    {
        let _ = current;
        error(404, "not_found")
    }
}

pub async fn fetch(request: Request, env: &Env) -> worker::Result<Response> {
    if !enabled(env) {
        return error(404, "not_found");
    }
    #[cfg(feature = "messaging-beta")]
    {
        if request.method() == Method::Get {
            let (body, content_type): (&[u8], &str) = match request.url()?.path() {
                "/messaging/client.js" | "/messaging/crypto.wasm" => {
                    let path = if request.url()?.path() == "/messaging/client.js" {
                        "/chat/client.js"
                    } else {
                        "/chat/crypto.wasm"
                    };
                    let target = request.url()?.join(path)?.to_string();
                    let asset = Request::new(&target, Method::Get)?;
                    let mut response = env.service("FONT_ASSETS")?.fetch_request(asset).await?;
                    let mime = if path.ends_with(".js") {
                        "text/javascript; charset=utf-8"
                    } else {
                        "application/wasm"
                    };
                    if response.status_code() != 200 {
                        return error(503, "messaging_unavailable");
                    }
                    let body = response.bytes().await?;
                    return Ok(Response::builder()
                        .with_header("Content-Type", mime)?
                        .with_header("Cache-Control", "no-store")?
                        .with_header("X-Content-Type-Options", "nosniff")?
                        .with_header("Cross-Origin-Resource-Policy", "same-origin")?
                        .fixed(body));
                }
                "/messaging/chat.css" => (
                    include_bytes!("../ui/messaging/chat.css"),
                    "text/css; charset=utf-8",
                ),
                _ => return api(request, env).await,
            };
            return Ok(Response::builder()
                .with_header("Content-Type", content_type)?
                .with_header("Cache-Control", "no-store")?
                .with_header("X-Content-Type-Options", "nosniff")?
                .with_header("Cross-Origin-Resource-Policy", "same-origin")?
                .fixed(body.to_vec()));
        }
        api(request, env).await
    }
    #[cfg(not(feature = "messaging-beta"))]
    {
        let _ = (request, Method::Get);
        error(404, "not_found")
    }
}

#[cfg(feature = "messaging-beta")]
async fn api(request: Request, env: &Env) -> worker::Result<Response> {
    if !crate::auth_resources::admit_work(&request, env).await? {
        return crate::auth_resources::limited();
    }
    crate::messaging::fetch(request, env).await
}
