//! Owner-authorized forwarding to the separate agent recipient service.
use worker::{Headers, Method, Request, RequestInit, Response, RouteContext};

use crate::vault_attributes::{error, owner, same_origin};

pub async fn route(mut request: Request, context: RouteContext<()>) -> worker::Result<Response> {
    let Some(path) = context.param("operation") else {
        return error(404, "not_found");
    };
    let read =
        request.method() == Method::Get && matches!(path.as_str(), "status" | "record-status");
    let write = request.method() == Method::Post
        && [
            "grants",
            "revoke",
            "decide",
            "attribute-capability",
            "attribute-decide",
            "attribute-prepare",
            "record-capability",
            "record-decide",
            "record-prepare",
            "oauth-request",
            "oauth-decide",
        ]
        .contains(&path.as_str());
    if !read && !write {
        return error(404, "not_found");
    }
    if write && !same_origin(&request)? {
        return error(403, "invalid_origin");
    }
    let db = context.env.d1("DB")?;
    let Some(owner) = owner(&request, &db).await? else {
        return error(401, "authentication_required");
    };
    let Ok(service) = context.env.service("AGENT_ACCESS") else {
        return error(503, "agent_service_unavailable");
    };
    let headers = Headers::new();
    headers.set("X-Mikaki-Account", &owner.account_id)?;
    headers.set("X-Mikaki-Session-Hash", &owner.secret_hash)?;
    headers.set(
        "X-Mikaki-Origin",
        &request.url()?.origin().ascii_serialization(),
    )?;
    headers.set("Content-Type", "application/json")?;
    let body = if write {
        if request.headers().get("Content-Type")?.as_deref() != Some("application/json") {
            return error(415, "invalid_content_type");
        }
        let bytes = match crate::read_bounded_body(&mut request, 48 * 1024).await {
            Ok(bytes) => bytes,
            Err(_) => return error(413, "invalid_request"),
        };
        Some(wasm_bindgen::JsValue::from_str(&bytes))
    } else {
        None
    };
    let mut init = RequestInit::new();
    init.with_method(request.method()).with_headers(headers);
    init.body = body;
    let forwarded = Request::new_with_init(&format!("https://agent.internal/{path}"), &init)?;
    service.fetch_request(forwarded).await
}
