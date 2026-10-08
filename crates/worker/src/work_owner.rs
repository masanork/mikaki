//! Opt-in OP owner transport for existing managed-work records. No issuer,
//! requester/actor input, new grant or external effect. Separately gated source
//! inspection delegates to work_sources with its live source-access checks.
use serde::Deserialize;
use serde_json::{Value, json};
use worker::{Env, Method, Request, Response, RouteContext, Router};

use crate::vault_http::{owner, same_origin};
use crate::work_store::{OwnerRecordKind, StoreError, WorkStore, owner_id_shape};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RevokeBody {
    format_version: u8,
}

pub(super) fn reply(status: u16, body: &Value) -> worker::Result<Response> {
    Response::builder()
        .with_status(status)
        .with_header("Cache-Control", "no-store")?
        .with_header("Vary", "Cookie, Origin")?
        .with_header("X-Content-Type-Options", "nosniff")?
        .with_header("Referrer-Policy", "no-referrer")?
        .with_header(
            "Content-Security-Policy",
            "default-src 'none'; frame-ancestors 'none'",
        )?
        .from_json(body)
}
pub(super) fn error(status: u16, code: &str) -> worker::Result<Response> {
    reply(status, &json!({"error":code}))
}
pub(super) fn unavailable() -> worker::Result<Response> {
    // Never log owner text, identifiers, SQL errors or credential material.
    worker::console_log!("{{\"event\":\"work_owner_unavailable\"}}");
    error(503, "work_unavailable")
}

pub async fn route(request: Request, context: RouteContext<()>) -> worker::Result<Response> {
    handle(request, context.env).await
}

pub fn routes(router: Router<'_, ()>) -> Router<'_, ()> {
    // Method/path validation below gives disabled and unsupported routes the
    // same closed JSON response, including methods absent from the interface.
    router.on_async("/work/*path", route)
}

fn resource_id(segment: &str) -> Option<String> {
    // Decode once; encoded separators, non-ASCII and double encoding cannot
    // survive the native ID alphabet. '+' is not a space in a path component.
    let mut bytes = segment.bytes();
    let mut decoded = Vec::with_capacity(segment.len().min(128));
    while let Some(byte) = bytes.next() {
        let byte = if byte == b'%' {
            let digit = |b: u8| match b {
                b'0'..=b'9' => Some(b - b'0'),
                b'a'..=b'f' => Some(b - b'a' + 10),
                b'A'..=b'F' => Some(b - b'A' + 10),
                _ => None,
            };
            digit(bytes.next()?)? * 16 + digit(bytes.next()?)?
        } else {
            byte
        };
        if decoded.len() == 128 || !(byte.is_ascii_alphanumeric() || b"-_.:".contains(&byte)) {
            return None;
        }
        decoded.push(byte);
    }
    let id = String::from_utf8(decoded).ok()?;
    owner_id_shape(&id).then_some(id)
}

/// Shared with the Wasm qualification entry; that entry's synthetic fixture API
/// is not compiled into the product Router.
pub async fn handle(mut request: Request, env: Env) -> worker::Result<Response> {
    if !env
        .var("WORK_OWNER_API_ENABLED")
        .is_ok_and(|v| v.to_string() == "true")
    {
        return error(404, "not_found");
    }
    let url = request.url()?;
    if url.path().len() > 512 || url.query().is_some_and(|q| q.len() > 256) {
        return error(400, "invalid_request");
    }
    if matches!(
        url.path(),
        "/work/sources"
            | "/work/sources/read"
            | "/work/source-review"
            | "/work/source-review.js"
            | "/work/source-review.css"
    ) {
        return crate::work_sources::handle(request, env).await;
    }
    let segments: Vec<_> = url.path().split('/').collect();
    let listing = request.method() == Method::Get && segments == ["", "work", "requests"];
    let session = request.method() == Method::Get && segments == ["", "work", "session"];
    let reading = request.method() == Method::Get
        && segments.len() == 4
        && segments[1] == "work"
        && matches!(
            segments[2],
            "disclosures" | "preparations" | "requests" | "grants" | "runs" | "operations"
        );
    let revoking = request.method() == Method::Post
        && segments.len() == 5
        && segments[1..3] == ["work", "grants"]
        && segments[4] == "revoke";
    if !listing && !reading && !revoking && !session {
        return error(404, "not_found");
    }
    // Reject browser cross-site reads as well as all non-same-origin mutations.
    if request.headers().get("Sec-Fetch-Site")?.as_deref() == Some("cross-site")
        || (request.headers().get("Origin")?.is_some() && !same_origin(&request)?)
        || (revoking && !same_origin(&request)?)
    {
        return error(403, "invalid_origin");
    }
    let id = if listing || session {
        String::new()
    } else {
        match resource_id(segments[3]) {
            Some(id) => id,
            None => return error(400, "invalid_request"),
        }
    };
    let after = if listing {
        let pairs: Vec<_> = url.query_pairs().collect();
        if pairs.len() > 1
            || pairs
                .first()
                .is_some_and(|(key, value)| key != "after" || !owner_id_shape(value))
        {
            return error(400, "invalid_request");
        }
        pairs.first().map(|(_, value)| value.to_string())
    } else {
        if url.query().is_some() {
            return error(400, "invalid_request");
        }
        None
    };
    match crate::auth_resources::admit_work(&request, &env).await {
        Ok(true) => {}
        Ok(false) => return crate::auth_resources::limited(),
        Err(_) => return unavailable(),
    }
    let db = match env.d1("DB") {
        Ok(db) => db,
        Err(_) => return unavailable(),
    };
    let owner = match owner(&request, &db).await {
        Ok(Some(owner)) => owner,
        Ok(None) => return error(401, "authentication_required"),
        Err(_) => return unavailable(),
    };
    let store = WorkStore::from_env(&env)
        .map_err(|_| worker::Error::RustError("work_storage_unavailable".into()))?;
    if session {
        if let Err(error) = store.require_current_authority().await {
            return match error {
                StoreError::Denied(_) => crate::work_owner::error(409, "stale_authority"),
                StoreError::Storage(_) => unavailable(),
            };
        }
        // Recheck the live SSO after independent service I/O, before publishing
        // the local display lease. It grants no source/disclosure permission.
        let owner = match crate::vault_http::owner(&request, &db).await {
            Ok(Some(owner)) => owner,
            Ok(None) => return error(401, "authentication_required"),
            Err(_) => return unavailable(),
        };
        return reply(
            200,
            &json!({
                "session_tag": crate::passkey_login::hash(&format!("work-session-v1:{}", owner.secret_hash)),
                "account_id": owner.account_id,
                "credential_id": owner.credential_id,
            }),
        );
    }
    let result = if listing {
        store.owner_requests(&owner.secret_hash, after.as_deref()).await
            .map(|page| json!({"format_version":1,"checked_at":crate::now_seconds(),"requests":page.requests,"next_after":page.next_after}))
    } else if revoking {
        if request.headers().get("Content-Type")?.as_deref() != Some("application/json") {
            return error(415, "invalid_content_type");
        }
        let body = match crate::read_bounded_body(&mut request, 256).await {
            Ok(body) => body,
            Err(_) => return error(413, "invalid_request"),
        };
        if !serde_json::from_str::<RevokeBody>(&body).is_ok_and(|b| b.format_version == 1) {
            return error(400, "invalid_request");
        }
        match store.revoke_grant(&owner.secret_hash, &id).await {
            Ok(()) => {
                store
                    .owner_record(&owner.secret_hash, OwnerRecordKind::Grant, &id)
                    .await
            }
            Err(error) => Err(error),
        }
    } else {
        let kind = match segments[2] {
            "disclosures" => OwnerRecordKind::Disclosure,
            "preparations" => OwnerRecordKind::Preparation,
            "requests" => OwnerRecordKind::Request,
            "grants" => OwnerRecordKind::Grant,
            "runs" => OwnerRecordKind::Run,
            "operations" => OwnerRecordKind::Operation,
            _ => return error(404, "not_found"),
        };
        store.owner_record(&owner.secret_hash, kind, &id).await
    };
    match result {
        Ok(record) if listing => reply(200, &record),
        Ok(record) => reply(
            200,
            &json!({"format_version":1,"checked_at":crate::now_seconds(),"record":record}),
        ),
        Err(StoreError::Denied(mikaki_auth::work::Denied::InvalidInput)) => {
            error(400, "invalid_request")
        }
        Err(StoreError::Denied(mikaki_auth::work::Denied::StaleAuthority)) => {
            error(409, "stale_authority")
        }
        Err(StoreError::Denied(_)) => error(404, "not_found"),
        Err(StoreError::Storage(_)) => unavailable(),
    }
}
