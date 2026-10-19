//! Opt-in OP owner transport for managed-work metadata. No issuer,
//! requester/actor input, new grant or external effect. Separately gated selection
//! composition reserves metadata only. Separately gated source
//! inspection delegates to work_sources with its live source-access checks.
use serde::Deserialize;
use serde_json::{Value, json};
use worker::{D1Database, Env, Method, Request, Response, RouteContext, Router, Url};

use crate::vault_http::{owner, same_origin};
use crate::work_store::{OwnerRecordKind, StoreError, WorkStore, owner_id_shape};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RevokeBody {
    format_version: u8,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CopyBody {
    format_version: u8,
    review_digest: String,
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

enum OwnerRoute {
    Requests,
    Preparations,
    Compose,
    Session,
    Read(OwnerRecordKind),
    Revoke,
    CopyConsent,
    CopyExecution,
}
impl OwnerRoute {
    fn is_listing(&self) -> bool {
        matches!(self, Self::Requests | Self::Preparations)
    }

    fn has_resource_id(&self) -> bool {
        !matches!(
            self,
            Self::Requests | Self::Preparations | Self::Compose | Self::Session
        )
    }

    fn is_mutation(&self, method: Method) -> bool {
        matches!(self, Self::Compose | Self::Revoke)
            || (matches!(self, Self::CopyConsent | Self::CopyExecution) && method != Method::Get)
    }

    fn enabled(&self, env: &Env) -> bool {
        let flag = match self {
            Self::Compose => "WORK_PREPARATION_COMPOSE_ENABLED",
            Self::CopyExecution => "WORK_COPY_EXECUTION_ENABLED",
            Self::CopyConsent => "WORK_COPY_CONSENT_ENABLED",
            _ => return true,
        };
        env.var(flag).is_ok_and(|v| v.to_string() == "true")
    }
}

fn owner_route(method: Method, segments: &[&str]) -> Option<OwnerRoute> {
    match (method, segments) {
        (Method::Get, ["", "work", "requests"]) => Some(OwnerRoute::Requests),
        (Method::Get, ["", "work", "preparations"]) => Some(OwnerRoute::Preparations),
        (Method::Post, ["", "work", "preparations"]) => Some(OwnerRoute::Compose),
        (Method::Get, ["", "work", "session"]) => Some(OwnerRoute::Session),
        (Method::Get, ["", "work", kind, _]) => {
            let kind = match *kind {
                "disclosures" => OwnerRecordKind::Disclosure,
                "preparations" => OwnerRecordKind::Preparation,
                "requests" => OwnerRecordKind::Request,
                "grants" => OwnerRecordKind::Grant,
                "runs" => OwnerRecordKind::Run,
                "operations" => OwnerRecordKind::Operation,
                _ => return None,
            };
            Some(OwnerRoute::Read(kind))
        }
        (Method::Post, ["", "work", "grants", _, "revoke"]) => Some(OwnerRoute::Revoke),
        (
            Method::Get | Method::Post | Method::Delete,
            ["", "work", "preparations", _, "copy-consent"],
        ) => Some(OwnerRoute::CopyConsent),
        (Method::Get | Method::Post | Method::Delete, ["", "work", "preparations", _, "copy"]) => {
            Some(OwnerRoute::CopyExecution)
        }
        _ => None,
    }
}

fn invalid_origin(request: &Request, route: &OwnerRoute) -> worker::Result<bool> {
    // Reject browser cross-site reads as well as all non-same-origin mutations.
    Ok(
        request.headers().get("Sec-Fetch-Site")?.as_deref() == Some("cross-site")
            || (request.headers().get("Origin")?.is_some() && !same_origin(request)?)
            || (route.is_mutation(request.method()) && !same_origin(request)?),
    )
}

fn query_after(url: &Url, listing: bool) -> Result<Option<String>, ()> {
    if !listing {
        return if url.query().is_some() {
            Err(())
        } else {
            Ok(None)
        };
    }
    let pairs: Vec<_> = url.query_pairs().collect();
    if pairs.len() > 1
        || pairs
            .first()
            .is_some_and(|(key, value)| key != "after" || !owner_id_shape(value))
    {
        return Err(());
    }
    Ok(pairs.first().map(|(_, value)| value.to_string()))
}

/// Shared with the Wasm qualification entry; that entry's synthetic fixture API
/// is not compiled into the product Router.
pub async fn handle(request: Request, env: Env) -> worker::Result<Response> {
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
            | "/work/task-demo.js"
            | "/work/task-demo.css"
            | "/work/browser-assistant.js"
    ) {
        return crate::work_sources::handle(request, env).await;
    }
    if matches!(
        url.path(),
        "/work/preparation-review"
            | "/work/preparation-review.js"
            | "/work/preparation-review.css"
            | "/work/copy-review"
            | "/work/copy-review.js"
            | "/work/copy-review.css"
    ) {
        return crate::work_preparations::handle(request, env).await;
    }
    let segments: Vec<_> = url.path().split('/').collect();
    let route = match owner_route(request.method(), &segments) {
        Some(route) if route.enabled(&env) => route,
        _ => return error(404, "not_found"),
    };
    if invalid_origin(&request, &route)? {
        return error(403, "invalid_origin");
    }
    let id = if route.has_resource_id() {
        match resource_id(segments[3]) {
            Some(id) => id,
            None => return error(400, "invalid_request"),
        }
    } else {
        String::new()
    };
    let after = match query_after(&url, route.is_listing()) {
        Ok(after) => after,
        Err(()) => return error(400, "invalid_request"),
    };
    authenticated_route(request, &env, route, &id, after.as_deref()).await
}

async fn authenticated_route(
    mut request: Request,
    env: &Env,
    route: OwnerRoute,
    id: &str,
    after: Option<&str>,
) -> worker::Result<Response> {
    match crate::auth_resources::admit_work(&request, env).await {
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
    let store = WorkStore::from_env(env)
        .map_err(|_| worker::Error::RustError("work_storage_unavailable".into()))?;
    match route {
        OwnerRoute::Session => session_response(&request, &db, &store).await,
        OwnerRoute::CopyExecution => {
            copy_execution(&mut request, env, &store, &owner.secret_hash, id).await
        }
        OwnerRoute::Compose => compose(&mut request, env, &store, &owner.secret_hash).await,
        OwnerRoute::CopyConsent => {
            copy_consent(&mut request, env, &store, &owner.secret_hash, id).await
        }
        OwnerRoute::Requests => list_records(&store, &owner.secret_hash, after, false).await,
        OwnerRoute::Preparations => list_records(&store, &owner.secret_hash, after, true).await,
        OwnerRoute::Revoke => revoke(&mut request, &store, &owner.secret_hash, id).await,
        OwnerRoute::Read(kind) => store_response(
            store.owner_record(&owner.secret_hash, kind, id).await,
            false,
        ),
    }
}

async fn session_response(
    request: &Request,
    db: &D1Database,
    store: &WorkStore,
) -> worker::Result<Response> {
    if let Err(error) = store.require_current_authority().await {
        return match error {
            StoreError::Denied(_) => crate::work_owner::error(409, "stale_authority"),
            StoreError::Storage(_) => unavailable(),
        };
    }
    // Recheck the live SSO after independent service I/O, before publishing
    // the local display lease. It grants no source/disclosure permission.
    let owner = match owner(request, db).await {
        Ok(Some(owner)) => owner,
        Ok(None) => return error(401, "authentication_required"),
        Err(_) => return unavailable(),
    };
    reply(
        200,
        &json!({
            "session_tag": crate::passkey_login::hash(&format!("work-session-v1:{}", owner.secret_hash)),
            "account_id": owner.account_id,
            "credential_id": owner.credential_id,
        }),
    )
}

/// Expected input refusals remain HTTP responses; transport errors still use
/// the outer Worker result. Revocation deliberately retains its Serde-only
/// validation, while compose/copy also use the existing strict-JSON limits.
async fn json_input<T: serde::de::DeserializeOwned>(
    request: &mut Request,
    limit: usize,
    strict_depth: Option<usize>,
) -> worker::Result<Result<T, Response>> {
    if request.headers().get("Content-Type")?.as_deref() != Some("application/json") {
        return Ok(Err(error(415, "invalid_content_type")?));
    }
    let body = match crate::read_bounded_body(request, limit).await {
        Ok(body) => body,
        Err(_) => return Ok(Err(error(413, "invalid_request")?)),
    };
    if let Some(depth) = strict_depth
        && mikaki_webauthn::strict_json(&body, limit, depth).is_err()
    {
        return Ok(Err(error(400, "invalid_request")?));
    }
    match serde_json::from_str(&body) {
        Ok(input) => Ok(Ok(input)),
        Err(_) => Ok(Err(error(400, "invalid_request")?)),
    }
}

async fn copy_digest(
    request: &mut Request,
    limit: usize,
) -> worker::Result<Result<mikaki_auth::work::Digest, Response>> {
    let input = match json_input::<CopyBody>(request, limit, Some(4)).await? {
        Ok(input) if input.format_version == 1 => input,
        Ok(_) => return Ok(Err(error(400, "invalid_request")?)),
        Err(response) => return Ok(Err(response)),
    };
    match mikaki_auth::work::Digest::parse_hex(&input.review_digest) {
        Ok(digest) => Ok(Ok(digest)),
        Err(_) => Ok(Err(error(400, "invalid_request")?)),
    }
}

async fn copy_execution(
    request: &mut Request,
    env: &Env,
    store: &WorkStore,
    session: &str,
    id: &str,
) -> worker::Result<Response> {
    let account = match crate::work_store::copy_account(env) {
        Ok(account) => account,
        Err(_) => return unavailable(),
    };
    let result = if request.method() == Method::Get {
        store.owner_copy_job(env, session, id, &account).await
    } else {
        let digest = match copy_digest(request, 4096).await? {
            Ok(digest) => digest,
            Err(response) => return Ok(response),
        };
        if request.method() == Method::Post {
            store.start_copy_job(env, session, id, digest).await
        } else {
            cleanup_copy(env, store, session, id, &account, digest).await
        }
    };
    store_response(result, false)
}

async fn cleanup_copy(
    env: &Env,
    store: &WorkStore,
    session: &str,
    id: &str,
    account: &str,
    digest: mikaki_auth::work::Digest,
) -> crate::work_store::Result<Value> {
    let review = store.owner_copy_review(session, id, account).await?;
    if review["review_digest"] != digest.to_hex() {
        return Err(mikaki_auth::work::Denied::ReviewMismatch.into());
    }
    store.cleanup_copy_job(env, id).await?;
    store.owner_copy_job(env, session, id, account).await
}

async fn compose(
    request: &mut Request,
    env: &Env,
    store: &WorkStore,
    session: &str,
) -> worker::Result<Response> {
    let input =
        match json_input::<crate::work_store::PreparationComposeInput>(request, 16384, Some(8))
            .await?
        {
            Ok(input) => input,
            Err(response) => return Ok(response),
        };
    store_response(store.compose_preparation(env, session, input).await, false)
}

async fn copy_consent(
    request: &mut Request,
    env: &Env,
    store: &WorkStore,
    session: &str,
    id: &str,
) -> worker::Result<Response> {
    let account = match crate::work_store::copy_account(env) {
        Ok(account) => account,
        Err(_) => return unavailable(),
    };
    let result = if request.method() == Method::Get {
        store.owner_copy_review(session, id, &account).await
    } else {
        let digest = match copy_digest(request, 256).await? {
            Ok(digest) => digest,
            Err(response) => return Ok(response),
        };
        if request.method() == Method::Post {
            store.confirm_copy(session, id, &account, digest).await
        } else {
            store.withdraw_copy(session, id, &account, digest).await
        }
    };
    store_response(result, false)
}

async fn list_records(
    store: &WorkStore,
    session: &str,
    after: Option<&str>,
    preparations: bool,
) -> worker::Result<Response> {
    let result = if preparations {
        store.owner_preparations(session, after).await
            .map(|page| json!({"format_version":1,"checked_at":crate::now_seconds(),"preparations":page["preparations"],"next_after":page["next_after"]}))
    } else {
        store.owner_requests(session, after).await
            .map(|page| json!({"format_version":1,"checked_at":crate::now_seconds(),"requests":page.requests,"next_after":page.next_after}))
    };
    store_response(result, true)
}

async fn revoke(
    request: &mut Request,
    store: &WorkStore,
    session: &str,
    id: &str,
) -> worker::Result<Response> {
    match json_input::<RevokeBody>(request, 256, None).await? {
        Ok(input) if input.format_version == 1 => {}
        Ok(_) => return error(400, "invalid_request"),
        Err(response) => return Ok(response),
    }
    let result = match store.revoke_grant(session, id).await {
        Ok(()) => {
            store
                .owner_record(session, OwnerRecordKind::Grant, id)
                .await
        }
        Err(error) => Err(error),
    };
    store_response(result, false)
}

fn store_response(
    result: crate::work_store::Result<Value>,
    listing: bool,
) -> worker::Result<Response> {
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
