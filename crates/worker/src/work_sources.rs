//! Owner source inspection. Private Artifacts RPC supplies data; primary D1
//! authorizes before and after reading. No grant, token, launch or Git write.
use crate::vault_http::{owner, same_origin};
use crate::work_owner::{error, reply, unavailable};
use crate::work_store::{StoreError, WorkStore, owner_id_shape};
use futures_util::future::{Either, select};
use mikaki_auth::work::{Denied, SourceReadInput};
use serde_json::json;
use std::time::Duration;
use wasm_bindgen::{JsValue, prelude::wasm_bindgen};
use wasm_bindgen_futures::JsFuture;
use worker::{Delay, Env, Method, Request, Response};

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(extends=js_sys::Object)]
    type SourceReader;
    #[wasm_bindgen(method, catch, js_name=readRegisteredSource)]
    fn read_registered_source(
        this: &SourceReader,
        input: &str,
    ) -> std::result::Result<js_sys::Promise, JsValue>;
}

pub(crate) async fn read_registered(
    store: &WorkStore,
    env: &Env,
    session: &str,
    i: &SourceReadInput,
) -> Result<(crate::work_store::OwnerSource, String), StoreError> {
    let source = store.owner_source(session, &i.source_id).await?;
    store.require_current_authority().await?;
    let input = source.service_request(i)?;
    let binding: SourceReader = env.service("WORK_SOURCE_READER")?.into_rpc();
    // One named RPC takes/returns bounded closed JSON. Never forward arbitrary
    // method names, SQL, owner/session facts or caller-supplied repository names.
    let promise = binding
        .read_registered_source(&input)
        .map_err(worker::Error::from)?;
    // Bound the owner's wait; timing out does not claim cancellation of the
    // remote read. This capability has no external mutation to retry.
    let value = match select(
        Box::pin(JsFuture::from(promise)),
        Box::pin(Delay::from(Duration::from_secs(10))),
    )
    .await
    {
        Either::Left((value, _)) => value.map_err(worker::Error::from)?,
        Either::Right(_) => {
            return Err(worker::Error::RustError("source_unavailable".into()).into());
        }
    };
    let body = value.as_string().ok_or(Denied::InvalidInput)?;
    source.verify_reply(i, &body)?;
    store
        .confirm_source_read(session, &i.source_id, &source)
        .await?;
    store.require_current_authority().await?;
    Ok((source, body))
}

async fn read(
    store: &WorkStore,
    env: &Env,
    session: &str,
    i: SourceReadInput,
) -> Result<serde_json::Value, StoreError> {
    let (source, body) = read_registered(store, env, session, &i).await?;
    source.verify_reply(&i, &body)
}

pub async fn handle(mut request: Request, env: Env) -> worker::Result<Response> {
    if !env
        .var("WORK_SOURCE_API_ENABLED")
        .is_ok_and(|v| v.to_string() == "true")
    {
        return error(404, "not_found");
    }
    let url = request.url()?;
    let listing = request.method() == Method::Get && url.path() == "/work/sources";
    let reading = request.method() == Method::Post && url.path() == "/work/sources/read";
    let page = request.method() == Method::Get && url.path() == "/work/source-review";
    let static_asset = request.method() == Method::Get
        && matches!(
            url.path(),
            "/work/source-review.js"
                | "/work/source-review.css"
                | "/work/browser-assistant.js"
                | "/work/task-demo.js"
                | "/work/task-demo.css"
        );
    if !listing && !reading && !page && !static_asset {
        return error(404, "not_found");
    }
    if request.headers().get("Sec-Fetch-Site")?.as_deref() == Some("cross-site")
        || (request.headers().get("Origin")?.is_some() && !same_origin(&request)?)
        || (reading && !same_origin(&request)?)
    {
        return error(403, "invalid_origin");
    }
    let pairs: Vec<_> = url.query_pairs().collect();
    if pairs.len() > 1
        || pairs.first().is_some_and(|(k, v)| {
            !((listing && k == "after" && owner_id_shape(v))
                || (page && k == "lang" && matches!(v.as_ref(), "ja" | "en")))
        })
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
    let owner = match owner(&request, &db).await {
        Ok(Some(o)) => o,
        Ok(None) => return error(401, "authentication_required"),
        Err(_) => return unavailable(),
    };
    if page || static_asset {
        let store = WorkStore::from_env(&env)
            .map_err(|_| worker::Error::RustError("work_storage_unavailable".into()))?;
        if let Err(error) = store.require_current_authority().await {
            return match error {
                StoreError::Denied(_) => crate::work_owner::error(409, "stale_authority"),
                StoreError::Storage(_) => unavailable(),
            };
        }
        if page {
            let strings = crate::i18n::catalog(crate::i18n::select(&request, None)?);
            let html = include_str!("../ui/work-sources.html")
                .replace("{{locale}}", strings.locale)
                .replace(
                    "{{compose}}",
                    if env
                        .var("WORK_PREPARATION_COMPOSE_ENABLED")
                        .is_ok_and(|v| v.to_string() == "true")
                    {
                        "true"
                    } else {
                        "false"
                    },
                )
                .replace(
                    "{{title}}",
                    &crate::i18n::html_escape(strings.message("source_title")),
                );
            return Response::builder()
                .with_header("Cache-Control", "no-store")?
                .with_header("Vary", "Cookie, Origin")?
                .with_header("Referrer-Policy", "no-referrer")?
                .with_header("X-Content-Type-Options", "nosniff")?
                .with_header("Content-Security-Policy", "default-src 'none'; img-src 'self'; script-src 'self'; connect-src 'self'; style-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")?
                .from_html(html);
        }
        let (body, mime) = if url.path() == "/work/browser-assistant.js" {
            (
                include_str!(concat!(env!("OUT_DIR"), "/work-assistant.js")),
                "text/javascript; charset=utf-8",
            )
        } else if url.path() == "/work/task-demo.js" {
            (
                include_str!(concat!(env!("OUT_DIR"), "/work-task-demo.js")),
                "text/javascript; charset=utf-8",
            )
        } else if url.path() == "/work/task-demo.css" {
            (
                include_str!(concat!(env!("OUT_DIR"), "/work-task-demo.css")),
                "text/css; charset=utf-8",
            )
        } else if url.path().ends_with(".js") {
            (
                include_str!(concat!(env!("OUT_DIR"), "/work-sources.js")),
                "text/javascript; charset=utf-8",
            )
        } else {
            (
                include_str!(concat!(env!("OUT_DIR"), "/work-sources.css")),
                "text/css; charset=utf-8",
            )
        };
        return Ok(Response::builder()
            .with_header("Cache-Control", "no-store")?
            .with_header("Vary", "Cookie, Origin")?
            .with_header("X-Content-Type-Options", "nosniff")?
            .with_header("Content-Type", mime)?
            .fixed(body.as_bytes().to_vec()));
    }
    let store = WorkStore::from_env(&env)
        .map_err(|_| worker::Error::RustError("work_storage_unavailable".into()))?;
    let result = if listing {
        store
            .owner_sources(&owner.secret_hash, pairs.first().map(|(_, v)| v.as_ref()))
            .await
    } else {
        if request.headers().get("Content-Type")?.as_deref() != Some("application/json") {
            return error(415, "invalid_content_type");
        }
        let body = match crate::read_bounded_body(&mut request, 16384).await {
            Ok(b) => b,
            Err(_) => return error(413, "invalid_request"),
        };
        let i: SourceReadInput = match serde_json::from_str(&body) {
            Ok(i) => i,
            Err(_) => return error(400, "invalid_request"),
        };
        read(&store, &env, &owner.secret_hash, i).await
    };
    match result {
        Ok(record) => reply(
            200,
            &json!({"format_version":1,"checked_at":crate::now_seconds(),"record":record}),
        ),
        Err(StoreError::Denied(Denied::InvalidInput)) => error(400, "invalid_request"),
        Err(StoreError::Denied(Denied::StaleAuthority)) => error(409, "stale_authority"),
        Err(StoreError::Denied(_)) => error(404, "not_found"),
        Err(StoreError::Storage(_)) => unavailable(),
    }
}
