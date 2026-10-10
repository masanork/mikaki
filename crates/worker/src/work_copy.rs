//! Named private workflow adapter. No public RPC, bearer or caller gate selection.
use crate::work_store::WorkStore;
use serde::Deserialize;
use worker::{Env, Method, Request, Response};
#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "kebab-case", deny_unknown_fields)]
enum Input {
    Pending,
    Advance { preparation_id: String, step: u64 },
    Cancel { preparation_id: String },
}
pub async fn handle(mut request: Request, env: &Env) -> worker::Result<Response> {
    if request.method() != Method::Post
        || request.url()?.path() != "/copy-job"
        || !env
            .var("WORK_COPY_EXECUTION_ENABLED")
            .is_ok_and(|v| v.to_string() == "true")
    {
        return Response::empty().map(|r| r.with_status(404));
    }
    let result = async {
        let body = crate::read_bounded_body(&mut request, 4096).await?;
        mikaki_webauthn::strict_json(&body, 4096, 4)
            .map_err(|_| worker::Error::from("copy_input"))?;
        let input: Input = serde_json::from_str(&body)?;
        let store = WorkStore::from_env(env).map_err(|_| worker::Error::from("copy_store"))?;
        let value = match input {
            Input::Pending => store.pending_copy_jobs().await,
            Input::Advance {
                preparation_id,
                step,
            } => store.advance_copy_job(env, &preparation_id, step).await,
            Input::Cancel { preparation_id } => store.cleanup_copy_job(env, &preparation_id).await,
        }
        .map_err(|_| worker::Error::from("copy_denied"))?;
        Response::builder()
            .with_header("Cache-Control", "no-store")?
            .from_json(&value)
    }
    .await;
    result.or_else(|_: worker::Error| {
        Response::builder()
            .with_status(409)
            .with_header("Cache-Control", "no-store")?
            .from_json(&serde_json::json!({"error":"copy_unavailable_or_denied"}))
    })
}

#[wasm_bindgen::prelude::wasm_bindgen]
pub async fn administer_work_copy(
    request: web_sys::Request,
    env: Env,
) -> std::result::Result<web_sys::Response, wasm_bindgen::JsValue> {
    handle(request.into(), &env)
        .await
        .map(Into::into)
        .map_err(Into::into)
}
