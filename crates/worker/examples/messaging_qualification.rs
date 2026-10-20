//! Local runtime entrypoint only. No synthetic authentication bypass.
#![cfg(target_arch = "wasm32")]
use worker::*;
#[event(fetch)]
pub async fn main(request: Request, env: Env, _context: Context) -> Result<Response> {
    if request.url()?.path().starts_with("/vault/") {
        return mikaki_worker::messaging::vault_qualification_routes(Router::new())
            .run(request, env)
            .await;
    }
    mikaki_worker::messaging::fetch(request, &env).await
}
