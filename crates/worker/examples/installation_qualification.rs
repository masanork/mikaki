//! Local qualification entrypoint only. Never deploy this example.
#![cfg(target_arch = "wasm32")]
use worker::*;

#[event(fetch)]
pub async fn main(request: Request, env: Env, _context: Context) -> Result<Response> {
    mikaki_worker::installation_qualification::fetch(request, &env).await
}
