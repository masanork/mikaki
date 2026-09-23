//! Cloudflare Workers platform adapter. Protocol decisions remain in `sakimori-oidc`.

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::JsCast;

#[cfg(target_arch = "wasm32")]
pub struct WorkersCryptoRandom;

#[cfg(target_arch = "wasm32")]
impl sakimori_oidc::CryptographicRandom for WorkersCryptoRandom {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), sakimori_oidc::CodeEntropyError> {
        let global = js_sys::global();
        let crypto = js_sys::Reflect::get(&global, &"crypto".into())
            .map_err(|_| sakimori_oidc::CodeEntropyError)?
            .dyn_into::<web_sys::Crypto>()
            .map_err(|_| sakimori_oidc::CodeEntropyError)?;
        crypto
            .get_random_values_with_u8_array(output)
            .map(|_| ())
            .map_err(|_| sakimori_oidc::CodeEntropyError)
    }
}

#[cfg(all(target_arch = "wasm32", feature = "worker-entry"))]
#[worker::event(fetch)]
pub async fn main(
    req: worker::Request,
    env: worker::Env,
    _ctx: worker::Context,
) -> worker::Result<worker::Response> {
    worker::Router::with_data(())
        .get_async("/health", |_req, _ctx| async { worker::Response::ok("ok") })
        .run(req, env)
        .await
}
