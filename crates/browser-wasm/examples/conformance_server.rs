//! Isolated loopback FIDO test server. No Wasm or child-process verification.
#[cfg(not(target_arch = "wasm32"))]
#[path = "support/conformance_http.rs"]
mod server;

#[cfg(not(target_arch = "wasm32"))]
fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    server::run()
}

#[cfg(target_arch = "wasm32")]
fn main() {}
