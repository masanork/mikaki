//! JSON boundary for the local Workers adapter. Evidence constructors stay private.
use sakimori_auth::Ceremony;
use serde::Deserialize;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn valid_json(input: &str, bytes: usize, depth: usize) -> bool {
    sakimori_webauthn::strict_json(input, bytes, depth).is_ok()
}

/// Validate internal diagnostics against the same catalog as the Rust verifier.
#[wasm_bindgen]
pub fn diagnostic_stage(code: &str) -> Option<String> {
    sakimori_webauthn::Invalid::from_code(code).map(|e| e.stage().to_owned())
}

#[derive(Deserialize)]
struct Input<T> {
    ceremony: Ceremony,
    browser_hash: String,
    now: u64,
    max_failures: u32,
    response: T,
}
fn diagnostic(error: sakimori_webauthn::Invalid) -> JsValue {
    JsValue::from_str(&format!(
        "{{\"code\":\"{}\",\"stage\":\"{}\"}}",
        error.code(),
        error.stage()
    ))
}
fn parse<T: serde::de::DeserializeOwned>(input: &str) -> Result<T, JsValue> {
    // Outer wrapper has additional trusted levels. WebAuthn payload limits are checked inside core.
    sakimori_webauthn::bounded_json(input, 262144, 16).map_err(diagnostic)?;
    serde_json::from_str(input).map_err(|_| diagnostic(sakimori_webauthn::Invalid::Input))
}
#[wasm_bindgen]
pub fn register(input: &str) -> Result<String, JsValue> {
    let i: Input<sakimori_webauthn::Registration> = parse(input)?;
    let proof = i
        .ceremony
        .register(&i.browser_hash, i.now, i.max_failures, i.response)
        .map_err(diagnostic)?;
    serde_json::to_string(&proof).map_err(|_| JsValue::from_str("invalid_request"))
}
#[wasm_bindgen]
pub fn authenticate(input: &str, credential: &str) -> Result<String, JsValue> {
    let i: Input<sakimori_webauthn::Assertion> = parse(input)?;
    let stored = parse(credential)?;
    let proof = i
        .ceremony
        .authenticate(&i.browser_hash, i.now, i.max_failures, &stored, i.response)
        .map_err(diagnostic)?;
    serde_json::to_string(&proof).map_err(|_| JsValue::from_str("invalid_request"))
}
#[wasm_bindgen]
pub fn authorize(
    input: &str,
    client: &str,
    redirect: &str,
    state_limit: usize,
    nonce_limit: usize,
) -> bool {
    let Ok(request) = serde_json::from_str::<sakimori_oidc::Authorization>(input) else {
        return false;
    };
    request.valid(client, redirect, state_limit, nonce_limit)
}
#[wasm_bindgen]
pub fn pkce(verifier: &str) -> Result<String, JsValue> {
    sakimori_oidc::pkce(verifier).ok_or_else(|| JsValue::from_str("invalid_grant"))
}

#[wasm_bindgen]
pub fn attestation_hint(input: &str) -> Result<String, JsValue> {
    sakimori_webauthn::attestation_hint(input).map_err(diagnostic)
}
#[wasm_bindgen]
pub fn mds_crl_urls(jwt: &str) -> Result<String, JsValue> {
    let urls = sakimori_webauthn::metadata::mds_crl_urls(jwt).map_err(diagnostic)?;
    serde_json::to_string(&urls).map_err(|_| JsValue::from_str("invalid_mds"))
}
#[wasm_bindgen]
pub fn verify_mds(input: &str) -> Result<String, JsValue> {
    sakimori_webauthn::strict_json(input, 8_388_608, 8).map_err(diagnostic)?;
    let i =
        serde_json::from_str(input).map_err(|_| diagnostic(sakimori_webauthn::Invalid::Input))?;
    let verified = sakimori_webauthn::metadata::verify_mds(i).map_err(diagnostic)?;
    serde_json::to_string(&verified).map_err(|_| JsValue::from_str("invalid_mds"))
}
