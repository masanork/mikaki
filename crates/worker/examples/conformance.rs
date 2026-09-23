//! Test-only native transport. One bounded JSON request on stdin; no HTTP or state.
use serde::Deserialize;
use std::io::{Read, Write};
#[derive(Deserialize)]
struct Request {
    ceremony: sakimori_auth::Ceremony,
    browser_hash: String,
    now: u64,
    max_failures: u32,
    response: serde_json::Value,
    credential: Option<sakimori_webauthn::StoredCredential>,
}
fn verify(input: &str) -> Option<serde_json::Value> {
    sakimori_webauthn::strict_json(input, 8_388_608, 16).ok()?;
    let raw: serde_json::Value = serde_json::from_str(input).ok()?;
    if let Some(mds) = raw.get("mds") {
        let verified =
            sakimori_webauthn::metadata::verify_mds(serde_json::from_value(mds.clone()).ok()?)
                .ok()?;
        return serde_json::to_value(verified).ok();
    }
    sakimori_webauthn::strict_json(input, 262144, 16).ok()?;
    let i: Request = serde_json::from_str(input).ok()?;
    if i.ceremony.purpose == "register" {
        let proof = i
            .ceremony
            .register(
                &i.browser_hash,
                i.now,
                i.max_failures,
                serde_json::from_value(i.response).ok()?,
            )
            .ok()?;
        serde_json::to_value(proof).ok()
    } else {
        let proof = i
            .ceremony
            .authenticate(
                &i.browser_hash,
                i.now,
                i.max_failures,
                i.credential.as_ref()?,
                serde_json::from_value(i.response).ok()?,
            )
            .ok()?;
        serde_json::to_value(proof).ok()
    }
}
fn main() {
    let mut input = String::new();
    let result = std::io::stdin()
        .take(8_388_609)
        .read_to_string(&mut input)
        .ok()
        .and_then(|_| verify(&input));
    let output = serde_json::to_vec(&result).expect("JSON result");
    std::io::stdout().write_all(&output).expect("stdout");
}
