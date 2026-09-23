//! Isolated jsonwebtoken evaluation for native and Wasm.
//!
//! This is not product code. It verifies signatures only and intentionally
//! accepts a fixed algorithm per entry point.

use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, jwk::Jwk};
use serde::Deserialize;
use serde_json::Value;
use wasm_bindgen::prelude::wasm_bindgen;

#[derive(Deserialize)]
struct ProbeClaims {
    #[serde(rename = "sub")]
    _sub: String,
    #[serde(rename = "iss")]
    _iss: String,
    #[serde(rename = "aud")]
    _aud: Value,
    #[serde(rename = "exp")]
    _exp: u64,
}

fn verify_with(token: &str, jwk_json: &str, algorithm: Algorithm) -> bool {
    let Ok(jwk) = serde_json::from_str::<Jwk>(jwk_json) else {
        return false;
    };
    let Ok(key) = DecodingKey::from_jwk(&jwk) else {
        return false;
    };
    let mut validation = Validation::new(algorithm);
    validation.required_spec_claims.clear();
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.validate_aud = false;
    decode::<ProbeClaims>(token, &key, &validation).is_ok()
}

fn verify_claims_with(
    token: &str,
    jwk_json: &str,
    algorithm: Algorithm,
    issuer: &str,
    audience: &str,
) -> bool {
    let Ok(jwk) = serde_json::from_str::<Jwk>(jwk_json) else {
        return false;
    };
    let Ok(key) = DecodingKey::from_jwk(&jwk) else {
        return false;
    };
    let mut validation = Validation::new(algorithm);
    validation.set_issuer(&[issuer]);
    validation.set_audience(&[audience]);
    validation.set_required_spec_claims(&["exp", "iss", "aud"]);
    validation.leeway = 0;
    decode::<ProbeClaims>(token, &key, &validation).is_ok()
}

/// Verify an ES256 compact JWS using a public JWK JSON value.
#[wasm_bindgen]
pub fn verify_es256(token: &str, public_jwk_json: &str) -> bool {
    verify_with(token, public_jwk_json, Algorithm::ES256)
}

/// Verify an RS256 compact JWS using a public JWK JSON value.
#[wasm_bindgen]
pub fn verify_rs256(token: &str, public_jwk_json: &str) -> bool {
    verify_with(token, public_jwk_json, Algorithm::RS256)
}

/// Verify an ES256 JWS and its exp, iss, and aud claims.
#[wasm_bindgen]
pub fn verify_es256_claims(
    token: &str,
    public_jwk_json: &str,
    issuer: &str,
    audience: &str,
) -> bool {
    verify_claims_with(token, public_jwk_json, Algorithm::ES256, issuer, audience)
}

/// Verify an RS256 JWS and its exp, iss, and aud claims.
#[wasm_bindgen]
pub fn verify_rs256_claims(
    token: &str,
    public_jwk_json: &str,
    issuer: &str,
    audience: &str,
) -> bool {
    verify_claims_with(token, public_jwk_json, Algorithm::RS256, issuer, audience)
}
