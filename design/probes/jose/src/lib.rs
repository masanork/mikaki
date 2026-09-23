//! Isolated compile-time evaluation of jsonwebtoken for native and Wasm.
//!
//! This is not product code. It intentionally accepts a fixed algorithm per
//! entry point so callers cannot choose an algorithm from an untrusted header.

use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde_json::Value;

fn validate_with(token: &str, key: &DecodingKey, algorithm: Algorithm) -> bool {
    let mut validation = Validation::new(algorithm);
    validation.validate_exp = false;
    decode::<Value>(token, key, &validation).is_ok()
}

/// Verify a compact JWS with an ES256 public key in SEC1 DER form.
pub fn verify_es256(token: &str, public_key_sec1_der: &[u8]) -> bool {
    let key = DecodingKey::from_ec_der(public_key_sec1_der);
    validate_with(token, &key, Algorithm::ES256)
}

/// Verify a compact JWS with an RS256 public key in SubjectPublicKeyInfo DER.
pub fn verify_rs256(token: &str, public_key_spki_der: &[u8]) -> bool {
    let key = DecodingKey::from_rsa_der(public_key_spki_der);
    validate_with(token, &key, Algorithm::RS256)
}
