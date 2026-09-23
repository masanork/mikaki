//! Non-production interoperability probe; the ONLY key is a public RFC fixture.
//! This module does not parse JWTs, validate claims, or implement an OP.
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hex_literal::hex;
use p256::ecdsa::{
    Signature, SigningKey,
    signature::{Signer, Verifier},
};
use wasm_bindgen::prelude::*;

fn fixture_key() -> SigningKey {
    // Public test material from RFC 6979 A.2.5. Never use for real authentication.
    SigningKey::from_bytes(
        &hex!("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721").into(),
    )
    .expect("valid RFC fixture")
}

#[wasm_bindgen]
pub fn fixture_sign(input: &str) -> String {
    let signature: Signature = fixture_key().sign(input.as_bytes());
    URL_SAFE_NO_PAD.encode(signature.to_bytes())
}

#[wasm_bindgen]
pub fn fixture_verify(input: &str, signature: &str) -> bool {
    let Ok(bytes) = URL_SAFE_NO_PAD.decode(signature) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(&bytes) else {
        return false;
    };
    fixture_key()
        .verifying_key()
        .verify(input.as_bytes(), &signature)
        .is_ok()
}

#[wasm_bindgen]
pub fn fixture_public_jwk() -> String {
    let key = fixture_key();
    let point = key.verifying_key().to_sec1_point(false);
    let bytes = point.as_bytes();
    format!(
        r#"{{"kty":"EC","crv":"P-256","x":"{}","y":"{}"}}"#,
        URL_SAFE_NO_PAD.encode(&bytes[1..33]),
        URL_SAFE_NO_PAD.encode(&bytes[33..65])
    )
}

#[wasm_bindgen]
pub fn known_answer_matches() -> bool {
    let signature: Signature = fixture_key().sign(b"sample");
    signature.to_bytes().as_slice()
        == hex!(
            "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716
         f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6979_known_answer() {
        assert!(known_answer_matches());
    }

    #[test]
    fn rejects_tampered_message_and_invalid_signature() {
        let signature = fixture_sign("message");
        assert!(fixture_verify("message", &signature));
        assert!(!fixture_verify("tampered", &signature));
        assert!(!fixture_verify("message", "not-a-signature"));
    }

    #[test]
    fn raw_jose_and_der_are_distinct() {
        let raw = fixture_sign("message");
        let bytes = URL_SAFE_NO_PAD.decode(&raw).unwrap();
        assert_eq!(bytes.len(), 64);
        let der = Signature::from_slice(&bytes).unwrap().to_der();
        assert!(!fixture_verify(
            "message",
            &URL_SAFE_NO_PAD.encode(der.as_bytes())
        ));
    }
}
