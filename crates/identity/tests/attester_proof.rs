use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use mikaki_identity::{
    attester_proof,
    issuance::{self, PublicJwk},
    wallet_authorization::Signer,
};
use p256::ecdsa::SigningKey;
use serde_json::{Value, json};
const NOW: u64 = 1791000000;
struct Key(SigningKey);
fn key(n: u8) -> Key {
    Key(SigningKey::from_slice(&[n; 32]).unwrap())
}
impl Signer for Key {
    fn public(&self) -> Result<PublicJwk, String> {
        Ok(PublicJwk::from_key(self.0.verifying_key()))
    }
    fn sign(&self, h: Value, c: Value) -> Result<String, String> {
        issuance::sign_jwt(&self.0, h, c).map_err(str::to_owned)
    }
}
fn header() -> Value {
    json!({"typ":"mikaki-wallet-attester-proof+jwt","alg":"ES256","jwk":key(6).public().unwrap()})
}
fn claims() -> Value {
    json!({"iss":"wallet","aud":"https://attester.example","nonce":B64.encode([1;32]),"purpose":"client","iat":NOW,"exp":NOW+60})
}
fn check(h: Value, c: Value, n: u8) -> bool {
    attester_proof::verify(
        &key(n).sign(h, c).unwrap(),
        "wallet",
        "https://attester.example",
        &B64.encode([1; 32]),
        "client",
        &key(6).public().unwrap(),
        NOW,
    )
    .is_ok()
}
#[test]
fn creates_verifiable_role_bound_native_proof() {
    for purpose in ["client", "holder"] {
        let proof = attester_proof::create(
            &key(6),
            "wallet",
            "https://attester.example",
            &B64.encode([1; 32]),
            purpose,
            NOW,
        )
        .unwrap();
        attester_proof::verify(
            &proof,
            "wallet",
            "https://attester.example",
            &B64.encode([1; 32]),
            purpose,
            &key(6).public().unwrap(),
            NOW,
        )
        .unwrap();
        assert!(
            attester_proof::verify(
                &proof,
                "wallet",
                "https://attester.example",
                &B64.encode([1; 32]),
                if purpose == "client" {
                    "holder"
                } else {
                    "client"
                },
                &key(6).public().unwrap(),
                NOW
            )
            .is_err()
        );
    }
}
#[test]
fn rejects_substitution_signature_time_and_unknown_proof_material() {
    assert!(check(header(), claims(), 6));
    assert!(!check(header(), claims(), 7));
    for (field, value) in [
        ("iss", json!("other")),
        ("aud", json!("https://issuer.example")),
        ("nonce", json!("other")),
        ("purpose", json!("holder")),
        ("iat", json!(NOW + 31)),
        ("iat", json!(NOW - 61)),
        ("exp", json!(NOW)),
        ("exp", json!(NOW + 61)),
        ("extension", json!(true)),
    ] {
        let mut c = claims();
        c[field] = value;
        assert!(!check(header(), c, 6), "{field}");
    }
    for (field, value) in [
        ("typ", json!("openid4vci-proof+jwt")),
        ("alg", json!("none")),
        ("crit", json!([])),
        ("x5c", json!([])),
        ("jku", json!("https://evil.example")),
    ] {
        let mut h = header();
        h[field] = value;
        assert!(!check(h, claims(), 6), "{field}");
    }
    let mut h = header();
    h["jwk"]["d"] = json!(B64.encode([6; 32]));
    assert!(!check(h, claims(), 6));
    assert!(
        attester_proof::verify(
            &"x".repeat(4097),
            "wallet",
            "https://attester.example",
            "nonce",
            "client",
            &key(6).public().unwrap(),
            NOW
        )
        .is_err()
    );
}
