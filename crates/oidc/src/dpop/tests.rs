use super::*;
use p256::ecdsa::{SigningKey, signature::Signer};
use serde_json::{Value, json};

fn key() -> SigningKey {
    SigningKey::from_slice(&[7; 32]).unwrap()
}
fn header() -> Value {
    let point = key().verifying_key().to_sec1_point(false);
    json!({"alg":"ES256","typ":"dpop+jwt","jwk":{
        "kty":"EC","crv":"P-256","x":B64.encode(point.x().unwrap()),"y":B64.encode(point.y().unwrap())
    }})
}
fn claims() -> Value {
    json!({"htm":"POST","htu":"https://issuer.example/token","jti":"proof-1","iat":1000})
}
fn sign(h: &Value, c: &Value, key: &SigningKey) -> String {
    let input = format!(
        "{}.{}",
        B64.encode(serde_json::to_vec(h).unwrap()),
        B64.encode(serde_json::to_vec(c).unwrap())
    );
    let signature: Signature = key.sign(input.as_bytes());
    format!("{input}.{}", B64.encode(signature.to_bytes()))
}
fn verify(compact: &str, now: u64) -> Result<VerifiedDpopProof, InvalidDpopProof> {
    verify_dpop_proof(
        compact,
        "POST",
        "https://issuer.example/token",
        DpopTarget::Token,
        now,
    )
}

#[test]
fn signature_and_public_key_metadata_are_checked_before_returning_capability() {
    let proof = verify(&sign(&header(), &claims(), &key()), 1000).unwrap();
    assert_eq!(proof.jti_hash(), B64.encode(Sha256::digest(b"proof-1")));
    assert_eq!(proof.retain_until(), 1070);
    assert!(
        verify(
            &sign(
                &header(),
                &claims(),
                &SigningKey::from_slice(&[8; 32]).unwrap()
            ),
            1000
        )
        .is_err()
    );
    for (field, value) in [
        ("alg", json!("none")),
        ("typ", json!("JWT")),
        ("jku", json!("https://evil.example/key")),
        ("crit", json!(["extension"])),
        ("crit", json!(null)),
        ("b64", json!(false)),
        ("x5u", json!("https://evil.example/key")),
    ] {
        let mut h = header();
        h[field] = value;
        assert!(
            verify(&sign(&h, &claims(), &key()), 1000).is_err(),
            "{field}"
        );
    }
    for field in ["d", "p", "q", "dp", "dq", "qi", "k", "oth"] {
        let mut h = header();
        h["jwk"][field] = json!("private");
        assert!(
            verify(&sign(&h, &claims(), &key()), 1000).is_err(),
            "{field}"
        );
    }
    let mut extended = header();
    extended["unknown-noncritical"] = json!(true);
    let mut extended_claims = claims();
    extended_claims["unknown-claim"] = json!(true);
    assert!(verify(&sign(&extended, &extended_claims, &key()), 1000).is_ok());
    let mut h = header();
    h["jwk"]["use"] = json!("sig");
    assert!(verify(&sign(&h, &claims(), &key()), 1000).is_ok());
}

#[test]
fn method_origin_path_and_inclusive_timing_boundaries_are_enforced() {
    let compact = sign(&header(), &claims(), &key());
    for now in [990, 1000, 1070] {
        assert!(verify(&compact, now).is_ok());
    }
    for now in [989, 1071, u64::MAX] {
        assert!(verify(&compact, now).is_err());
    }
    for (field, value) in [
        ("htm", json!("GET")),
        ("htu", json!("https://evil.example/token")),
        ("htu", json!("https://issuer.example/userinfo")),
        ("htu", json!("http://issuer.example/token")),
        ("iat", json!(1.5)),
        ("iat", json!(-1)),
        ("jti", json!("")),
        ("jti", json!("a\n")),
        ("jti", json!("x".repeat(257))),
    ] {
        let mut c = claims();
        c[field] = value;
        assert!(
            verify(&sign(&header(), &c, &key()), 1000).is_err(),
            "{field}"
        );
    }
    for htu in [
        "https://issuer.example/token?x=1",
        "https://issuer.example/token#x",
    ] {
        let mut c = claims();
        c["htu"] = json!(htu);
        assert!(verify(&sign(&header(), &c, &key()), 1000).is_ok());
    }
    assert!(
        verify_dpop_proof(
            &compact,
            "POST",
            "https://issuer.example/token?ignored=1",
            DpopTarget::Token,
            1000
        )
        .is_ok()
    );
    assert!(verify(&format!("{compact}, {compact}"), 1000).is_err());
    assert!(verify(&"x".repeat(8193), 1000).is_err());
}

#[test]
fn resource_requires_both_token_hash_and_issued_thumbprint() {
    let thumbprint = verify(&sign(&header(), &claims(), &key()), 1000)
        .unwrap()
        .thumbprint()
        .to_owned();
    let mut c = claims();
    c["htm"] = json!("GET");
    c["htu"] = json!("https://issuer.example/userinfo");
    c["ath"] = json!(B64.encode(Sha256::digest(b"access-token")));
    let compact = sign(&header(), &c, &key());
    let target = |token, jkt| DpopTarget::Resource {
        access_token: token,
        thumbprint: jkt,
    };
    assert!(
        verify_dpop_proof(
            &compact,
            "GET",
            "https://issuer.example/userinfo",
            target("access-token", &thumbprint),
            1000
        )
        .is_ok()
    );
    for (token, jkt) in [
        ("Access-token", thumbprint.as_str()),
        ("access-token", "wrong-key"),
    ] {
        assert!(
            verify_dpop_proof(
                &compact,
                "GET",
                "https://issuer.example/userinfo",
                target(token, jkt),
                1000
            )
            .is_err()
        );
    }
    c.as_object_mut().unwrap().remove("ath");
    assert!(
        verify_dpop_proof(
            &sign(&header(), &c, &key()),
            "GET",
            "https://issuer.example/userinfo",
            target("access-token", &thumbprint),
            1000
        )
        .is_err()
    );
}

#[test]
fn nonce_is_bounded_and_available_only_from_verified_claims() {
    let mut c = claims();
    c["nonce"] = json!("issued-server-nonce");
    assert_eq!(
        verify(&sign(&header(), &c, &key()), 1000).unwrap().nonce(),
        Some("issued-server-nonce")
    );
    for invalid in ["", "a\n", " ", &"x".repeat(129)] {
        c["nonce"] = json!(invalid);
        assert!(verify(&sign(&header(), &c, &key()), 1000).is_err());
    }
}
