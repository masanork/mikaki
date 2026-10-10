use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD as B64},
};
use mikaki_identity::{
    client_attestation::{AttesterTrust, verify},
    issuance::PublicJwk,
};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use serde_json::{Value, json};
const NOW: u64 = 1791000000;
fn certificate(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/trust/{name}.der",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}
fn key(n: u8) -> SigningKey {
    SigningKey::from_slice(&[n; 32]).unwrap()
}
fn jwt(header: Value, claims: Value, n: u8) -> String {
    let data = format!(
        "{}.{}",
        B64.encode(serde_json::to_vec(&header).unwrap()),
        B64.encode(serde_json::to_vec(&claims).unwrap())
    );
    let sig: Signature = key(n).sign(data.as_bytes());
    format!("{data}.{}", B64.encode(sig.to_bytes()))
}
fn policy() -> Vec<AttesterTrust> {
    vec![AttesterTrust {
        issuer: "https://attester.example".into(),
        trust_anchors: vec![STANDARD.encode(certificate("root"))],
    }]
}
fn ah() -> Value {
    json!({"typ":"oauth-client-attestation+jwt","alg":"ES256","x5c":[STANDARD.encode(certificate("attester")), STANDARD.encode(certificate("intermediate"))]})
}
fn ac() -> Value {
    json!({"iss":"https://attester.example","sub":"wallet","exp":NOW+300,"iat":NOW,"cnf":{"jwk":PublicJwk::from_key(key(6).verifying_key())},"extension":true})
}
fn ph() -> Value {
    json!({"typ":"oauth-client-attestation-pop+jwt","alg":"ES256"})
}
fn pc() -> Value {
    json!({"iss":"wallet","aud":"https://issuer.example","iat":NOW,"exp":NOW+300,"jti":"one-use-pop","extension":true})
}
fn check(ah: Value, ac: Value, ph: Value, pc: Value, a: u8, p: u8) -> bool {
    verify(
        &jwt(ah, ac, a),
        &jwt(ph, pc, p),
        "wallet",
        "https://issuer.example",
        &policy(),
        NOW,
    )
    .is_ok()
}
#[test]
fn authenticates_chain_and_instance_key_while_ignoring_extensions() {
    assert!(check(ah(), ac(), ph(), pc(), 5, 6));
    let mut c = ac();
    c["cnf"]["jwk"]["use"] = json!("sig");
    c["cnf"]["jwk"]["kid"] = json!("instance");
    let mut p = pc();
    p["aud"] = json!(["https://issuer.example"]);
    assert!(check(ah(), c, ph(), p, 5, 6));
}
#[test]
fn rejects_wrong_signer_instance_issuer_audience_time_and_private_keys() {
    assert!(!check(ah(), ac(), ph(), pc(), 4, 6));
    assert!(!check(ah(), ac(), ph(), pc(), 5, 4));
    for (field, value) in [
        ("sub", json!("another-wallet")),
        ("iss", json!("https://untrusted.example")),
        ("exp", json!(NOW)),
        ("iat", json!(NOW + 31)),
    ] {
        let mut c = ac();
        c[field] = value;
        assert!(!check(ah(), c, ph(), pc(), 5, 6), "attestation {field}");
    }
    for (field, value) in [
        ("iss", json!("other-wallet")),
        ("aud", json!("https://issuer.example/token")),
        ("exp", json!(NOW)),
        ("iat", json!(NOW - 301)),
        ("jti", json!("")),
    ] {
        let mut p = pc();
        p[field] = value;
        assert!(!check(ah(), ac(), ph(), p, 5, 6), "pop {field}");
    }
    let mut c = ac();
    c["cnf"]["jwk"]["d"] = json!(B64.encode([6; 32]));
    assert!(!check(ah(), c, ph(), pc(), 5, 6));
}

#[test]
fn allows_small_future_nbf_within_clock_skew_and_rejects_larger_or_expired_values() {
    for offset in [1, 30] {
        let mut c = ac();
        c["nbf"] = json!(NOW + offset);
        assert!(
            check(ah(), c, ph(), pc(), 5, 6),
            "attestation nbf +{offset}"
        );

        let mut p = pc();
        p["nbf"] = json!(NOW + offset);
        assert!(check(ah(), ac(), ph(), p, 5, 6), "pop nbf +{offset}");
    }

    for (offset, expected) in [(31, false), (300, false)] {
        let mut c = ac();
        c["nbf"] = json!(NOW + offset);
        assert_eq!(
            check(ah(), c, ph(), pc(), 5, 6),
            expected,
            "attestation nbf +{offset}"
        );

        let mut p = pc();
        p["nbf"] = json!(NOW + offset);
        assert_eq!(
            check(ah(), ac(), ph(), p, 5, 6),
            expected,
            "pop nbf +{offset}"
        );
    }

    let mut expired = ac();
    expired["exp"] = json!(NOW);
    assert!(!check(ah(), expired, ph(), pc(), 5, 6));

    let mut attestation_nbf_at_exp = ac();
    attestation_nbf_at_exp["nbf"] = json!(NOW + 10);
    attestation_nbf_at_exp["exp"] = json!(NOW + 10);
    assert!(!check(ah(), attestation_nbf_at_exp, ph(), pc(), 5, 6));

    let mut pop_nbf_at_exp = pc();
    pop_nbf_at_exp["nbf"] = json!(NOW + 10);
    pop_nbf_at_exp["exp"] = json!(NOW + 10);
    assert!(!check(ah(), ac(), ph(), pop_nbf_at_exp, 5, 6));
}
#[test]
fn rejects_untrusted_root_reader_purpose_root_in_header_and_critical_extensions() {
    for chain in [
        vec!["attester"],
        vec!["attester", "intermediate", "root"],
        vec!["leaf", "intermediate"],
        vec!["root"],
        vec!["attester", "wrong-root"],
    ] {
        let mut h = ah();
        h["x5c"] = json!(
            chain
                .iter()
                .map(|n| STANDARD.encode(certificate(n)))
                .collect::<Vec<_>>()
        );
        assert!(!check(h, ac(), ph(), pc(), 5, 6));
    }
    for field in ["crit", "b64", "jku", "x5u"] {
        let mut h = ph();
        h[field] = json!(true);
        assert!(!check(ah(), ac(), h, pc(), 5, 6));
    }
    let mut p = policy();
    p[0].trust_anchors = vec![STANDARD.encode(certificate("wrong-root"))];
    assert!(
        verify(
            &jwt(ah(), ac(), 5),
            &jwt(ph(), pc(), 6),
            "wallet",
            "https://issuer.example",
            &p,
            NOW
        )
        .is_err()
    );
}
