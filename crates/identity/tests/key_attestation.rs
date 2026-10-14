use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD as B64},
};
use mikaki_identity::{
    issuance::{PublicJwk, verify_attested_wallet_proof, verify_wallet_proof},
    key_attestation::{Trust, verify},
};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use serde_json::{Value, json};
const NOW: u64 = 1791000000;
fn key(n: u8) -> SigningKey {
    SigningKey::from_slice(&[n; 32]).unwrap()
}
fn cert(name: &str) -> String {
    STANDARD.encode(
        std::fs::read(format!(
            "{}/tests/fixtures/trust/{name}.der",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap(),
    )
}
fn policy() -> Trust {
    Trust {
        trust_anchors: vec![cert("root")],
        key_storage: None,
        user_authentication: None,
    }
}
fn header() -> Value {
    json!({"typ":"key-attestation+jwt","alg":"ES256","x5c":[cert("attester"),cert("intermediate")]})
}
fn claims() -> Value {
    json!({"iat":NOW,"exp":NOW+300,"nonce":"challenge","attested_keys":[PublicJwk::from_key(key(6).verifying_key())]})
}
fn jwt(h: Value, c: Value, n: u8) -> String {
    let input = format!(
        "{}.{}",
        B64.encode(serde_json::to_vec(&h).unwrap()),
        B64.encode(serde_json::to_vec(&c).unwrap())
    );
    let sig: Signature = key(n).sign(input.as_bytes());
    format!("{input}.{}", B64.encode(sig.to_bytes()))
}
fn check(h: Value, c: Value, n: u8) -> bool {
    verify(&jwt(h, c, n), "challenge", &policy(), true, NOW).is_ok()
}
#[test]
fn validates_purpose_trust_nonce_and_optional_exp_for_standalone() {
    policy().validate().unwrap();
    let v = verify(
        &jwt(header(), claims(), 5),
        "challenge",
        &policy(),
        true,
        NOW,
    )
    .unwrap();
    assert_eq!(v.holder, PublicJwk::from_key(key(6).verifying_key()));
    assert_eq!(v.expires_at, NOW + 300);
    let mut c = claims();
    c.as_object_mut().unwrap().remove("exp");
    assert!(
        verify(
            &jwt(header(), c.clone(), 5),
            "challenge",
            &policy(),
            false,
            NOW
        )
        .is_ok()
    );
    assert!(!check(header(), c, 5));
    let mut h = header();
    h["extension"] = json!(true);
    let mut c = claims();
    c["extension"] = json!(true);
    assert!(check(h, c, 5));
}
#[test]
fn rejects_signer_chain_time_nonce_and_ambiguous_keys() {
    assert!(!check(header(), claims(), 4));
    for (field, value) in [
        ("iat", json!(NOW + 31)),
        ("iat", json!(NOW - 61)),
        ("exp", json!(NOW)),
        ("exp", json!(NOW - 1)),
        ("nonce", json!("other")),
        ("attested_keys", json!([])),
        (
            "attested_keys",
            json!([
                PublicJwk::from_key(key(6).verifying_key()),
                PublicJwk::from_key(key(7).verifying_key())
            ]),
        ),
        ("status", json!({})),
        ("iat", json!(1.5)),
    ] {
        let mut c = claims();
        c[field] = value;
        assert!(!check(header(), c, 5), "{field}");
    }
    let mut c = claims();
    c["attested_keys"][0]["d"] = json!("private");
    assert!(!check(header(), c, 5));
    for (field, value) in [
        ("alg", json!("none")),
        ("typ", json!("JWT")),
        ("crit", json!(null)),
        ("b64", json!(false)),
        ("jku", json!("https://evil.example/key")),
        ("x5c", json!([cert("root")])),
        (
            "x5c",
            json!([cert("attester"), cert("intermediate"), cert("root")]),
        ),
    ] {
        let mut h = header();
        h[field] = value;
        assert!(!check(h, claims(), 5), "{field}");
    }
    let mut untrusted = policy();
    untrusted.trust_anchors = vec![cert("wrong-root")];
    assert!(
        verify(
            &jwt(header(), claims(), 5),
            "challenge",
            &untrusted,
            true,
            NOW
        )
        .is_err()
    );
}
#[test]
fn enforces_required_storage_and_authentication_without_promoting_unknown_values() {
    let mut p = policy();
    p.key_storage = Some(vec!["iso_18045_high".into()]);
    p.user_authentication = Some(vec!["iso_18045_moderate".into()]);
    let mut c = claims();
    assert!(verify(&jwt(header(), c.clone(), 5), "challenge", &p, true, NOW).is_err());
    c["key_storage"] = json!(["iso_18045_high"]);
    c["user_authentication"] = json!(["iso_18045_moderate"]);
    assert!(verify(&jwt(header(), c.clone(), 5), "challenge", &p, true, NOW).is_ok());
    c["key_storage"] = json!(["unknown"]);
    assert!(verify(&jwt(header(), c, 5), "challenge", &p, true, NOW).is_err());
}
#[test]
fn jwt_proof_must_prove_the_attested_key_and_authorized_client() {
    let attestation = jwt(header(), claims(), 5);
    let h = json!({"typ":"openid4vci-proof+jwt","alg":"ES256","jwk":PublicJwk::from_key(key(6).verifying_key()),"key_attestation":attestation});
    let c = json!({"aud":"https://issuer.example","iss":"wallet","nonce":"challenge","iat":NOW});
    let proof = jwt(h.clone(), c.clone(), 6);
    assert!(
        verify_attested_wallet_proof(
            &proof,
            "https://issuer.example",
            "challenge",
            "wallet",
            &policy(),
            NOW
        )
        .is_ok()
    );
    assert!(
        verify_wallet_proof(&proof, "https://issuer.example", "challenge", "wallet", NOW).is_err()
    );
    assert!(
        verify_attested_wallet_proof(
            &proof,
            "https://issuer.example",
            "challenge",
            "different-wallet",
            &policy(),
            NOW
        )
        .is_err()
    );
    let mut substitute = h.clone();
    substitute["jwk"] = json!(PublicJwk::from_key(key(7).verifying_key()));
    assert!(
        verify_attested_wallet_proof(
            &jwt(substitute, c.clone(), 7),
            "https://issuer.example",
            "challenge",
            "wallet",
            &policy(),
            NOW
        )
        .is_err()
    );
    assert!(
        verify_attested_wallet_proof(
            &jwt(h, c, 7),
            "https://issuer.example",
            "challenge",
            "wallet",
            &policy(),
            NOW
        )
        .is_err()
    );
}

#[test]
fn grouped_direct_attestation_binds_every_distinct_key_without_widening_single_proofs() {
    use mikaki_identity::key_attestation::verify_grouped;
    for count in [1, 2, 8] {
        let holders: Vec<_> = (10..10 + count)
            .map(|n| PublicJwk::from_key(key(n).verifying_key()))
            .collect();
        let mut c = claims();
        c["attested_keys"] = json!(holders);
        let attestation = jwt(header(), c.clone(), 5);
        let verified =
            verify_grouped(&attestation, "challenge", &policy(), count as usize, NOW).unwrap();
        assert_eq!(verified.holders, holders);
        assert_eq!(verified.expires_at, NOW + 300);
        for max in [0, 9] {
            assert!(verify_grouped(&attestation, "challenge", &policy(), max, NOW).is_err());
        }
        if count > 1 {
            assert!(
                verify_grouped(
                    &attestation,
                    "challenge",
                    &policy(),
                    count as usize - 1,
                    NOW
                )
                .is_err()
            );
            for jwt_proof in [false, true] {
                assert!(verify(&attestation, "challenge", &policy(), jwt_proof, NOW).is_err());
            }
            let proof = jwt(
                json!({"typ":"openid4vci-proof+jwt","alg":"ES256","jwk":holders[0],"key_attestation":attestation}),
                json!({"aud":"https://issuer.example","iss":"wallet","nonce":"challenge","iat":NOW}),
                10,
            );
            assert!(
                verify_attested_wallet_proof(
                    &proof,
                    "https://issuer.example",
                    "challenge",
                    "wallet",
                    &policy(),
                    NOW
                )
                .is_err()
            );
        }
        c.as_object_mut().unwrap().remove("exp");
        assert!(
            verify_grouped(
                &jwt(header(), c, 5),
                "challenge",
                &policy(),
                count as usize,
                NOW
            )
            .is_ok()
        );
    }
}

#[test]
fn grouped_attestation_rejects_any_bad_key_duplicate_or_untrusted_expired_signature() {
    use mikaki_identity::key_attestation::verify_grouped;
    let holders: Vec<_> = (10..18)
        .map(|n| PublicJwk::from_key(key(n).verifying_key()))
        .collect();
    let mut c = claims();
    c["attested_keys"] = json!(holders);
    let accepts = |claims: Value, signer| {
        verify_grouped(
            &jwt(header(), claims, signer),
            "challenge",
            &policy(),
            8,
            NOW,
        )
        .is_ok()
    };
    assert!(!accepts(c.clone(), 4));
    for (name, value) in [
        ("nonce", json!("other")),
        ("exp", json!(NOW)),
        ("status", json!({})),
        ("attested_keys", json!([])),
    ] {
        let mut bad = c.clone();
        bad[name] = value;
        assert!(!accepts(bad, 5), "{name}");
    }
    for (name, value) in [
        ("x", json!("invalid")),
        ("crv", json!("P-384")),
        ("d", json!("private")),
    ] {
        let mut bad = c.clone();
        bad["attested_keys"][7][name] = value;
        assert!(!accepts(bad, 5), "last key {name}");
    }
    let mut duplicate = c.clone();
    duplicate["attested_keys"][7] = duplicate["attested_keys"][0].clone();
    // JOSE metadata cannot disguise the same public key as another identity.
    duplicate["attested_keys"][7]["kid"] = json!("alias");
    assert!(!accepts(duplicate, 5));
    let mut overflow = c.clone();
    overflow["attested_keys"]
        .as_array_mut()
        .unwrap()
        .push(json!(PublicJwk::from_key(key(20).verifying_key())));
    assert!(!accepts(overflow, 5));
    let mut wrong = policy();
    wrong.trust_anchors = vec![cert("wrong-root")];
    assert!(verify_grouped(&jwt(header(), c.clone(), 5), "challenge", &wrong, 8, NOW).is_err());
    let mut constrained = policy();
    constrained.key_storage = Some(vec!["iso_18045_high".into()]);
    assert!(
        verify_grouped(
            &jwt(header(), c.clone(), 5),
            "challenge",
            &constrained,
            8,
            NOW
        )
        .is_err()
    );
    c["key_storage"] = json!(["iso_18045_high"]);
    assert!(verify_grouped(&jwt(header(), c, 5), "challenge", &constrained, 8, NOW).is_ok());
}
