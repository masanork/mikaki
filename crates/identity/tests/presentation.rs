use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use mikaki_identity::{
    issuance::{self, PublicJwk},
    presentation::{self, VerifierRegistration},
};
use p256::ecdsa::{Signature, SigningKey, signature::Verifier};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
const NOW: u64 = 1790812800;
const VCT: &str = "https://issuer.example/identity/issuer/types/linked-document";
fn verifier() -> SigningKey {
    SigningKey::from_slice(&[5; 32]).unwrap()
}
fn registry() -> VerifierRegistration {
    VerifierRegistration {
        client_id: "verifier".into(),
        name: "Fixture verifier".into(),
        response_uri: "https://verifier.example/response".into(),
        kid: "key".into(),
        jwk: PublicJwk::from_key(verifier().verifying_key()),
        certificate_trust: None,
        response_encryption: None,
        profile: mikaki_identity::presentation::Profile::Oid4vpFinal,
    }
}
fn claims() -> Value {
    json!({"iss":"verifier","aud":"https://self-issued.me/v2","client_id":"verifier","response_type":"vp_token","response_mode":"direct_post","response_uri":"https://verifier.example/response","nonce":"N".repeat(43),"state":"S".repeat(43),"iat":NOW,"exp":NOW+120,"dcql_query":{"credentials":[{"id":"identity","format":"dc+sd-jwt","meta":{"vct_values":[VCT]},"claims":[{"path":["name"]}]}]}})
}
fn signed(c: Value) -> String {
    issuance::sign_jwt(
        &verifier(),
        json!({"typ":"oauth-authz-req+jwt","alg":"ES256","kid":"key"}),
        c,
    )
    .unwrap()
}
#[test]
fn requests_pin_signature_audience_destination_freshness_and_exact_query() {
    assert!(presentation::verify_request(&signed(claims()), &[registry()], VCT, NOW).is_ok());
    assert!(presentation::verify_request(&signed(claims()), &[], VCT, NOW).is_err());
    let mut wrong = registry();
    wrong.jwk = PublicJwk::from_key(SigningKey::from_slice(&[6; 32]).unwrap().verifying_key());
    assert!(presentation::verify_request(&signed(claims()), &[wrong], VCT, NOW).is_err());
    for (field, value) in [
        ("aud", json!("evil")),
        ("response_uri", json!("https://evil.example/response")),
        ("response_mode", json!("fragment")),
        ("exp", json!(NOW)),
        ("iat", json!(NOW + 31)),
        ("nonce", json!("short")),
        ("iss", json!("other")),
    ] {
        let mut c = claims();
        c[field] = value;
        assert!(
            presentation::verify_request(&signed(c), &[registry()], VCT, NOW).is_err(),
            "{field}"
        );
    }
    for path in [json!(["unknown"]), json!(["address", "formatted"])] {
        let mut c = claims();
        c["dcql_query"]["credentials"][0]["claims"][0]["path"] = path;
        assert!(presentation::verify_request(&signed(c), &[registry()], VCT, NOW).is_err());
    }
    let mut c = claims();
    c["dcql_query"]["credentials"][0]["claims"] = json!([{"path":["name"]},{"path":["name"]}]);
    assert!(presentation::verify_request(&signed(c), &[registry()], VCT, NOW).is_err());
    let mut c = claims();
    c["request_uri"] = json!("https://evil.example");
    assert!(presentation::verify_request(&signed(c), &[registry()], VCT, NOW).is_err());
}
#[test]
fn disclosure_selection_and_key_binding_cover_exact_bytes_nonce_and_verifier() {
    let approved =
        presentation::verify_request(&signed(claims()), &[registry()], VCT, NOW).unwrap();
    let name = B64.encode(serde_json::to_vec(&json!(["salt1", "name", "Fixture"])).unwrap());
    let address = B64
        .encode(serde_json::to_vec(&json!(["salt2","address",{"formatted":"Private"}])).unwrap());
    let credential = format!("issuer.jwt.signature~{address}~{name}~");
    let (selected, values) = presentation::select_disclosures(&credential, &approved).unwrap();
    assert_eq!(selected, format!("issuer.jwt.signature~{name}~"));
    assert_eq!(values, json!({"name":"Fixture"}));
    assert!(
        presentation::select_disclosures(&format!("issuer.jwt.signature~{address}~"), &approved)
            .is_err()
    );
    let holder = SigningKey::from_slice(&[2; 32]).unwrap();
    let vp = presentation::present(&holder, &selected, &approved, NOW).unwrap();
    let kb = vp.rsplit('~').next().unwrap();
    let (input, sig) = kb.rsplit_once('.').unwrap();
    let signature = Signature::from_slice(&B64.decode(sig).unwrap()).unwrap();
    holder
        .verifying_key()
        .verify(input.as_bytes(), &signature)
        .unwrap();
    let payload: Value =
        serde_json::from_slice(&B64.decode(input.split('.').nth(1).unwrap()).unwrap()).unwrap();
    assert_eq!(payload["aud"], "verifier");
    assert_eq!(payload["nonce"], "N".repeat(43));
    assert_eq!(
        payload["sd_hash"],
        B64.encode(Sha256::digest(selected.as_bytes()))
    );
    assert_ne!(
        payload["sd_hash"],
        B64.encode(Sha256::digest(credential.as_bytes()))
    );
    assert!(presentation::present(&holder, &selected, &approved, NOW + 120).is_err());
    assert_eq!(
        presentation::response_body(&vp, &approved),
        json!({"identity":[vp]})
    );
}

#[test]
fn encrypted_response_policy_is_registered_and_plaintext_downgrade_is_rejected() {
    use presentation::encryption::{ResponseEncryption, encrypt_response};
    let mut registered = registry();
    registered.response_encryption = Some(ResponseEncryption {
        kid: "receiver".into(),
        alg: "ECDH-ES".into(),
        enc: "A256GCM".into(),
        jwk: PublicJwk::from_key(SigningKey::from_slice(&[6; 32]).unwrap().verifying_key()),
    });
    assert!(
        presentation::verify_request(&signed(claims()), &[registered.clone()], VCT, NOW).is_err()
    );
    let mut c = claims();
    c["response_mode"] = json!("direct_post.jwt");
    assert!(presentation::verify_request(&signed(c.clone()), &[registry()], VCT, NOW).is_err());
    let approved =
        presentation::verify_request(&signed(c.clone()), &[registered.clone()], VCT, NOW).unwrap();
    assert!(
        encrypt_response(
            "vp",
            &approved,
            NOW + 120,
            p256::SecretKey::from_slice(&[7; 32]).unwrap(),
            [8; 12]
        )
        .is_err()
    );
    c["client_metadata"] =
        json!({"jwks":{"keys":[registered.response_encryption.as_ref().unwrap().jwk]}});
    assert!(presentation::verify_request(&signed(c), &[registered.clone()], VCT, NOW).is_err());
    let mut c = claims();
    c["response_mode"] = json!("direct_post.jwt");
    for (alg, enc, kid) in [
        ("RSA-OAEP", "A256GCM", "receiver"),
        ("ECDH-ES", "A128GCM", "receiver"),
        ("ECDH-ES", "A256GCM", ""),
    ] {
        let mut invalid = registered.clone();
        let e = invalid.response_encryption.as_mut().unwrap();
        e.alg = alg.into();
        e.enc = enc.into();
        e.kid = kid.into();
        assert!(presentation::verify_request(&signed(c.clone()), &[invalid], VCT, NOW).is_err());
    }
    let without = mikaki_identity::mdoc::oid4vp_transcript(
        approved.client_id(),
        approved.nonce(),
        approved.response_uri(),
    )
    .unwrap();
    assert_ne!(without, approved.mdoc_transcript().unwrap());
}

#[test]
fn legacy_pe_requires_explicit_profile_and_rejects_ambiguous_queries() {
    use presentation::{Profile, encryption::ResponseEncryption};
    let mut reg = registry();
    reg.profile = Profile::Oid4vpDraft18Mdoc;
    reg.response_encryption = Some(ResponseEncryption {
        kid: "receiver".into(),
        alg: "ECDH-ES".into(),
        enc: "A256GCM".into(),
        jwk: PublicJwk::from_key(SigningKey::from_slice(&[6; 32]).unwrap().verifying_key()),
    });
    let mut c = claims();
    c.as_object_mut().unwrap().remove("dcql_query");
    c["client_id_scheme"] = json!("pre-registered");
    c["response_mode"] = json!("direct_post.jwt");
    c["require_signed_request_object"] = json!(true);
    c["presentation_definition"] = json!({"id":"legacy-definition","input_descriptors":[{"id":mikaki_identity::mdoc::DOCTYPE,"format":{"mso_mdoc":{"alg":["ES256"]}},"constraints":{"limit_disclosure":"required","fields":[{"path":[format!("$['{}']['name']",mikaki_identity::mdoc::NAMESPACE)],"intent_to_retain":true}]}}]});
    let check = |c: Value, reg: VerifierRegistration| {
        presentation::verify_request_with_wallet_nonce(&signed(c), &[reg], VCT, NOW, [9; 32])
    };
    let approved = check(c.clone(), reg.clone()).unwrap();
    assert_eq!(approved.fields, ["name"]);
    assert_eq!(approved.retained_fields, ["name"]);
    assert!(presentation::verify_request(&signed(c.clone()), &[reg.clone()], VCT, NOW).is_err());
    assert!(check(claims(), reg.clone()).is_err());
    let mut final_reg = reg.clone();
    final_reg.profile = Profile::Oid4vpFinal;
    assert!(check(c.clone(), final_reg).is_err());
    for path in [
        "$..*",
        "$[*]",
        "$['app.tossa.mikaki.linked_document.1']['name']['extra']",
        "$['wrong']['name']",
    ] {
        let mut bad = c.clone();
        bad["presentation_definition"]["input_descriptors"][0]["constraints"]["fields"][0]["path"] =
            json!([path]);
        assert!(check(bad, reg.clone()).is_err());
    }
    let mut bad = c.clone();
    bad["presentation_definition"]["input_descriptors"][0]["constraints"]["limit_disclosure"] =
        json!("preferred");
    assert!(check(bad, reg.clone()).is_err());
    let mut bad = c.clone();
    bad["presentation_definition"]["input_descriptors"][0]["constraints"]["fields"][0]["optional"] =
        json!(true);
    assert!(check(bad, reg.clone()).is_err());
    let mut bad = c.clone();
    bad["client_id_scheme"] = json!("x509_san_dns");
    assert!(check(bad, reg.clone()).is_err());
    let changed =
        presentation::verify_request_with_wallet_nonce(&signed(c), &[reg], VCT, NOW, [10; 32])
            .unwrap();
    assert_ne!(
        approved.mdoc_transcript().unwrap(),
        changed.mdoc_transcript().unwrap()
    );
}

#[test]
fn certificate_required_registration_checks_signed_x5c_without_fallback() {
    use base64::engine::general_purpose::STANDARD;
    use mikaki_identity::certificate::ReaderTrust;
    let cert = |name: &str| {
        std::fs::read(format!(
            "{}/tests/fixtures/trust/{name}.der",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    };
    let chain = json!([
        STANDARD.encode(cert("leaf")),
        STANDARD.encode(cert("intermediate"))
    ]);
    let mut reg = registry();
    reg.certificate_trust = Some(ReaderTrust {
        trust_anchors: vec![STANDARD.encode(cert("root"))],
        dns_name: Some("verifier.example".into()),
        revocation: None,
    });
    let sign = |x5c: Value| {
        issuance::sign_jwt(
            &verifier(),
            json!({"typ":"oauth-authz-req+jwt","alg":"ES256","kid":"key","x5c":x5c}),
            claims(),
        )
        .unwrap()
    };
    assert!(presentation::verify_request(&sign(chain.clone()), &[reg.clone()], VCT, NOW).is_ok());
    assert!(presentation::verify_request(&signed(claims()), &[reg.clone()], VCT, NOW).is_err());
    for bad in [
        json!(null),
        json!([]),
        json!(["bogus"]),
        json!([
            STANDARD.encode(cert("wrong-eku")),
            STANDARD.encode(cert("intermediate"))
        ]),
    ] {
        assert!(presentation::verify_request(&sign(bad), &[reg.clone()], VCT, NOW).is_err());
    }
    assert!(presentation::verify_request(&sign(chain), &[registry()], VCT, NOW).is_err());
    reg.certificate_trust.as_mut().unwrap().dns_name = Some("evil.example".into());
    assert!(
        presentation::verify_request(
            &sign(json!([
                STANDARD.encode(cert("leaf")),
                STANDARD.encode(cert("intermediate"))
            ])),
            &[reg],
            VCT,
            NOW
        )
        .is_err()
    );
}

#[test]
fn crl_deadline_expires_approved_consent_before_request_expiration() {
    use base64::engine::general_purpose::STANDARD;
    use mikaki_identity::certificate::{CrlPolicy, ReaderTrust};
    let fixture = |name: &str| {
        std::fs::read(format!(
            "{}/tests/fixtures/trust/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    };
    let mut reg = registry();
    reg.certificate_trust = Some(ReaderTrust {
        trust_anchors: vec![STANDARD.encode(fixture("root.der"))],
        dns_name: Some("verifier.example".into()),
        revocation: Some(CrlPolicy {
            crls: vec![
                STANDARD.encode(fixture("clean-intermediate.crl")),
                STANDARD.encode(fixture("clean-root.crl")),
            ],
            max_age_seconds: 86401,
        }),
    });
    let signed = issuance::sign_jwt(&verifier(), json!({"typ":"oauth-authz-req+jwt","alg":"ES256","kid":"key","x5c":[STANDARD.encode(fixture("leaf.der")),STANDARD.encode(fixture("intermediate.der"))]}),claims()).unwrap();
    let approved = presentation::verify_request(&signed, &[reg], VCT, NOW).unwrap();
    assert_eq!(approved.expires_at(), NOW + 1);
    assert!(presentation::binding_claims("synthetic~", &approved, NOW).is_ok());
    assert_eq!(
        presentation::binding_claims("synthetic~", &approved, NOW + 1).err(),
        Some("request_expired")
    );
}

fn request_key_claims(byte: u8) -> Value {
    let jwk = PublicJwk::from_key(SigningKey::from_slice(&[byte; 32]).unwrap().verifying_key());
    let mut c = claims();
    c["response_mode"] = json!("direct_post.jwt");
    let mut key = serde_json::to_value(jwk).unwrap();
    key["kid"] = json!("recipient");
    key["alg"] = json!("ECDH-ES");
    key["use"] = json!("enc");
    c["client_metadata"] = json!({"jwks":{"keys":[key]},"encrypted_response_enc_values_supported":["A128GCM","A256GCM"]});
    c
}
fn request_key_registry() -> VerifierRegistration {
    let mut r = registry();
    r.profile = presentation::Profile::Oid4vpFinalRequestKeys;
    r
}
#[test]
fn request_recipient_rotation_binds_approval_and_mdoc_transcript() {
    let mut c = request_key_claims(6);
    let first =
        presentation::verify_request(&signed(c.clone()), &[request_key_registry()], VCT, NOW)
            .unwrap();
    c["client_metadata"] = request_key_claims(7)["client_metadata"].clone();
    let second =
        presentation::verify_request(&signed(c), &[request_key_registry()], VCT, NOW).unwrap();
    assert_ne!(first.request_hash, second.request_hash);
    assert_ne!(
        first.mdoc_transcript().unwrap(),
        second.mdoc_transcript().unwrap()
    );
    assert_ne!(
        first.response_encryption().unwrap().thumbprint().unwrap(),
        second.response_encryption().unwrap().thumbprint().unwrap()
    );
    assert_eq!(first.response_encryption().unwrap().enc, "A256GCM");
    assert_eq!(
        first.response_encryption().unwrap().jwk,
        PublicJwk::from_key(SigningKey::from_slice(&[6; 32]).unwrap().verifying_key())
    );
}
#[test]
fn request_recipient_profile_rejects_downgrade_and_signing_key_reuse() {
    let check = |c: Value, r: VerifierRegistration| {
        presentation::verify_request(&signed(c), &[r], VCT, NOW)
    };
    assert!(check(claims(), request_key_registry()).is_err());
    let mut c = request_key_claims(6);
    c["response_mode"] = json!("direct_post");
    assert!(check(c, request_key_registry()).is_err());
    let mut c = request_key_claims(6);
    c["client_metadata"] = Value::Null;
    assert!(check(c, request_key_registry()).is_err());
    assert!(check(request_key_claims(5), request_key_registry()).is_err());
    assert!(check(request_key_claims(6), registry()).is_err());
    let approved = check(request_key_claims(6), request_key_registry()).unwrap();
    let mut r = request_key_registry();
    r.response_encryption = approved.response_encryption().cloned();
    assert!(check(request_key_claims(6), r).is_err());
}
#[test]
fn request_recipient_selector_rejects_ambiguous_private_and_invalid_keys() {
    let base = request_key_claims(6)["client_metadata"].clone();
    let check = |m: &Value| presentation::encryption::from_client_metadata(m);
    for (field, value) in [
        ("alg", json!("ES256")),
        ("use", json!("sig")),
        ("x", json!("invalid")),
        ("kid", json!("")),
        ("key_ops", json!(["sign"])),
        ("d", json!("private")),
        ("jku", json!("https://evil.example")),
    ] {
        let mut m = base.clone();
        m["jwks"]["keys"][0][field] = value;
        assert!(check(&m).is_err(), "{field}");
    }
    let mut m = base.clone();
    m["encrypted_response_enc_values_supported"] = json!(["A128GCM"]);
    assert!(check(&m).is_err());
    m["encrypted_response_enc_values_supported"] = json!(["A256GCM", "A256GCM"]);
    assert!(check(&m).is_err());
    let key = base["jwks"]["keys"][0].clone();
    let mut m = base.clone();
    m["jwks"]["keys"] = json!([key.clone(), key.clone()]);
    assert!(check(&m).is_err());
    m["jwks"]["keys"][1]["kid"] = json!("distinct");
    assert!(check(&m).is_err());
    m["jwks"]["keys"] = json!(vec![key; 9]);
    assert!(check(&m).is_err());
    let mut m = base.clone();
    m["jwks"]["keys"].as_array_mut().unwrap().insert(
        0,
        json!({"kty":"RSA","kid":"unsupported","alg":"RSA-OAEP","d":"private"}),
    );
    assert!(check(&m).is_err());
    m["jwks"]["keys"][0].as_object_mut().unwrap().remove("d");
    assert_eq!(check(&m).unwrap().kid, "recipient");
    for field in ["kid", "alg"] {
        let mut bad = m.clone();
        bad["jwks"]["keys"][0]
            .as_object_mut()
            .unwrap()
            .remove(field);
        assert!(
            check(&bad).is_err(),
            "unsupported keys still require {field}"
        );
    }
}
#[test]
fn valid_signature_cannot_authorize_duplicate_recipient_json_members() {
    use p256::ecdsa::signature::Signer;
    let raw = serde_json::to_string(&request_key_claims(6))
        .unwrap()
        .replace(
            "\"kid\":\"recipient\"",
            "\"kid\":\"recipient\",\"kid\":\"substitute\"",
        );
    let header = B64.encode(br#"{"typ":"oauth-authz-req+jwt","alg":"ES256","kid":"key"}"#);
    let input = format!("{header}.{}", B64.encode(raw));
    let sig: Signature = verifier().sign(input.as_bytes());
    let jwt = format!("{input}.{}", B64.encode(sig.to_bytes()));
    assert!(presentation::verify_request(&jwt, &[request_key_registry()], VCT, NOW).is_err());
}

fn reader_certificate(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/trust/{name}.der",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}
fn x509_registry() -> VerifierRegistration {
    use base64::engine::general_purpose::STANDARD;
    let mut r = request_key_registry();
    r.profile = presentation::Profile::Oid4vpFinalX509Hash;
    r.client_id = format!(
        "x509_hash:{}",
        B64.encode(Sha256::digest(reader_certificate("leaf")))
    );
    r.certificate_trust = Some(mikaki_identity::certificate::ReaderTrust {
        trust_anchors: vec![STANDARD.encode(reader_certificate("root"))],
        dns_name: None,
        revocation: None,
    });
    r
}
fn x509_claims() -> Value {
    let mut c = request_key_claims(6);
    c["client_id"] = json!(x509_registry().client_id);
    c.as_object_mut().unwrap().remove("iss");
    c["client_metadata"]["vp_formats_supported"] = json!({"dc+sd-jwt":{"sd-jwt_alg_values":["ES256"],"kb-jwt_alg_values":["ES256"]},"mso_mdoc":{"issuerauth_alg_values":[-9],"deviceauth_alg_values":[-9]}});
    c
}
fn x509_signed(c: Value, chain: Value) -> String {
    issuance::sign_jwt(
        &verifier(),
        json!({"typ":"oauth-authz-req+jwt","alg":"ES256","x5c":chain}),
        c,
    )
    .unwrap()
}
fn reader_chain() -> Value {
    use base64::engine::general_purpose::STANDARD;
    json!([
        STANDARD.encode(reader_certificate("leaf")),
        STANDARD.encode(reader_certificate("intermediate"))
    ])
}
#[test]
fn x509_hash_authenticates_leaf_and_ignores_iss_without_header_kid() {
    for iss in [
        None,
        Some(json!("unrelated")),
        Some(json!(null)),
        Some(json!({"ignored":"value"})),
    ] {
        let mut c = x509_claims();
        if let Some(iss) = iss {
            c["iss"] = iss;
        }
        let approved = presentation::verify_request(
            &x509_signed(c, reader_chain()),
            &[x509_registry()],
            VCT,
            NOW,
        )
        .unwrap();
        assert_eq!(approved.client_id(), x509_registry().client_id);
        assert_eq!(approved.response_encryption().unwrap().enc, "A256GCM");
        assert_eq!(
            presentation::binding_claims("synthetic~", &approved, NOW).unwrap()["aud"],
            x509_registry().client_id
        );
    }
}
#[test]
fn x509_hash_rejects_root_included_duplicate_untrusted_or_changed_chains() {
    use base64::engine::general_purpose::STANDARD;
    let mut with_root = reader_chain();
    with_root
        .as_array_mut()
        .unwrap()
        .push(json!(STANDARD.encode(reader_certificate("root"))));
    let mut duplicate = reader_chain();
    let repeated = duplicate[1].clone();
    duplicate.as_array_mut().unwrap().push(repeated);
    for chain in [
        with_root,
        duplicate,
        json!([]),
        json!([
            STANDARD.encode(reader_certificate("wrong-eku")),
            STANDARD.encode(reader_certificate("intermediate"))
        ]),
        json!([STANDARD.encode(reader_certificate("root"))]),
    ] {
        assert!(
            presentation::verify_request(
                &x509_signed(x509_claims(), chain),
                &[x509_registry()],
                VCT,
                NOW
            )
            .is_err()
        );
    }
    let mut r = x509_registry();
    r.certificate_trust.as_mut().unwrap().trust_anchors =
        vec![STANDARD.encode(reader_certificate("wrong-root"))];
    assert!(
        presentation::verify_request(&x509_signed(x509_claims(), reader_chain()), &[r], VCT, NOW)
            .is_err()
    );
    let mut r = x509_registry();
    r.jwk = PublicJwk::from_key(SigningKey::from_slice(&[7; 32]).unwrap().verifying_key());
    assert!(
        presentation::verify_request(&x509_signed(x509_claims(), reader_chain()), &[r], VCT, NOW)
            .is_err()
    );
}
#[test]
fn x509_hash_identifier_cannot_downgrade_or_substitute_leaf_or_destination() {
    let mut r = x509_registry();
    r.client_id = format!("x509_hash:{}", "A".repeat(43));
    let mut c = x509_claims();
    c["client_id"] = json!(r.client_id);
    assert_eq!(
        presentation::verify_request(&x509_signed(c, reader_chain()), &[r], VCT, NOW).err(),
        Some("certificate_hash_mismatch")
    );
    for id in [
        "verifier",
        "x509_hash:short",
        "x509_hash:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "x509_san_dns:verifier.example",
    ] {
        let mut r = x509_registry();
        r.client_id = id.into();
        assert!(r.validate_identifier().is_err());
    }
    let mut r = x509_registry();
    r.profile = presentation::Profile::Oid4vpFinalRequestKeys;
    assert!(r.validate_identifier().is_err());
    let mut r = x509_registry();
    r.certificate_trust = None;
    assert!(r.validate_identifier().is_err());
    let mut c = x509_claims();
    c["response_uri"] = json!("https://other.example/response");
    assert!(
        presentation::verify_request(
            &x509_signed(c, reader_chain()),
            &[x509_registry()],
            VCT,
            NOW
        )
        .is_err()
    );
    let mut c = x509_claims();
    c["response_mode"] = json!("direct_post");
    assert!(
        presentation::verify_request(
            &x509_signed(c, reader_chain()),
            &[x509_registry()],
            VCT,
            NOW
        )
        .is_err()
    );
    assert!(
        presentation::verify_request(&signed(x509_claims()), &[x509_registry()], VCT, NOW).is_err()
    );
}

#[test]
fn matching_x509_hash_does_not_replace_purpose_expiry_status_or_signature_checks() {
    use base64::engine::general_purpose::STANDARD;
    for leaf in [
        "wrong-eku",
        "expired",
        "future",
        "missing-eku",
        "unknown-critical",
        "root",
    ] {
        let mut r = x509_registry();
        r.client_id = format!(
            "x509_hash:{}",
            B64.encode(Sha256::digest(reader_certificate(leaf)))
        );
        let mut c = x509_claims();
        c["client_id"] = json!(r.client_id);
        let chain = json!([
            STANDARD.encode(reader_certificate(leaf)),
            STANDARD.encode(reader_certificate("intermediate"))
        ]);
        assert!(
            presentation::verify_request(&x509_signed(c, chain), &[r], VCT, NOW).is_err(),
            "{leaf}"
        );
    }
    let mut r = x509_registry();
    let crl = |name| {
        STANDARD.encode(
            std::fs::read(format!(
                "{}/tests/fixtures/trust/{name}.crl",
                env!("CARGO_MANIFEST_DIR")
            ))
            .unwrap(),
        )
    };
    r.certificate_trust.as_mut().unwrap().revocation =
        Some(mikaki_identity::certificate::CrlPolicy {
            crls: vec![crl("revoked-leaf"), crl("clean-root")],
            max_age_seconds: 86401,
        });
    assert_eq!(
        presentation::verify_request(
            &x509_signed(x509_claims(), reader_chain()),
            std::slice::from_ref(&r),
            VCT,
            NOW
        )
        .err(),
        Some("certificate_revoked")
    );
    r.certificate_trust
        .as_mut()
        .unwrap()
        .revocation
        .as_mut()
        .unwrap()
        .crls[0] = crl("clean-intermediate");
    let approved =
        presentation::verify_request(&x509_signed(x509_claims(), reader_chain()), &[r], VCT, NOW)
            .unwrap();
    assert_eq!(approved.expires_at(), NOW + 1);
    let wrong_signer = issuance::sign_jwt(
        &SigningKey::from_slice(&[7; 32]).unwrap(),
        json!({"typ":"oauth-authz-req+jwt","alg":"ES256","x5c":reader_chain()}),
        x509_claims(),
    )
    .unwrap();
    assert_eq!(
        presentation::verify_request(&wrong_signer, &[x509_registry()], VCT, NOW).err(),
        Some("invalid_request_signature")
    );
    let mut bad = x509_signed(x509_claims(), reader_chain())
        .split('.')
        .map(str::to_string)
        .collect::<Vec<_>>();
    bad[2] = B64.encode([0; 64]);
    assert_eq!(
        presentation::verify_request(&bad.join("."), &[x509_registry()], VCT, NOW).err(),
        Some("invalid_request")
    );
}

#[test]
fn x509_final_accepts_optional_state_times_and_opaque_nonce_with_local_deadline() {
    let mut c = x509_claims();
    for field in ["iat", "exp", "state"] {
        c.as_object_mut().unwrap().remove(field);
    }
    c["nonce"] = json!("Nonce:opaque/+?0123456789abc");
    c["extension"] = json!({"future":"ignored"});
    let approved = presentation::verify_request(
        &x509_signed(c.clone(), reader_chain()),
        &[x509_registry()],
        VCT,
        NOW,
    )
    .unwrap();
    assert_eq!(approved.expires_at(), NOW + 120);
    assert_eq!(approved.state(), None);
    assert!(approved.authorization_payload("vp").get("state").is_none());
    assert_eq!(
        presentation::binding_claims("synthetic~", &approved, NOW).unwrap()["nonce"],
        c["nonce"]
    );
    c["state"] = json!("opaque state: &=+?日本語");
    c["iat"] = json!(NOW - 5000);
    c["exp"] = json!(NOW + 60);
    let approved = presentation::verify_request(
        &x509_signed(c, reader_chain()),
        &[x509_registry()],
        VCT,
        NOW,
    )
    .unwrap();
    assert_eq!(approved.expires_at(), NOW + 60);
    assert_eq!(
        approved.authorization_payload("vp")["state"],
        "opaque state: &=+?日本語"
    );
    assert!(presentation::binding_claims("synthetic~", &approved, NOW + 60).is_err());
}
#[test]
fn x509_final_optional_fields_do_not_ignore_invalid_values_or_unsupported_features() {
    for (field, value) in [
        ("iat", json!(null)),
        ("iat", json!(NOW + 31)),
        ("exp", json!(NOW)),
        ("exp", json!("future")),
        ("nbf", json!(NOW + 1)),
        ("nonce", json!("short")),
        ("nonce", json!("N".repeat(513))),
        ("nonce", json!("Nonce0123456789\n")),
        ("state", json!(null)),
        ("state", json!("S".repeat(2049))),
        ("state", json!("control\n")),
        ("aud", json!("another-wallet")),
        ("transaction_data", json!(null)),
        ("wallet_nonce", json!("unbound")),
        ("scope", json!("unsupported")),
    ] {
        let mut c = x509_claims();
        c[field] = value;
        assert!(
            presentation::verify_request(
                &x509_signed(c, reader_chain()),
                &[x509_registry()],
                VCT,
                NOW
            )
            .is_err(),
            "{field}"
        );
    }
    let mut c = request_key_claims(6);
    c["nonce"] = json!("N".repeat(26));
    assert!(presentation::verify_request(&signed(c), &[request_key_registry()], VCT, NOW).is_err());
}
#[test]
fn x509_final_negotiates_both_signature_formats_without_algorithm_downgrade() {
    for (format, meta, path, formats) in [
        (
            "dc+sd-jwt",
            json!({"vct_values":[VCT]}),
            json!(["name"]),
            json!({"dc+sd-jwt":{"sd-jwt_alg_values":["ES384","ES256"],"kb-jwt_alg_values":["ES256"]}}),
        ),
        (
            "mso_mdoc",
            json!({"doctype_value":mikaki_identity::mdoc::DOCTYPE}),
            json!([mikaki_identity::mdoc::NAMESPACE, "name"]),
            json!({"mso_mdoc":{"issuerauth_alg_values":[-9],"deviceauth_alg_values":[-7]}}),
        ),
    ] {
        let mut c = x509_claims();
        c["dcql_query"]["credentials"][0]["format"] = json!(format);
        c["dcql_query"]["credentials"][0]["meta"] = meta;
        c["dcql_query"]["credentials"][0]["claims"][0]["path"] = path;
        c["client_metadata"]["vp_formats_supported"] = formats;
        assert!(
            presentation::verify_request(
                &x509_signed(c.clone(), reader_chain()),
                &[x509_registry()],
                VCT,
                NOW
            )
            .is_ok()
        );
        c["client_metadata"]["vp_formats_supported"][format] = json!({});
        assert!(
            presentation::verify_request(
                &x509_signed(c, reader_chain()),
                &[x509_registry()],
                VCT,
                NOW
            )
            .is_ok(),
            "algorithm constraints are optional"
        );
    }
}
#[test]
fn x509_final_rejects_missing_formats_malformed_or_nonmatching_algorithm_constraints() {
    for formats in [
        json!(null),
        json!({}),
        json!({"mso_mdoc":{}}),
        json!({"dc+sd-jwt":null}),
        json!({"dc+sd-jwt":{"sd-jwt_alg_values":[]}}),
        json!({"dc+sd-jwt":{"kb-jwt_alg_values":["ES384"]}}),
        json!({"dc+sd-jwt":{"sd-jwt_alg_values":[-7]}}),
        json!({"dc+sd-jwt":{"kb-jwt_alg_values":null}}),
        json!({"dc+sd-jwt":{"sd-jwt_alg_values":vec!["ES256";17]}}),
    ] {
        let mut c = x509_claims();
        c["client_metadata"]["vp_formats_supported"] = formats;
        assert_eq!(
            presentation::verify_request(
                &x509_signed(c, reader_chain()),
                &[x509_registry()],
                VCT,
                NOW
            )
            .err(),
            Some("vp_formats_not_supported")
        );
    }
    for constraint in [json!([-65537]), json!(["-7"]), json!([]), json!([-35])] {
        let mut c = x509_claims();
        c["dcql_query"]["credentials"][0]["format"] = json!("mso_mdoc");
        c["dcql_query"]["credentials"][0]["meta"] =
            json!({"doctype_value":mikaki_identity::mdoc::DOCTYPE});
        c["dcql_query"]["credentials"][0]["claims"][0]["path"] =
            json!([mikaki_identity::mdoc::NAMESPACE, "name"]);
        c["client_metadata"]["vp_formats_supported"]["mso_mdoc"]["deviceauth_alg_values"] =
            constraint;
        assert!(
            presentation::verify_request(
                &x509_signed(c, reader_chain()),
                &[x509_registry()],
                VCT,
                NOW
            )
            .is_err()
        );
    }
}

#[test]
fn request_uri_post_metadata_contains_only_shared_static_capabilities() {
    use presentation::retrieval::{Method, RequestRetrieval, wallet_metadata};
    let context = RequestRetrieval::new(&x509_registry(), Method::Post, NOW, [9; 32]).unwrap();
    let fields = context.form().unwrap();
    assert_eq!(fields.len(), 2);
    assert_eq!(fields[1], ("wallet_nonce".into(), B64.encode([9; 32])));
    let metadata: Value = serde_json::from_str(&fields[0].1).unwrap();
    assert_eq!(metadata, wallet_metadata());
    assert_eq!(
        metadata["client_id_prefixes_supported"],
        json!(["x509_hash"])
    );
    assert_eq!(
        metadata["authorization_encryption_enc_values_supported"],
        json!(["A256GCM"])
    );
    assert_eq!(
        metadata["vp_formats_supported"]["mso_mdoc"]["deviceauth_alg_values"],
        json!([-7])
    );
    for secret in [
        "jwks",
        "credentials",
        "client_id",
        "device_id",
        "trust_anchors",
    ] {
        assert!(metadata.get(secret).is_none());
    }
}
#[test]
fn request_uri_post_verifies_one_use_nonce_without_altering_final_jwe_or_mdoc_binding() {
    use presentation::retrieval::{Method, RequestRetrieval};
    let r = x509_registry();
    let mut context = RequestRetrieval::new(&r, Method::Post, NOW, [9; 32]).unwrap();
    let mut c = x509_claims();
    c["wallet_nonce"] = json!(context.form().unwrap()[1].1);
    c["exp"] = json!(NOW + 600);
    let approved = context
        .verify(
            &x509_signed(c.clone(), reader_chain()),
            std::slice::from_ref(&r),
            VCT,
            NOW + 119,
        )
        .unwrap();
    assert_eq!(approved.expires_at(), NOW + 120);
    assert_eq!(
        approved.wallet_nonce(),
        None,
        "POST nonce is not the legacy handover nonce"
    );
    let encrypted = presentation::encryption::encrypt_response(
        "vp",
        &approved,
        NOW + 119,
        p256::SecretKey::from_slice(&[8; 32]).unwrap(),
        [8; 12],
    )
    .unwrap();
    let header: Value =
        serde_json::from_slice(&B64.decode(encrypted.split('.').next().unwrap()).unwrap()).unwrap();
    assert!(header.get("apu").is_none());
    assert_eq!(header["apv"], B64.encode("N".repeat(43)));
    c.as_object_mut().unwrap().remove("wallet_nonce");
    let get = presentation::verify_request(
        &x509_signed(c, reader_chain()),
        std::slice::from_ref(&r),
        VCT,
        NOW,
    )
    .unwrap();
    assert_eq!(
        approved.mdoc_transcript().unwrap(),
        get.mdoc_transcript().unwrap()
    );
    assert_eq!(
        context.verify("invalid", &[r], VCT, NOW).err(),
        Some("request_consumed")
    );
    assert!(context.form().is_err());
}
#[test]
fn request_uri_nonce_absence_substitution_expiry_and_get_downgrade_fail_closed() {
    use presentation::retrieval::{Method, RequestRetrieval};
    for nonce in [
        None,
        Some(json!(null)),
        Some(json!(B64.encode([8; 32]))),
        Some(json!([B64.encode([9; 32])])),
    ] {
        let r = x509_registry();
        let mut ctx = RequestRetrieval::new(&r, Method::Post, NOW, [9; 32]).unwrap();
        let mut c = x509_claims();
        if let Some(value) = nonce {
            c["wallet_nonce"] = value;
        }
        assert_eq!(
            ctx.verify(
                &x509_signed(c, reader_chain()),
                std::slice::from_ref(&r),
                VCT,
                NOW
            )
            .err(),
            Some("invalid_wallet_nonce")
        );
        assert_eq!(
            ctx.verify("unused", &[r], VCT, NOW).err(),
            Some("request_consumed")
        );
    }
    let r = x509_registry();
    let mut ctx = RequestRetrieval::new(&r, Method::Post, NOW, [9; 32]).unwrap();
    let mut c = x509_claims();
    c["wallet_nonce"] = json!(B64.encode([9; 32]));
    let signed = x509_signed(c, reader_chain());
    assert_eq!(
        ctx.verify(&signed, std::slice::from_ref(&r), VCT, NOW + 120)
            .err(),
        Some("request_expired")
    );
    assert!(presentation::verify_request(&signed, std::slice::from_ref(&r), VCT, NOW).is_err());
    let mut get = RequestRetrieval::new(&r, Method::Get, NOW, [9; 32]).unwrap();
    assert!(get.form().unwrap().is_empty());
    assert_eq!(
        get.verify(&signed, &[r], VCT, NOW).err(),
        Some("invalid_wallet_nonce")
    );
    assert!(RequestRetrieval::new(&registry(), Method::Post, NOW, [9; 32]).is_err());
}

// The recipient decrypts errors without access to any credential or holder key.
fn decrypt_error(compact: &str) -> (Value, Value) {
    use aes_gcm::{
        Aes256Gcm, KeyInit, Nonce,
        aead::{Aead, Payload},
    };
    let parts: Vec<_> = compact.split('.').collect();
    assert_eq!(parts.len(), 5);
    assert_eq!(parts[1], "");
    let header: Value = serde_json::from_slice(&B64.decode(parts[0]).unwrap()).unwrap();
    let epk: PublicJwk = serde_json::from_value(header["epk"].clone()).unwrap();
    let secret = p256::SecretKey::from_slice(&[6; 32]).unwrap();
    let public = epk.verifying_key().unwrap();
    let shared = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), public.as_affine());
    let mut kdf = Sha256::new();
    kdf.update(1u32.to_be_bytes());
    kdf.update(shared.raw_secret_bytes());
    let apu = header
        .get("apu")
        .map(|v| B64.decode(v.as_str().unwrap()).unwrap())
        .unwrap_or_default();
    let apv = header
        .get("apv")
        .map(|v| B64.decode(v.as_str().unwrap()).unwrap())
        .unwrap_or_default();
    for bytes in [b"A256GCM".as_slice(), apu.as_slice(), apv.as_slice()] {
        kdf.update((bytes.len() as u32).to_be_bytes());
        kdf.update(bytes);
    }
    kdf.update(256u32.to_be_bytes());
    let key = kdf.finalize();
    let mut ciphertext = B64.decode(parts[3]).unwrap();
    ciphertext.extend(B64.decode(parts[4]).unwrap());
    let iv: [u8; 12] = B64.decode(parts[2]).unwrap().try_into().unwrap();
    let plaintext = Aes256Gcm::new_from_slice(&key)
        .unwrap()
        .decrypt(
            &Nonce::from(iv),
            Payload {
                msg: &ciphertext,
                aad: parts[0].as_bytes(),
            },
        )
        .unwrap();
    (header, serde_json::from_slice(&plaintext).unwrap())
}
#[test]
fn authenticated_errors_are_credential_free_encrypted_bound_and_one_use() {
    use presentation::{
        error_response::Outcome,
        retrieval::{Method, RequestRetrieval},
    };
    for method in [Method::Get, Method::Post] {
        for case in 0..3 {
            let r = x509_registry();
            let mut ctx = RequestRetrieval::new(&r, method, NOW, [9; 32]).unwrap();
            let mut c = x509_claims();
            if method == Method::Post {
                c["wallet_nonce"] = json!(ctx.form().unwrap()[1].1);
            }
            if case == 0 {
                c.as_object_mut().unwrap().remove("nonce");
            }
            if case == 1 {
                c["redirect_uri"] = json!("https://attacker.example/never-contact");
            }
            if case == 2 {
                c["transaction_data"] = json!(["unsupported"]);
                c.as_object_mut().unwrap().remove("state");
            }
            let compact = x509_signed(c, reader_chain());
            let Outcome::Error(error) = ctx
                .evaluate(&compact, std::slice::from_ref(&r), VCT, NOW)
                .unwrap()
            else {
                panic!("approved invalid request")
            };
            assert_eq!(error.response_uri(), r.response_uri);
            let code = if case == 2 {
                "invalid_transaction_data"
            } else {
                "invalid_request"
            };
            assert_eq!(error.code(), code);
            assert_eq!(error.expires_at(), NOW + 120);
            assert_eq!(
                ctx.evaluate(&compact, &[r], VCT, NOW).err(),
                Some("request_consumed")
            );
            assert!(ctx.form().is_err());
            let encrypted = error
                .encrypt(NOW, p256::SecretKey::from_slice(&[8; 32]).unwrap(), [8; 12])
                .unwrap();
            let (header, payload) = decrypt_error(&encrypted);
            assert!(header.get("apu").is_none());
            assert_eq!(
                header.get("apv").cloned(),
                if case == 0 {
                    None
                } else {
                    Some(json!(B64.encode("N".repeat(43))))
                }
            );
            assert_eq!(
                payload,
                if case == 2 {
                    json!({"error":code})
                } else {
                    json!({"error":code,"state":"S".repeat(43)})
                }
            );
        }
    }
}
#[test]
fn error_routing_never_uses_unauthenticated_or_unbound_request_data() {
    use presentation::retrieval::{Method, RequestRetrieval};
    for case in 0..16 {
        let mut r = x509_registry();
        let mut c = x509_claims();
        c.as_object_mut().unwrap().remove("nonce");
        let mut at = NOW;
        match case {
            0 => c["client_id"] = json!("x509_hash:other"),
            1 => c["response_uri"] = json!("https://attacker.example/response"),
            2 => c["aud"] = json!("wrong"),
            3 => c["response_type"] = json!("code"),
            4 => c["response_mode"] = json!("direct_post"),
            5 => c["exp"] = json!(NOW),
            6 => c["nbf"] = json!(NOW + 1),
            7 => c["wallet_nonce"] = json!("unsolicited"),
            8 => c["state"] = json!(null),
            9 => c["client_metadata"]["jwks"]["keys"][0]["d"] = json!("private"),
            10 => {
                c["client_metadata"] = request_key_claims(5)["client_metadata"].clone();
            }
            11 => {
                c.as_object_mut().unwrap().remove("client_metadata");
            }
            12 => r.certificate_trust = None,
            13 => {
                r.jwk =
                    PublicJwk::from_key(SigningKey::from_slice(&[7; 32]).unwrap().verifying_key())
            }
            14 => at = NOW + 120,
            15 => c["nonce"] = json!(null),
            _ => unreachable!(),
        }
        let mut ctx = RequestRetrieval::new(&x509_registry(), Method::Get, NOW, [9; 32]).unwrap();
        assert!(
            ctx.evaluate(&x509_signed(c, reader_chain()), &[r], VCT, at)
                .is_err(),
            "case {case}"
        );
    }

    use base64::engine::general_purpose::STANDARD;
    for leaf in [
        "wrong-eku",
        "expired",
        "future",
        "missing-eku",
        "unknown-critical",
        "root",
    ] {
        let mut r = x509_registry();
        r.client_id = format!(
            "x509_hash:{}",
            B64.encode(Sha256::digest(reader_certificate(leaf)))
        );
        let mut c = x509_claims();
        c["client_id"] = json!(r.client_id);
        c.as_object_mut().unwrap().remove("nonce");
        let chain = json!([
            STANDARD.encode(reader_certificate(leaf)),
            STANDARD.encode(reader_certificate("intermediate"))
        ]);
        let mut ctx = RequestRetrieval::new(&r, Method::Get, NOW, [9; 32]).unwrap();
        assert!(
            ctx.evaluate(&x509_signed(c, chain), &[r], VCT, NOW)
                .is_err(),
            "{leaf}"
        );
    }
    let mut r = x509_registry();
    let crl = |name| {
        STANDARD.encode(
            std::fs::read(format!(
                "{}/tests/fixtures/trust/{name}.crl",
                env!("CARGO_MANIFEST_DIR")
            ))
            .unwrap(),
        )
    };
    r.certificate_trust.as_mut().unwrap().revocation =
        Some(mikaki_identity::certificate::CrlPolicy {
            crls: vec![crl("revoked-leaf"), crl("clean-root")],
            max_age_seconds: 86401,
        });
    let mut c = x509_claims();
    c.as_object_mut().unwrap().remove("nonce");
    let mut ctx = RequestRetrieval::new(&r, Method::Get, NOW, [9; 32]).unwrap();
    assert!(
        ctx.evaluate(&x509_signed(c.clone(), reader_chain()), &[r], VCT, NOW)
            .is_err()
    );
    use p256::ecdsa::signature::Signer;
    let raw = serde_json::to_string(&c).unwrap().replace(
        "\"kid\":\"recipient\"",
        "\"kid\":\"recipient\",\"kid\":\"other\"",
    );
    let header = B64.encode(
        serde_json::to_vec(
            &json!({"typ":"oauth-authz-req+jwt","alg":"ES256","x5c":reader_chain()}),
        )
        .unwrap(),
    );
    let input = format!("{header}.{}", B64.encode(raw));
    let sig: Signature = verifier().sign(input.as_bytes());
    let jwt = format!("{input}.{}", B64.encode(sig.to_bytes()));
    let r = x509_registry();
    let mut ctx = RequestRetrieval::new(&r, Method::Get, NOW, [9; 32]).unwrap();
    assert!(ctx.evaluate(&jwt, &[r], VCT, NOW).is_err());
    let r = x509_registry();
    let mut c = x509_claims();
    c.as_object_mut().unwrap().remove("nonce");
    let mut ctx = RequestRetrieval::new(&r, Method::Post, NOW, [9; 32]).unwrap();
    assert!(
        ctx.evaluate(
            &x509_signed(c.clone(), reader_chain()),
            std::slice::from_ref(&r),
            VCT,
            NOW
        )
        .is_err()
    );
    let mut ctx = RequestRetrieval::new(&x509_registry(), Method::Get, NOW, [9; 32]).unwrap();
    let jwt = x509_signed(c.clone(), reader_chain());
    let (input, _) = jwt.rsplit_once('.').unwrap();
    let bad = format!("{input}.{}", B64.encode([0; 64]));
    assert!(
        ctx.evaluate(&bad, std::slice::from_ref(&r), VCT, NOW)
            .is_err()
    );
    let mut ctx = RequestRetrieval::new(&x509_registry(), Method::Get, NOW, [9; 32]).unwrap();
    let mut chain = reader_chain();
    chain[0] = chain[1].clone();
    assert!(
        ctx.evaluate(
            &x509_signed(c.clone(), chain),
            std::slice::from_ref(&r),
            VCT,
            NOW
        )
        .is_err()
    );
    let mut ctx = RequestRetrieval::new(&x509_registry(), Method::Get, NOW, [9; 32]).unwrap();
    let presentation::error_response::Outcome::Error(error) = ctx
        .evaluate(&x509_signed(c, reader_chain()), &[r], VCT, NOW)
        .unwrap()
    else {
        panic!("approved")
    };
    assert_eq!(
        error
            .encrypt(
                NOW + 120,
                p256::SecretKey::from_slice(&[8; 32]).unwrap(),
                [8; 12]
            )
            .err(),
        Some("request_expired")
    );
}

fn set_claims(format: &str, required: bool) -> Value {
    let mut c = x509_claims();
    if format == "mso_mdoc" {
        c["dcql_query"]["credentials"][0]["format"] = json!(format);
        c["dcql_query"]["credentials"][0]["meta"] =
            json!({"doctype_value":mikaki_identity::mdoc::DOCTYPE});
        c["dcql_query"]["credentials"][0]["claims"] =
            json!([{"path":[mikaki_identity::mdoc::NAMESPACE,"name"],"intent_to_retain":true}]);
    }
    let mut fake = c["dcql_query"]["credentials"][0].clone();
    fake["id"] = json!("missing");
    fake["meta"] = if format == "mso_mdoc" {
        json!({"doctype_value":"org.example.unavailable"})
    } else {
        json!({"vct_values":["urn:example:unavailable"]})
    };
    fake["claims"] = if format == "mso_mdoc" {
        json!([{"path":["org.example.unavailable","unknown"]}])
    } else {
        json!([{"path":["unknown"]}])
    };
    c["dcql_query"]["credentials"]
        .as_array_mut()
        .unwrap()
        .push(fake);
    c["dcql_query"]["credential_sets"] =
        json!([{"options":[["identity"]]}, {"options":[["missing"]],"required":required}]);
    c
}
#[test]
fn credential_sets_omit_optional_nonmatching_types_and_never_send_partial_required_results() {
    use presentation::{
        error_response::Outcome,
        retrieval::{Method, RequestRetrieval},
    };
    for format in ["dc+sd-jwt", "mso_mdoc"] {
        for method in [Method::Get, Method::Post] {
            for required in [false, true] {
                let r = x509_registry();
                let mut ctx = RequestRetrieval::new(&r, method, NOW, [9; 32]).unwrap();
                let mut c = set_claims(format, required);
                if method == Method::Post {
                    c["wallet_nonce"] = json!(ctx.form().unwrap()[1].1);
                }
                match ctx
                    .evaluate(&x509_signed(c, reader_chain()), &[r], VCT, NOW)
                    .unwrap()
                {
                    Outcome::Approved(request) => {
                        assert!(!required);
                        assert_eq!(request.query_id(), "identity");
                        assert_eq!(request.format(), format);
                        assert_eq!(
                            presentation::response_body("vp", &request),
                            json!({"identity":["vp"]})
                        );
                        assert_eq!(
                            request.retained_fields,
                            if format == "mso_mdoc" {
                                vec!["name".to_string()]
                            } else {
                                vec![]
                            }
                        );
                    }
                    Outcome::Error(error) => {
                        assert!(required);
                        assert_eq!(error.code(), "access_denied");
                        let (_, payload) = decrypt_error(
                            &error
                                .encrypt(
                                    NOW,
                                    p256::SecretKey::from_slice(&[8; 32]).unwrap(),
                                    [8; 12],
                                )
                                .unwrap(),
                        );
                        assert_eq!(
                            payload,
                            json!({"error":"access_denied","state":"S".repeat(43)})
                        );
                    }
                }
            }
        }
    }
}
#[test]
fn credential_set_alternatives_choose_only_one_satisfying_signed_id() {
    let mut c = set_claims("dc+sd-jwt", true);
    // An unavailable first alternative must not prevent choosing the available one.
    c["dcql_query"]["credential_sets"] =
        json!([{"options":[["missing"],["identity"]]}, {"options":[["identity"]]}]);
    c["dcql_query"]["credentials"][0]["meta"]["vct_values"] = json!(["urn:example:other", VCT]);
    c["dcql_query"]["credentials"]
        .as_array_mut()
        .unwrap()
        .reverse();
    let r = x509_registry();
    let q = presentation::verify_request(
        &x509_signed(c.clone(), reader_chain()),
        std::slice::from_ref(&r),
        VCT,
        NOW,
    )
    .unwrap();
    assert_eq!(q.query_id(), "identity");
    c["dcql_query"]["credentials"][1]["id"] = json!("signed_alternative");
    c["dcql_query"]["credential_sets"] = json!([{"options":[["signed_alternative"]]}]);
    let q = presentation::verify_request(&x509_signed(c, reader_chain()), &[r], VCT, NOW).unwrap();
    assert_eq!(
        presentation::response_body("vp", &q),
        json!({"signed_alternative":["vp"]})
    );
}
#[test]
fn malformed_and_unsupported_sets_cannot_be_reclassified_as_access_denied() {
    use presentation::retrieval::{Method, RequestRetrieval};
    for case in 0..18 {
        let mut c = set_claims("dc+sd-jwt", true);
        match case {
            0 => c["dcql_query"]["credential_sets"][0]["options"] = json!([["unknown_id"]]),
            1 => {
                c["dcql_query"]["credential_sets"][0]["options"] = json!([["identity", "identity"]])
            }
            2 => c["dcql_query"]["credential_sets"][0]["options"] = json!([]),
            3 => c["dcql_query"]["credential_sets"][0]["options"] = json!([[]]),
            4 => c["dcql_query"]["credential_sets"][0]["required"] = json!(null),
            5 => c["dcql_query"]["credential_sets"] = json!(null),
            6 => c["dcql_query"]["credential_sets"] = json!([]),
            7 => c["dcql_query"]["credentials"][1]["id"] = json!("identity"),
            8 => c["dcql_query"]["credentials"][1]["format"] = json!("unknown_format"),
            9 => c["dcql_query"]["credentials"][1]["claims"][0]["path"] = json!([]),
            10 => c["dcql_query"]["credentials"][1]["claims"][0]["values"] = json!([true]),
            11 => c["dcql_query"]["credentials"][1]["claim_sets"] = json!([["claim"]]),
            12 => c["dcql_query"]["credentials"][1]["meta"]["vct_values"] = json!(null),
            13 => c["dcql_query"]["credentials"][1]["meta"]["vct_values"] = json!([]),
            14 => c["scope"] = json!("unsupported"),
            15 => {
                c["dcql_query"]["credential_sets"][0]["options"] = json!(vec![vec!["identity"]; 9])
            }
            16 => {
                c["dcql_query"]["credential_sets"] =
                    json!(vec![json!({"options":[["identity"]]}); 9])
            }
            17 => c["dcql_query"]["credentials"] = json!([]),
            _ => unreachable!(),
        }
        let r = x509_registry();
        let mut ctx = RequestRetrieval::new(&r, Method::Get, NOW, [9; 32]).unwrap();
        assert!(
            ctx.evaluate(&x509_signed(c, reader_chain()), &[r], VCT, NOW)
                .is_err(),
            "case {case}"
        );
    }
    for case in 0..4 {
        let r = x509_registry();
        let mut c = set_claims("dc+sd-jwt", true);
        let mut ctx = RequestRetrieval::new(&r, Method::Post, NOW, [9; 32]).unwrap();
        c["wallet_nonce"] = json!(ctx.form().unwrap()[1].1);
        if case == 0 {
            c["client_id"] = json!("x509_hash:other");
        }
        if case == 1 {
            c["wallet_nonce"] = json!("substitution");
        }
        if case == 2 {
            c["response_uri"] = json!("https://attacker.example");
        }
        let jwt = x509_signed(c, reader_chain());
        let jwt = if case == 3 {
            let (input, _) = jwt.rsplit_once('.').unwrap();
            format!("{input}.{}", B64.encode([0; 64]))
        } else {
            jwt
        };
        assert!(
            ctx.evaluate(&jwt, &[r], VCT, NOW).is_err(),
            "unauthenticated denial case {case}"
        );
    }
    // Without sets every query is required; never return a partial presentation.
    let r = x509_registry();
    let mut c = set_claims("dc+sd-jwt", false);
    c["dcql_query"]
        .as_object_mut()
        .unwrap()
        .remove("credential_sets");
    let mut ctx = RequestRetrieval::new(&r, Method::Get, NOW, [9; 32]).unwrap();
    let presentation::error_response::Outcome::Error(error) = ctx
        .evaluate(&x509_signed(c, reader_chain()), &[r], VCT, NOW)
        .unwrap()
    else {
        panic!("partial approval")
    };
    assert_eq!(error.code(), "access_denied");
    let r = x509_registry();
    let mut c = set_claims("dc+sd-jwt", false);
    c["dcql_query"]["credentials"][1] = c["dcql_query"]["credentials"][0].clone();
    c["dcql_query"]["credentials"][1]["id"] = json!("second");
    c["dcql_query"]["credential_sets"] = json!([{"options":[["identity","second"]]}]);
    let mut ctx = RequestRetrieval::new(&r, Method::Get, NOW, [9; 32]).unwrap();
    let presentation::error_response::Outcome::Approved(request) = ctx
        .evaluate(&x509_signed(c, reader_chain()), &[r], VCT, NOW)
        .unwrap()
    else {
        panic!("rejected complete request")
    };
    assert_eq!(
        presentation::response_body("vp", &request),
        json!({"identity":["vp"],"second":["vp"]})
    );
}

#[test]
fn omitted_claims_select_no_attributes_but_preserve_type_holder_and_request_binding() {
    for format in ["dc+sd-jwt", "mso_mdoc"] {
        let mut c = set_claims(format, false);
        c["dcql_query"]["credentials"][0]
            .as_object_mut()
            .unwrap()
            .remove("claims");
        let r = x509_registry();
        let approved = presentation::verify_request(
            &x509_signed(c.clone(), reader_chain()),
            std::slice::from_ref(&r),
            VCT,
            NOW,
        )
        .unwrap();
        assert_eq!(approved.format(), format);
        assert!(approved.fields.is_empty());
        assert!(approved.retained_fields.is_empty());
        if format == "dc+sd-jwt" {
            let disclosure =
                B64.encode(serde_json::to_vec(&json!(["salt", "name", "Private Name"])).unwrap());
            let (selected, values) = presentation::select_disclosures(
                &format!("issuer.jwt.signature~{disclosure}~"),
                &approved,
            )
            .unwrap();
            assert_eq!(selected, "issuer.jwt.signature~");
            assert_eq!(values, json!({}));
            let holder = SigningKey::from_slice(&[2; 32]).unwrap();
            let vp = presentation::present(&holder, &selected, &approved, NOW).unwrap();
            assert_eq!(vp.split('~').count(), 2);
            let kb = vp.rsplit('~').next().unwrap();
            let (input, sig) = kb.rsplit_once('.').unwrap();
            holder
                .verifying_key()
                .verify(
                    input.as_bytes(),
                    &Signature::from_slice(&B64.decode(sig).unwrap()).unwrap(),
                )
                .unwrap();
            let payload: Value =
                serde_json::from_slice(&B64.decode(input.split('.').nth(1).unwrap()).unwrap())
                    .unwrap();
            assert_eq!(
                payload["sd_hash"],
                B64.encode(Sha256::digest(selected.as_bytes()))
            );
            assert_eq!(payload["nonce"], approved.nonce());
            assert_eq!(payload["aud"], approved.client_id());
        }
        for invalid in [json!([]), json!(null), json!({}), json!("all")] {
            let mut bad = c.clone();
            bad["dcql_query"]["credentials"][0]["claims"] = invalid;
            assert!(
                presentation::verify_request(
                    &x509_signed(bad, reader_chain()),
                    std::slice::from_ref(&r),
                    VCT,
                    NOW
                )
                .is_err()
            );
        }
        c["dcql_query"]["credentials"][0]["claim_sets"] = json!([["name"]]);
        assert!(
            presentation::verify_request(&x509_signed(c, reader_chain()), &[r], VCT, NOW).is_err()
        );
    }
}

#[test]
fn multiple_queries_use_only_selected_attribute_union_and_complete_encrypted_map() {
    for format in ["dc+sd-jwt", "mso_mdoc"] {
        let mut c = set_claims(format, false);
        let mut second = c["dcql_query"]["credentials"][0].clone();
        second["id"] = json!("birth");
        second["claims"] = if format == "dc+sd-jwt" {
            json!([{"path":["birthdate"]}])
        } else {
            json!([{"path":[mikaki_identity::mdoc::NAMESPACE,"birthdate"],"intent_to_retain":true}])
        };
        let mut optional = second.clone();
        optional["id"] = json!("optional_address");
        optional["claims"] = if format == "dc+sd-jwt" {
            json!([{"path":["address"]}])
        } else {
            json!([{"path":[mikaki_identity::mdoc::NAMESPACE,"address"],"intent_to_retain":true}])
        };
        let base = c["dcql_query"]["credentials"][0].clone();
        c["dcql_query"]["credentials"] = json!([base, second, optional]);
        c["dcql_query"]["credential_sets"] = json!([{"options":[["identity","birth"]]},{"options":[["birth"]]},{"options":[["optional_address"]],"required":false}]);
        let request = presentation::verify_request(
            &x509_signed(c.clone(), reader_chain()),
            &[x509_registry()],
            VCT,
            NOW,
        )
        .unwrap();
        assert_eq!(
            request.query_ids().collect::<Vec<_>>(),
            vec!["identity", "birth"]
        );
        assert_eq!(request.fields, vec!["name", "birthdate"]);
        assert!(!request.retained_fields.contains(&"address".into()));
        let response = presentation::encryption::encrypt_response(
            "vp",
            &request,
            NOW,
            p256::SecretKey::from_slice(&[8; 32]).unwrap(),
            [8; 12],
        )
        .unwrap();
        let (_, payload) = decrypt_error(&response);
        assert_eq!(
            payload["vp_token"],
            json!({"identity":["vp"],"birth":["vp"]})
        );
        let mut no_sets = c.clone();
        no_sets["dcql_query"]
            .as_object_mut()
            .unwrap()
            .remove("credential_sets");
        let all = presentation::verify_request(
            &x509_signed(no_sets, reader_chain()),
            &[x509_registry()],
            VCT,
            NOW,
        )
        .unwrap();
        assert!(all.fields.contains(&"address".into()));
        assert_eq!(all.query_ids().count(), 3);
        // No aggregate response may silently omit a query to fit the encryption bound.
        assert!(
            presentation::encryption::encrypt_response(
                &"x".repeat(40000),
                &request,
                NOW,
                p256::SecretKey::from_slice(&[8; 32]).unwrap(),
                [8; 12]
            )
            .is_err()
        );
    }
    let mut c = set_claims("dc+sd-jwt", true);
    let mut m = set_claims("mso_mdoc", false)["dcql_query"]["credentials"][0].clone();
    m["id"] = json!("mdoc");
    c["dcql_query"]["credentials"] = json!([c["dcql_query"]["credentials"][0], m]);
    c["dcql_query"]
        .as_object_mut()
        .unwrap()
        .remove("credential_sets");
    assert_eq!(
        presentation::verify_request(
            &x509_signed(c, reader_chain()),
            &[x509_registry()],
            VCT,
            NOW
        )
        .err(),
        Some("mixed_presentation_formats_unsupported")
    );
}

#[test]
fn inventory_retrieval_preserves_authentication_nonce_and_one_use_guards() {
    use presentation::retrieval::{Method, RequestRetrieval};
    for case in 0..5 {
        let r = x509_registry();
        let mut ctx = RequestRetrieval::new(&r, Method::Post, NOW, [9; 32]).unwrap();
        let mut c = set_claims("dc+sd-jwt", false);
        c["wallet_nonce"] = json!(ctx.form().unwrap()[1].1);
        match case {
            1 => c["wallet_nonce"] = json!("substitution"),
            2 => c["client_id"] = json!("x509_hash:substituted"),
            3 => c["response_uri"] = json!("https://other.example/response"),
            _ => {}
        }
        let mut jwt = x509_signed(c, reader_chain());
        if case == 4 {
            let n = jwt.rfind('.').unwrap() + 1;
            jwt.replace_range(n..n + 1, if &jwt[n..n + 1] == "A" { "B" } else { "A" });
        }
        let result = ctx.verify_inventory(&jwt, std::slice::from_ref(&r), VCT, NOW);
        assert_eq!(result.is_ok(), case == 0);
        assert!(ctx.verify_inventory(&jwt, &[r], VCT, NOW).is_err());
    }
}

#[test]
fn inventory_evaluation_keeps_bound_protocol_errors_and_one_use_authentication() {
    use presentation::retrieval::{InventoryOutcome, Method, RequestRetrieval};
    for case in 0..7 {
        let r = x509_registry();
        let mut ctx = RequestRetrieval::new(&r, Method::Post, NOW, [9; 32]).unwrap();
        let mut c = x509_claims();
        c["wallet_nonce"] = json!(ctx.form().unwrap()[1].1);
        match case {
            0 => {
                let mut second = c["dcql_query"]["credentials"][0].clone();
                second["id"] = json!("mdoc");
                second["format"] = json!("mso_mdoc");
                second["meta"] = json!({"doctype_value":mikaki_identity::mdoc::DOCTYPE});
                second["claims"] = json!([{"path":[mikaki_identity::mdoc::NAMESPACE,"birthdate"]}]);
                c["dcql_query"]["credentials"]
                    .as_array_mut()
                    .unwrap()
                    .push(second);
                c["client_metadata"]["vp_formats_supported"]["mso_mdoc"] =
                    json!({"issuerauth_alg_values":[-7],"deviceauth_alg_values":[-7]});
            }
            1 => {
                c.as_object_mut().unwrap().remove("nonce");
            }
            2 => c["dcql_query"]["credentials"][0]["meta"] = json!({"vct_values":["urn:missing"]}),
            3 => {
                c["transaction_data"] = json!([B64.encode(
                    serde_json::to_vec(&json!({"type":"unknown","credential_ids":["identity"]}))
                        .unwrap()
                )])
            }
            4 => c["client_id"] = json!("x509_hash:substituted"),
            5 => c["wallet_nonce"] = json!("substituted"),
            _ => {}
        }
        let mut jwt = x509_signed(c, reader_chain());
        if case == 6 {
            let n = jwt.rfind('.').unwrap() + 1;
            jwt.replace_range(n..n + 1, if &jwt[n..n + 1] == "A" { "B" } else { "A" });
        }
        let result = ctx.evaluate_inventory(&jwt, std::slice::from_ref(&r), VCT, NOW);
        match (case, result) {
            (0, Ok(InventoryOutcome::Approved(_))) => {}
            (1, Ok(InventoryOutcome::Error(error))) => assert_eq!(error.code(), "invalid_request"),
            (2, Ok(InventoryOutcome::Error(error))) => assert_eq!(error.code(), "access_denied"),
            (3, Ok(InventoryOutcome::Error(error))) => {
                assert_eq!(error.code(), "invalid_transaction_data")
            }
            (4..=6, Err(_)) => {}
            _ => panic!("unexpected inventory evaluation for case {case}"),
        }
        assert!(ctx.evaluate_inventory(&jwt, &[r], VCT, NOW).is_err());
    }
}
#[test]
fn authenticated_inventory_can_compile_the_original_single_receipt_union_without_retrieval_reuse() {
    let mut c = x509_claims();
    let mut second = c["dcql_query"]["credentials"][0].clone();
    second["id"] = json!("birth");
    second["claims"] = json!([{"path":["birthdate"]}]);
    c["dcql_query"]["credentials"]
        .as_array_mut()
        .unwrap()
        .push(second);
    let jwt = x509_signed(c, reader_chain());
    let request = presentation::inventory::verify_request(&jwt, &[x509_registry()], VCT, NOW)
        .unwrap()
        .into_single()
        .unwrap();
    assert_eq!(request.fields, ["name", "birthdate"]);
    assert_eq!(
        request.query_ids().collect::<Vec<_>>(),
        ["identity", "birth"]
    );
    assert_eq!(
        request.request_hash,
        B64.encode(Sha256::digest(jwt.as_bytes()))
    );
    assert!(request.response_encryption().is_some());
}
