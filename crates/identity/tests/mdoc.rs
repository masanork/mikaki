use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use mikaki_identity::{
    card::{CardPreview, DocumentType},
    evidence::VerifiedDocument,
    issuance::{self, PublicJwk},
    mdoc,
    presentation::{self, VerifierRegistration},
};
use p256::ecdsa::{SigningKey, signature::Signer};
use serde_json::json;
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn document() -> VerifiedDocument {
    VerifiedDocument {
        attributes: CardPreview {
            name: "Fixture".into(),
            address: "Private".into(),
            birth_date: "1990-02-28".into(),
            gender: "1".into(),
            verification: "issuer_signed_static_data".into(),
            document_type: DocumentType::MyNumberCard,
            expiry_date: None,
            backend_verifiable: true,
        },
        trusted_key_id: "fixture".into(),
        verified_at: now(),
        assurance: "issuer_signed_static_data".into(),
        attributes_source: "input_support_ef".into(),
    }
}
#[test]
fn receipt_pins_certificate_holder_digests_and_expiry_and_auth_binds_transcript() {
    let issuer = SigningKey::from_slice(&[4; 32]).unwrap();
    let holder = SigningKey::from_slice(&[2; 32]).unwrap();
    let other = SigningKey::from_slice(&[3; 32]).unwrap();
    let public = PublicJwk::from_key(issuer.verifying_key());
    let device = PublicJwk::from_key(holder.verifying_key());
    let time = now();
    let cert = include_bytes!("fixtures/mdoc-ds.der");
    let cred = mdoc::issue(
        &issuer,
        cert,
        &device,
        &document(),
        time,
        &[[1; 16], [2; 16], [3; 16], [4; 16]],
    )
    .unwrap();
    let valid = mdoc::verify_receipt(&cred, &public, &device, time).unwrap();
    assert!(mdoc::verify_receipt(&cred, &public, &device, time + 299).is_ok());
    assert!(mdoc::verify_receipt(&cred, &public, &device, time + 300).is_err());
    assert!(
        mdoc::verify_receipt(
            &cred,
            &public,
            &PublicJwk::from_key(other.verifying_key()),
            time
        )
        .is_err()
    );
    assert!(
        mdoc::verify_receipt(
            &cred,
            &PublicJwk::from_key(other.verifying_key()),
            &device,
            time
        )
        .is_err()
    );
    let mut corrupted = B64.decode(&cred).unwrap();
    let end = corrupted.len() - 1;
    corrupted[end] ^= 1;
    assert!(mdoc::verify_receipt(&B64.encode(corrupted), &public, &device, time).is_err());
    let transcript =
        mdoc::oid4vp_transcript("verifier", "nonce", "https://verifier.example/response").unwrap();
    let payload = mdoc::device_authentication(&transcript).unwrap();
    let sig: p256::ecdsa::Signature = holder.sign(&mdoc::signature_input(&payload).unwrap());
    let fields = vec!["name".into(), "birthdate".into()];
    assert_eq!(
        mdoc::selected_values(&valid, &fields).unwrap(),
        json!({"name":"Fixture","birthdate":"1990-02-28"})
    );
    assert!(mdoc::selected_values(&valid, &["document_expiry_date".into()]).is_err());
    assert!(mdoc::device_response(&valid, &fields, &transcript, &sig.to_bytes(), &device).is_ok());
    assert_eq!(mdoc::selected_values(&valid, &[]).unwrap(), json!({}));
    let empty = mdoc::device_response(&valid, &[], &transcript, &sig.to_bytes(), &device).unwrap();
    let decoded = mdoc::decode(&B64.decode(empty).unwrap()).unwrap();
    let doc = cbor_field(&decoded, "documents")
        .unwrap()
        .as_array()
        .unwrap()[0]
        .clone();
    let issuer_signed = cbor_field(&doc, "issuerSigned").unwrap();
    assert!(cbor_field(issuer_signed, "nameSpaces").is_none());
    assert!(cbor_field(issuer_signed, "issuerAuth").is_some());
    assert!(cbor_field(&doc, "deviceSigned").is_some());
    for t in [
        mdoc::oid4vp_transcript("other", "nonce", "https://verifier.example/response"),
        mdoc::oid4vp_transcript("verifier", "other", "https://verifier.example/response"),
        mdoc::oid4vp_transcript("verifier", "nonce", "https://other.example/response"),
    ] {
        assert!(
            mdoc::device_response(&valid, &fields, &t.unwrap(), &sig.to_bytes(), &device).is_err()
        );
    }
    assert!(
        mdoc::device_response(
            &valid,
            &fields,
            &transcript,
            &sig.to_bytes(),
            &PublicJwk::from_key(other.verifying_key())
        )
        .is_err()
    );
}
#[test]
fn bounded_cbor_rejects_duplicates_indefinite_trailing_excessive_depth_and_huge_collections() {
    for b in [
        vec![0xa2, 0x61, b'x', 0, 0x61, b'x', 1],
        vec![0x9f, 0xff],
        vec![0, 0],
        vec![0x9a, 0xff, 0xff, 0xff, 0xff],
        vec![0x81; 20],
        vec![0x18, 0],
    ] {
        assert!(mdoc::decode(&b).is_err());
    }
    let qr = mdoc::qr_transcript(&[0xa0], &[0xa0]).unwrap();
    let online = mdoc::oid4vp_transcript("v", "n", "https://v.example").unwrap();
    assert_ne!(qr, online);
    let nfc = mdoc::nfc_transcript(&[0xa0], &[0xa0], &[1, 2, 3], None).unwrap();
    assert_ne!(nfc, qr);
    assert_ne!(nfc, online);
    assert!(mdoc::nfc_transcript(&[0xa0], &[0xa0], &[], None).is_err());
    assert!(mdoc::qr_transcript(&[0xa0, 0], &[0xa0]).is_err());
}
#[test]
fn dcql_mdoc_paths_and_retention_are_bound_to_signed_request() {
    let key = SigningKey::from_slice(&[5; 32]).unwrap();
    let registry = VerifierRegistration {
        client_id: "verifier".into(),
        name: "Fixture".into(),
        response_uri: "https://verifier.example/response".into(),
        kid: "key".into(),
        jwk: PublicJwk::from_key(key.verifying_key()),
        certificate_trust: None,
        response_encryption: None,
        profile: mikaki_identity::presentation::Profile::Oid4vpFinal,
    };
    let time = now();
    let mut claims = json!({"iss":"verifier","client_id":"verifier","aud":"https://self-issued.me/v2","nonce":"N".repeat(43),"state":"S".repeat(43),"iat":time,"exp":time+120,"response_type":"vp_token","response_mode":"direct_post","response_uri":registry.response_uri,"dcql_query":{"credentials":[{"id":"identity","format":"mso_mdoc","meta":{"doctype_value":mdoc::DOCTYPE},"claims":[{"path":[mdoc::NAMESPACE,"name"],"intent_to_retain":true}]}]}});
    let signed = |c| {
        issuance::sign_jwt(
            &key,
            json!({"typ":"oauth-authz-req+jwt","alg":"ES256","kid":"key"}),
            c,
        )
        .unwrap()
    };
    let checked = presentation::verify_request(
        &signed(claims.clone()),
        std::slice::from_ref(&registry),
        "vct",
        time,
    )
    .unwrap();
    assert_eq!(checked.format(), "mso_mdoc");
    assert_eq!(checked.retained_fields, vec!["name"]);
    claims["dcql_query"]["credentials"][0]["claims"][0]["path"] =
        json!(["wrong.namespace", "name"]);
    assert!(presentation::verify_request(&signed(claims), &[registry], "vct", time).is_err());
}

fn cbor_field<'a>(value: &'a ciborium::Value, name: &str) -> Option<&'a ciborium::Value> {
    value
        .as_map()?
        .iter()
        .find_map(|(k, v)| (k.as_text() == Some(name)).then_some(v))
}
