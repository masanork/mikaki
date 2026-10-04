//! Disposable, synthetic interoperability vector. Contains no real card or production keys.
use mikaki_identity::{
    card::{CardPreview, DocumentType},
    evidence::VerifiedDocument,
    issuance::{self, PublicJwk},
    presentation::{self, VerifierRegistration},
};
use p256::ecdsa::SigningKey;
use serde_json::json;
fn main() {
    let fixture_profile = std::env::args().nth(2).unwrap_or_default();
    let mut now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let issuer = "https://issuer.example/identity/issuer";
    if fixture_profile.starts_with("crl") {
        now = 1790899200;
    }
    let holder = SigningKey::from_slice(&[2; 32]).unwrap();
    let issuer_key = SigningKey::from_slice(&[4; 32]).unwrap();
    let verifier = SigningKey::from_slice(&[5; 32]).unwrap();
    let registry = VerifierRegistration {
        client_id: "fixture-verifier".into(),
        name: "Fixture only".into(),
        response_uri: "https://verifier.example/response".into(),
        kid: "fixture-verifier-key".into(),
        jwk: PublicJwk::from_key(verifier.verifying_key()),
        certificate_trust: None,
        response_encryption: None,
        profile: mikaki_identity::presentation::Profile::Oid4vpFinal,
    };
    let request_claims = json!({"iss":registry.client_id,"aud":"https://self-issued.me/v2","client_id":registry.client_id,"response_type":"vp_token","response_mode":"direct_post","response_uri":registry.response_uri,"nonce":"N".repeat(43),"state":"S".repeat(43),"iat":now,"exp":now+120,"dcql_query":{"credentials":[{"id":"identity","format":"dc+sd-jwt","meta":{"vct_values":[format!("{issuer}/types/linked-document")]},"claims":[{"path":["name"]},{"path":["birthdate"]}]}]}});
    let request = issuance::sign_jwt(
        &verifier,
        json!({"typ":"oauth-authz-req+jwt","alg":"ES256","kid":registry.kid}),
        request_claims.clone(),
    )
    .unwrap();
    let document = VerifiedDocument {
        attributes: CardPreview {
            name: "Fixture Person".into(),
            address: "Private fixture address".into(),
            birth_date: "1990-02-28".into(),
            gender: "1".into(),
            verification: "issuer_signed_static_data".into(),
            document_type: DocumentType::MyNumberCard,
            expiry_date: None,
            backend_verifiable: true,
        },
        trusted_key_id: "fixture-card-issuer".into(),
        verified_at: now,
        assurance: "issuer_signed_static_data".into(),
        attributes_source: "input_support_ef".into(),
    };
    let holder_jwk = PublicJwk::from_key(holder.verifying_key());
    let credential = issuance::issue(
        &issuer_key,
        "fixture-issuer",
        issuer,
        &holder_jwk,
        &document,
        now,
        &[[1; 16], [2; 16], [3; 16], [4; 16]],
    )
    .unwrap();
    let approved = presentation::verify_request(
        &request,
        std::slice::from_ref(&registry),
        &format!("{issuer}/types/linked-document"),
        now,
    )
    .unwrap();
    let (selected, values) = presentation::select_disclosures(&credential, &approved).unwrap();
    let vp = presentation::present(&holder, &selected, &approved, now).unwrap();
    let certificate = include_bytes!("../tests/fixtures/mdoc-ds.der");
    let mdoc_credential = mikaki_identity::mdoc::issue(
        &issuer_key,
        certificate,
        &holder_jwk,
        &document,
        now,
        &[[1; 16], [2; 16], [3; 16], [4; 16]],
    )
    .unwrap();
    let validated = mikaki_identity::mdoc::verify_receipt(
        &mdoc_credential,
        &PublicJwk::from_key(issuer_key.verifying_key()),
        &holder_jwk,
        now,
    )
    .unwrap();
    let transcript = mikaki_identity::mdoc::oid4vp_transcript(
        &registry.client_id,
        &"N".repeat(43),
        &registry.response_uri,
    )
    .unwrap();
    let auth = mikaki_identity::mdoc::device_authentication(&transcript).unwrap();
    use p256::ecdsa::signature::Signer;
    let device_sig: p256::ecdsa::Signature =
        holder.sign(&mikaki_identity::mdoc::signature_input(&auth).unwrap());
    let mdoc_response = mikaki_identity::mdoc::device_response(
        &validated,
        &["name".into(), "birthdate".into()],
        &transcript,
        &device_sig.to_bytes(),
        &holder_jwk,
    )
    .unwrap();
    use base64::Engine;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let ephemeral = p256::SecretKey::from_slice(&[7; 32]).unwrap();
    let mut session = if std::env::args().nth(2).as_deref() == Some("nfc_negotiated_data") {
        mikaki_identity::mdoc::proximity::HolderSession::new_nfc_negotiated_data(ephemeral).unwrap()
    } else if std::env::args().nth(2).as_deref() == Some("nfc_negotiated") {
        mikaki_identity::mdoc::proximity::HolderSession::new_nfc_negotiated(
            ephemeral,
            core::array::from_fn(|i| i as u8),
        )
        .unwrap()
    } else if std::env::args().nth(2).as_deref() == Some("qr_nfc") {
        mikaki_identity::mdoc::proximity::HolderSession::new_nfc_data(ephemeral).unwrap()
    } else if std::env::args().nth(2).as_deref() == Some("nfc") {
        mikaki_identity::mdoc::proximity::HolderSession::new_nfc(
            ephemeral,
            core::array::from_fn(|i| i as u8),
        )
        .unwrap()
    } else {
        mikaki_identity::mdoc::proximity::HolderSession::new(ephemeral, [8; 16]).unwrap()
    };
    let mut output = json!({"engagement":b64.encode(session.engagement()),"handover_select":session.handover_select().map(|h|b64.encode(h)),"reader_jwk":PublicJwk::from_key(issuer_key.verifying_key()),"holder_jwk":holder_jwk,"issuer_jwk":PublicJwk::from_key(issuer_key.verifying_key()),"now":now});
    if let Some(hr) = std::env::args().nth(3) {
        let hr = b64.decode(hr).unwrap();
        match session.negotiate(&hr) {
            Ok(_) => output["handover_request"] = json!(b64.encode(hr)),
            Err(error) => {
                output["error"] = json!(error);
                output["consumed"] =
                    json!(session.establish(&[0xa0], &[], now).err() == Some("session_consumed"));
                println!("{output}");
                return;
            }
        }
    }
    if let Some(packet) = std::env::args().nth(1).filter(|s| s != "-") {
        let packet = b64.decode(packet).unwrap();
        let reader_key = if std::env::args().nth(2).as_deref() == Some("untrusted") {
            SigningKey::from_slice(&[5; 32]).unwrap()
        } else {
            issuer_key.clone()
        };
        let certificate_trust =
            if fixture_profile == "certificate" || fixture_profile.starts_with("crl") {
                Some(mikaki_identity::certificate::ReaderTrust {
                    trust_anchors: vec![base64::engine::general_purpose::STANDARD.encode(
                        include_bytes!(concat!(
                            env!("CARGO_MANIFEST_DIR"),
                            "/tests/fixtures/trust/root.der"
                        )),
                    )],
                    dns_name: None,
                    revocation: if fixture_profile.starts_with("crl") {
                        let fixture = |name: &str| {
                            base64::engine::general_purpose::STANDARD.encode(
                                std::fs::read(format!(
                                    "{}/tests/fixtures/trust/{name}.crl",
                                    env!("CARGO_MANIFEST_DIR")
                                ))
                                .unwrap(),
                            )
                        };
                        let leaf_crl = match fixture_profile.as_str() {
                            "crl-revoked" => "revoked-reader",
                            "crl-stale" => "stale",
                            _ => "clean-intermediate",
                        };
                        let mut crls = vec![fixture(leaf_crl)];
                        if fixture_profile != "crl-missing" {
                            crls.push(fixture("clean-root"));
                        }
                        Some(mikaki_identity::certificate::CrlPolicy {
                            crls,
                            max_age_seconds: 604800,
                        })
                    } else {
                        None
                    },
                })
            } else {
                None
            };
        let readers = [mikaki_identity::mdoc::proximity::ReaderRegistration {
            name: "Fixture reader".into(),
            jwk: PublicJwk::from_key(reader_key.verifying_key()),
            certificate_trust,
        }];
        match session.establish(&packet, &readers, now) {
            Err(error) => {
                output["error"] = json!(error);
                output["consumed"] = json!(session.establish(&packet, &readers, now).is_err());
            }
            Ok(request) => {
                let fields = request.fields.clone();
                let retained = request.retained_fields.clone();
                let transcript = session.transcript().unwrap().to_vec();
                let authentication =
                    mikaki_identity::mdoc::device_authentication(&transcript).unwrap();
                let sig: p256::ecdsa::Signature =
                    holder.sign(&mikaki_identity::mdoc::signature_input(&authentication).unwrap());
                let response = mikaki_identity::mdoc::device_response(
                    &validated,
                    &fields,
                    &transcript,
                    &sig.to_bytes(),
                    &holder_jwk,
                )
                .unwrap();
                let encrypted = session
                    .seal_response(&b64.decode(response).unwrap())
                    .unwrap();
                output["packet"] = json!(b64.encode(encrypted));
                output["fields"] = json!(fields);
                output["retained_fields"] = json!(retained);
                output["consumed"] = json!(
                    session.seal_response(b"replay").is_err()
                        && session.establish(&packet, &readers, now).is_err()
                );
            }
        }
    }
    // Keep only the proximity vector in this example's output.
    let _ = (mdoc_response, credential, values, vp);
    println!("{output}");
}
