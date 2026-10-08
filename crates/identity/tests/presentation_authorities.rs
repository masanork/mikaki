#[path = "support/certificate.rs"]
mod mutable_certificate;
use mutable_certificate::Certificate;

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD as B64},
};
use der::Decode;
use mikaki_identity::{
    credential_certificate::SigningTrust,
    credential_receipt::CredentialTrust,
    evidence::VerifiedDocument,
    issuance::{self, PublicJwk, Validity},
    mdoc,
    presentation::{self, ApprovedRequest, Profile, VerifierRegistration},
};
use p256::ecdsa::SigningKey;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use x509_cert::ext::pkix::{AuthorityKeyIdentifier, SubjectKeyIdentifier};
const NOW: u64 = 1791000000;
const ISSUER: &str = "https://issuer.example/identity/issuer";
fn bytes(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/credential/{name}.der",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}
fn key(n: u8) -> SigningKey {
    SigningKey::from_slice(&[n; 32]).unwrap()
}
fn trust() -> CredentialTrust {
    serde_json::from_value(json!({"sd_jwt":{"trust_anchors":[STANDARD.encode(bytes("sd-ca"))]},"mdoc":{"trust_anchors":[STANDARD.encode(bytes("mdoc-ca"))]}})).unwrap()
}
fn identifier(name: &str, subject: bool) -> String {
    let cert = Certificate::from_der(&bytes(name)).unwrap();
    let ext = cert
        .tbs_certificate
        .extensions
        .as_ref()
        .unwrap()
        .iter()
        .find(|e| e.extn_id.to_string() == if subject { "2.5.29.14" } else { "2.5.29.35" })
        .unwrap();
    let id = if subject {
        SubjectKeyIdentifier::from_der(ext.extn_value.as_bytes())
            .unwrap()
            .0
    } else {
        AuthorityKeyIdentifier::from_der(ext.extn_value.as_bytes())
            .unwrap()
            .key_identifier
            .unwrap()
    };
    B64.encode(id.as_bytes())
}
fn credential(format: &str) -> String {
    credential_for_holder(format, 3)
}
fn credential_for_holder(format: &str, seed: u8) -> String {
    credential_for_holder_deadline(format, seed, NOW + 300)
}
fn credential_for_holder_deadline(format: &str, seed: u8, deadline: u64) -> String {
    let document:VerifiedDocument = serde_json::from_value(json!({"attributes":{"name":"Fixture","address":"Private","birth_date":"1990-02-28","gender":"1","verification":"issuer_signed_static_data","document_type":"my_number_card","expiry_date":null,"backend_verifiable":true},"trusted_key_id":"fixture","verified_at":NOW,"assurance":"issuer_signed_static_data","attributes_source":"input_support_ef"})).unwrap();
    let holder = PublicJwk::from_key(key(seed).verifying_key());
    if format == "dc+sd-jwt" {
        issuance::issue_with_certificate_trust(
            &key(4),
            "issuer",
            ISSUER,
            &holder,
            &document,
            Validity::new(&document, NOW, deadline).unwrap(),
            &[[1; 16], [2; 16], [3; 16], [4; 16]],
            &SigningTrust {
                chain: vec![STANDARD.encode(bytes("sd-signer"))],
                trust_anchors: trust().sd_jwt.trust_anchors,
                revocation: None,
            },
        )
        .unwrap()
    } else {
        mdoc::issue(
            &key(4),
            &bytes("mdoc-signer"),
            &holder,
            &document,
            NOW,
            &[[1; 16], [2; 16], [3; 16], [4; 16]],
        )
        .unwrap()
    }
}
fn request(format: &str, authorities: Option<Value>) -> Result<ApprovedRequest, &'static str> {
    request_with_second(format, authorities, None)
}
fn request_with_second(
    format: &str,
    authorities: Option<Value>,
    second: Option<Value>,
) -> Result<ApprovedRequest, &'static str> {
    let registry = VerifierRegistration {
        client_id: "verifier".into(),
        name: "Verifier".into(),
        response_uri: "https://verifier.example/response".into(),
        kid: "key".into(),
        jwk: PublicJwk::from_key(key(5).verifying_key()),
        certificate_trust: None,
        response_encryption: None,
        profile: Profile::Oid4vpFinal,
    };
    let mut c = json!({"iss":"verifier","aud":"https://self-issued.me/v2","client_id":"verifier","response_type":"vp_token","response_mode":"direct_post","response_uri":registry.response_uri,"nonce":"N".repeat(43),"state":"S".repeat(43),"iat":NOW,"exp":NOW+120,"dcql_query":{"credentials":[{"id":"identity","format":format,"meta":if format=="dc+sd-jwt" {json!({"vct_values":[format!("{ISSUER}/types/linked-document")]})} else {json!({"doctype_value":mdoc::DOCTYPE})},"claims":[{"path":if format=="dc+sd-jwt" {vec!["name"]} else {vec![mdoc::NAMESPACE,"name"]}}]}]}});
    if let Some(authorities) = second {
        let mut query = c["dcql_query"]["credentials"][0].clone();
        query["id"] = json!("second");
        query["trusted_authorities"] = authorities;
        c["dcql_query"]["credentials"]
            .as_array_mut()
            .unwrap()
            .push(query);
    }
    if let Some(a) = authorities {
        c["dcql_query"]["credentials"][0]["trusted_authorities"] = a;
    }
    let jwt = issuance::sign_jwt(
        &key(5),
        json!({"typ":"oauth-authz-req+jwt","alg":"ES256","kid":"key"}),
        c,
    )
    .unwrap();
    presentation::verify_request(
        &jwt,
        &[registry],
        &format!("{ISSUER}/types/linked-document"),
        NOW,
    )
}
#[test]
fn both_formats_match_any_aki_value_after_receipt_and_chain_validation() {
    for (format, prefix) in [("dc+sd-jwt", "sd"), ("mso_mdoc", "mdoc")] {
        let credential = credential(format);
        let holder = PublicJwk::from_key(key(3).verifying_key());
        if format == "dc+sd-jwt" {
            issuance::verify_receipt(
                &credential,
                &PublicJwk::from_key(key(4).verifying_key()),
                "issuer",
                &holder,
                ISSUER,
                NOW,
            )
            .unwrap();
        } else {
            mdoc::verify_receipt(
                &credential,
                &PublicJwk::from_key(key(4).verifying_key()),
                &holder,
                NOW,
            )
            .unwrap();
        }
        let expected = identifier(&format!("{prefix}-signer"), false);
        assert_eq!(expected, identifier(&format!("{prefix}-ca"), true));
        let approved=request(format,Some(json!([{"type":"unsupported","values":["https://no-fetch.example"]},{"type":"aki","values":[B64.encode([0;20]),expected]}]))).unwrap();
        approved
            .check_credential_authorities(
                &credential,
                Some(&trust()),
                &PublicJwk::from_key(key(4).verifying_key()),
                NOW,
                NOW + 300,
            )
            .unwrap();
    }
}
#[test]
fn nonmatching_unknown_or_leaf_ski_conditions_do_not_reveal_credentials() {
    for (format, prefix) in [("dc+sd-jwt", "sd"), ("mso_mdoc", "mdoc")] {
        for a in [
            json!([{"type":"aki","values":[B64.encode([0;20])]}]),
            json!([{"type":"aki","values":[identifier(&format!("{prefix}-signer"),true)]}]),
            json!([{"type":"openid_federation","values":["https://no-fetch.example"]}]),
        ] {
            assert_eq!(
                request(format, Some(a))
                    .unwrap()
                    .check_credential_authorities(
                        &credential(format),
                        Some(&trust()),
                        &PublicJwk::from_key(key(4).verifying_key()),
                        NOW,
                        NOW + 300
                    )
                    .unwrap_err(),
                "credential_does_not_match"
            );
        }
        assert!(
            request(format, None)
                .unwrap()
                .check_credential_authorities(
                    "not-used",
                    None,
                    &PublicJwk::from_key(key(4).verifying_key()),
                    NOW,
                    NOW + 300
                )
                .is_ok()
        );
    }
}
#[test]
fn query_cannot_supply_trust_or_bypass_key_expiry_revocation_checks() {
    for (format, prefix) in [("dc+sd-jwt", "sd"), ("mso_mdoc", "mdoc")] {
        let a = json!([{"type":"aki","values":[identifier(&format!("{prefix}-signer"),false)]}]);
        let r = request(format, Some(a)).unwrap();
        let credential = credential(format);
        let issuer = PublicJwk::from_key(key(4).verifying_key());
        assert_eq!(
            r.check_credential_authorities(&credential, None, &issuer, NOW, NOW + 300)
                .unwrap_err(),
            "credential_authority_unavailable"
        );
        assert!(
            r.check_credential_authorities(
                &credential,
                Some(&trust()),
                &PublicJwk::from_key(key(6).verifying_key()),
                NOW,
                NOW + 300
            )
            .is_err()
        );
        assert!(
            r.check_credential_authorities(&credential, Some(&trust()), &issuer, NOW, u64::MAX)
                .is_err()
        );
        if format == "mso_mdoc" {
            let mut status = trust();
            let crl = |name: &str| {
                STANDARD.encode(
                    std::fs::read(format!(
                        "{}/tests/fixtures/credential/{name}.crl",
                        env!("CARGO_MANIFEST_DIR")
                    ))
                    .unwrap(),
                )
            };
            status.mdoc.revocation = Some(mikaki_identity::certificate::CrlPolicy {
                crls: vec![crl("mdoc-clean")],
                max_age_seconds: 604800,
            });
            r.check_credential_authorities(&credential, Some(&status), &issuer, NOW, NOW + 300)
                .unwrap();
            status.mdoc.revocation.as_mut().unwrap().crls = vec![crl("mdoc-revoked")];
            assert!(
                r.check_credential_authorities(&credential, Some(&status), &issuer, NOW, NOW + 300)
                    .is_err()
            );
            status.mdoc.revocation.as_mut().unwrap().crls.clear();
            assert!(
                r.check_credential_authorities(&credential, Some(&status), &issuer, NOW, NOW + 300)
                    .is_err()
            );
        }
        let mut changed = trust();
        if format == "dc+sd-jwt" {
            changed.sd_jwt.trust_anchors = changed.mdoc.trust_anchors.clone();
        } else {
            changed.mdoc.trust_anchors = changed.sd_jwt.trust_anchors.clone();
        }
        assert!(
            r.check_credential_authorities(&credential, Some(&changed), &issuer, NOW, NOW + 300)
                .is_err()
        );
    }
}
#[test]
fn malformed_empty_noncanonical_or_excessive_authority_queries_are_rejected() {
    for a in [
        Value::Null,
        json!([]),
        json!([{"type":"aki","values":[]}]),
        json!([{"type":"aki","values":[""]}]),
        json!([{"type":"aki","values":["AQ=="]}]),
        json!([{"type":"aki","values":["AB"]}]),
        json!([{"type":"aki","values":[B64.encode([0;65])]}]),
        json!([{"type":"aki","values":vec!["AQ";17]}]),
        json!(vec![json!({"type":"aki","values":["AQ"]}); 9]),
        json!([{"type":"aki","values":["AQ"],"trust_anchors":["foreign"]}]),
    ] {
        assert!(request("dc+sd-jwt", Some(a.clone())).is_err(), "{a}");
    }
}

#[test]
fn sd_jwt_matches_aki_on_a_carried_intermediate_without_matching_a_configured_root_extension() {
    use der::{
        Encode,
        asn1::{BitString, OctetString},
    };
    use p256::{
        ecdsa::{Signature, signature::Signer},
        pkcs8::EncodePublicKey,
    };
    use x509_cert::SubjectPublicKeyInfo;
    let root = Certificate::from_der(&bytes("sd-ca")).unwrap();
    let mut intermediate = root.clone();
    intermediate.tbs_certificate.subject = Certificate::from_der(&bytes("mdoc-ca"))
        .unwrap()
        .tbs_certificate
        .subject;
    intermediate.tbs_certificate.subject_public_key_info = SubjectPublicKeyInfo::from_der(
        key(8)
            .verifying_key()
            .to_public_key_der()
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    let parent_aki = B64.decode(identifier("sd-signer", false)).unwrap();
    let set_identifier = |cert: &mut Certificate, oid: &str, encoded: Vec<u8>| {
        cert.tbs_certificate
            .extensions
            .as_mut()
            .unwrap()
            .iter_mut()
            .find(|e| e.extn_id.to_string() == oid)
            .unwrap()
            .extn_value = OctetString::new(encoded).unwrap();
    };
    set_identifier(
        &mut intermediate,
        "2.5.29.14",
        SubjectKeyIdentifier(OctetString::new([8; 20]).unwrap())
            .to_der()
            .unwrap(),
    );
    // The root fixture omits AKI; add it only to the carried intermediate.
    let aki = AuthorityKeyIdentifier {
        key_identifier: Some(OctetString::new(parent_aki.clone()).unwrap()),
        ..Default::default()
    };
    intermediate
        .tbs_certificate
        .extensions
        .as_mut()
        .unwrap()
        .push(x509_cert::ext::Extension {
            extn_id: der::asn1::ObjectIdentifier::new_unwrap("2.5.29.35"),
            critical: false,
            extn_value: OctetString::new(aki.to_der().unwrap()).unwrap(),
        });
    let sig: Signature = key(9).sign(&intermediate.tbs_certificate.to_der().unwrap());
    intermediate.signature = BitString::from_bytes(sig.to_der().as_bytes()).unwrap();
    let mut leaf = Certificate::from_der(&bytes("sd-signer")).unwrap();
    leaf.tbs_certificate.issuer = intermediate.tbs_certificate.subject.clone();
    set_identifier(
        &mut leaf,
        "2.5.29.35",
        AuthorityKeyIdentifier {
            key_identifier: Some(OctetString::new([8; 20]).unwrap()),
            ..Default::default()
        }
        .to_der()
        .unwrap(),
    );
    let sig: Signature = key(8).sign(&leaf.tbs_certificate.to_der().unwrap());
    leaf.signature = BitString::from_bytes(sig.to_der().as_bytes()).unwrap();
    // The signed credential header carries leaf+intermediate, while its provisioned root is separate.
    let original = credential("dc+sd-jwt");
    let (jwt, tail) = original.split_once('~').unwrap();
    let parts = jwt.split('.').collect::<Vec<_>>();
    let mut header: Value = serde_json::from_slice(&B64.decode(parts[0]).unwrap()).unwrap();
    header["x5c"] = json!([
        STANDARD.encode(leaf.to_der().unwrap()),
        STANDARD.encode(intermediate.to_der().unwrap())
    ]);
    let claims = serde_json::from_slice(&B64.decode(parts[1]).unwrap()).unwrap();
    let credential = format!(
        "{}~{tail}",
        issuance::sign_jwt(&key(4), header, claims).unwrap()
    );
    let approved = request(
        "dc+sd-jwt",
        Some(json!([{"type":"aki","values":[B64.encode(&parent_aki)]}])),
    )
    .unwrap();
    approved
        .check_credential_authorities(
            &credential,
            Some(&trust()),
            &PublicJwk::from_key(key(4).verifying_key()),
            NOW,
            NOW + 300,
        )
        .unwrap();
    let mut altered = trust();
    let mut root = root;
    let fake = AuthorityKeyIdentifier {
        key_identifier: Some(OctetString::new([7; 20]).unwrap()),
        ..Default::default()
    };
    root.tbs_certificate
        .extensions
        .as_mut()
        .unwrap()
        .push(x509_cert::ext::Extension {
            extn_id: der::asn1::ObjectIdentifier::new_unwrap("2.5.29.35"),
            critical: false,
            extn_value: OctetString::new(fake.to_der().unwrap()).unwrap(),
        });
    let sig: Signature = key(9).sign(&root.tbs_certificate.to_der().unwrap());
    root.signature = BitString::from_bytes(sig.to_der().as_bytes()).unwrap();
    altered.sd_jwt.trust_anchors = vec![STANDARD.encode(root.to_der().unwrap())];
    let root_only = request(
        "dc+sd-jwt",
        Some(json!([{"type":"aki","values":[B64.encode([7;20])]}])),
    )
    .unwrap();
    assert_eq!(
        root_only
            .check_credential_authorities(
                &credential,
                Some(&altered),
                &PublicJwk::from_key(key(4).verifying_key()),
                NOW,
                NOW + 300
            )
            .unwrap_err(),
        "credential_does_not_match"
    );
}

#[test]
fn batch_authorities_are_and_across_queries_including_when_first_has_no_constraint() {
    for (format, prefix) in [("dc+sd-jwt", "sd"), ("mso_mdoc", "mdoc")] {
        let credential = credential(format);
        let key = PublicJwk::from_key(key(4).verifying_key());
        let good = json!([{"type":"aki","values":[identifier(&format!("{prefix}-ca"),true)]}]);
        let bad = json!([{"type":"aki","values":[B64.encode([0;20])]}]);
        for first in [None, Some(good.clone())] {
            let approved = request_with_second(format, first.clone(), Some(good.clone())).unwrap();
            assert_eq!(approved.query_ids().count(), 2);
            approved
                .check_credential_authorities(&credential, Some(&trust()), &key, NOW, NOW + 300)
                .unwrap();
            let invalid = request_with_second(format, first, Some(bad.clone())).unwrap();
            assert_eq!(
                invalid
                    .check_credential_authorities(&credential, Some(&trust()), &key, NOW, NOW + 300)
                    .err()
                    .as_deref(),
                Some("credential_does_not_match")
            );
        }
    }
}

fn decrypt_inventory(compact: &str) -> (Value, Value) {
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
fn inventory_query(id: &str, format: &str, name: &str) -> Value {
    json!({"id":id,"format":format,"meta":if format=="dc+sd-jwt" {json!({"vct_values":[format!("{ISSUER}/types/linked-document")]})} else {json!({"doctype_value":mdoc::DOCTYPE})},"claims":[{"path":if format=="dc+sd-jwt" {vec![name]} else {vec![mdoc::NAMESPACE,name]},"intent_to_retain":if format=="mso_mdoc" {json!(true)} else {json!(null)}}]})
}
fn inventory_request(
    mut queries: Vec<Value>,
    sets: Option<Value>,
) -> presentation::inventory::InventoryRequest {
    for q in &mut queries {
        if q["format"] == "dc+sd-jwt" {
            q["claims"][0]
                .as_object_mut()
                .unwrap()
                .remove("intent_to_retain");
        }
    }
    let registry = VerifierRegistration {
        client_id: "verifier".into(),
        name: "Verifier".into(),
        response_uri: "https://verifier.example/response".into(),
        kid: "key".into(),
        jwk: PublicJwk::from_key(key(5).verifying_key()),
        certificate_trust: None,
        profile: Profile::Oid4vpFinal,
        response_encryption: Some(presentation::encryption::ResponseEncryption {
            kid: "recipient".into(),
            alg: "ECDH-ES".into(),
            enc: "A256GCM".into(),
            jwk: PublicJwk::from_key(key(6).verifying_key()),
        }),
    };
    let mut payload = json!({"iss":"verifier","aud":"https://self-issued.me/v2","client_id":"verifier","response_type":"vp_token","response_mode":"direct_post.jwt","response_uri":registry.response_uri,"nonce":"N".repeat(43),"state":"S".repeat(43),"iat":NOW,"exp":NOW+120,"dcql_query":{"credentials":queries}});
    if let Some(sets) = sets {
        payload["dcql_query"]["credential_sets"] = sets;
    }
    let jwt = issuance::sign_jwt(
        &key(5),
        json!({"typ":"oauth-authz-req+jwt","alg":"ES256","kid":"key"}),
        payload,
    )
    .unwrap();
    presentation::inventory::verify_request(
        &jwt,
        &[registry],
        &format!("{ISSUER}/types/linked-document"),
        NOW,
    )
    .unwrap()
}
fn inventory_receipt(format: &str) -> presentation::inventory::VerifiedCredential {
    let seed = if format == "mso_mdoc" { 8 } else { 3 };
    presentation::inventory::VerifiedCredential::verify(
        credential_for_holder(format, seed),
        format,
        PublicJwk::from_key(key(4).verifying_key()),
        PublicJwk::from_key(key(seed).verifying_key()),
        ISSUER,
        "issuer",
        trust(),
        NOW,
    )
    .unwrap()
}
#[test]
fn mixed_inventory_selects_each_bound_holder_and_encrypts_a_complete_response() {
    use p256::ecdsa::{Signature, signature::Signer};
    let receipts = [
        inventory_receipt("dc+sd-jwt"),
        inventory_receipt("mso_mdoc"),
    ];
    let request = inventory_request(
        vec![
            inventory_query("identity", "dc+sd-jwt", "name"),
            inventory_query("birth", "mso_mdoc", "birthdate"),
            inventory_query("optional", "mso_mdoc", "address"),
        ],
        Some(
            json!([{"options":[["identity","birth"]]},{"options":[["optional"]],"required":false}]),
        ),
    );
    let prepared = request.select(&receipts, NOW).unwrap();
    assert_eq!(prepared.selected().len(), 2);
    assert_eq!(prepared.selected()[0].inventory_index(), 0);
    assert_eq!(prepared.selected()[1].inventory_index(), 1);
    assert_eq!(
        prepared.selected()[0].values(NOW).unwrap(),
        json!({"name":"Fixture"})
    );
    assert_eq!(
        prepared.selected()[1].values(NOW).unwrap(),
        json!({"birthdate":"1990-02-28"})
    );
    assert_eq!(
        prepared.selected()[1].request().retained_fields,
        ["birthdate"]
    );
    let proofs: Vec<_> = prepared
        .selected()
        .iter()
        .map(|s| {
            if s.request().format() == "dc+sd-jwt" {
                let (selected, _) =
                    presentation::select_disclosures(s.credential().credential(), s.request())
                        .unwrap();
                presentation::present(&key(3), &selected, s.request(), NOW).unwrap()
            } else {
                let validated = mdoc::verify_receipt(
                    s.credential().credential(),
                    &PublicJwk::from_key(key(4).verifying_key()),
                    &PublicJwk::from_key(key(8).verifying_key()),
                    NOW,
                )
                .unwrap();
                let transcript = s.request().mdoc_transcript().unwrap();
                let signature: Signature = key(8).sign(
                    &mdoc::signature_input(&mdoc::device_authentication(&transcript).unwrap())
                        .unwrap(),
                );
                mdoc::device_response(
                    &validated,
                    &s.request().fields,
                    &transcript,
                    &signature.to_bytes(),
                    &PublicJwk::from_key(key(8).verifying_key()),
                )
                .unwrap()
            }
        })
        .collect();
    let encrypted = prepared
        .encrypt_response(
            &proofs,
            NOW,
            p256::SecretKey::from_slice(&[7; 32]).unwrap(),
            [8; 12],
        )
        .unwrap();
    let (header, payload) = decrypt_inventory(&encrypted);
    assert!(header.get("apu").is_none());
    assert_eq!(
        payload,
        json!({"vp_token":{"identity":[proofs[0]],"birth":[proofs[1]]},"state":"S".repeat(43)})
    );
    assert!(
        prepared
            .encrypt_response(
                &proofs[..1],
                NOW,
                p256::SecretKey::from_slice(&[7; 32]).unwrap(),
                [8; 12]
            )
            .is_err()
    );
    assert!(
        prepared
            .encrypt_response(
                &proofs,
                NOW + 120,
                p256::SecretKey::from_slice(&[7; 32]).unwrap(),
                [8; 12]
            )
            .is_err()
    );
    assert!(
        prepared
            .encrypt_response(
                &["x".repeat(40000), "y".repeat(40000)],
                NOW,
                p256::SecretKey::from_slice(&[7; 32]).unwrap(),
                [8; 12]
            )
            .is_err()
    );
    assert!(request.select(&receipts[..1], NOW).is_err());
}
#[test]
fn inventory_uses_receipt_matching_for_options_without_partial_or_optional_disclosure() {
    let receipts = [
        inventory_receipt("dc+sd-jwt"),
        inventory_receipt("mso_mdoc"),
    ];
    let mut bad = inventory_query("wrong", "dc+sd-jwt", "name");
    bad["trusted_authorities"] = json!([{"type":"aki","values":[B64.encode([0;20])]}]);
    let absent = inventory_query("absent", "dc+sd-jwt", "document_expiry_date");
    let valid = inventory_query("valid", "mso_mdoc", "name");
    let optional = inventory_query("optional", "dc+sd-jwt", "address");
    let mut unavailable = inventory_query("unavailable", "dc+sd-jwt", "unknown");
    unavailable["meta"] = json!({"vct_values":["urn:unavailable"]});
    let request = inventory_request(
        vec![
            bad.clone(),
            absent.clone(),
            valid.clone(),
            optional,
            unavailable,
        ],
        Some(
            json!([{"options":[["wrong"],["absent"],["valid"]]},{"options":[["optional"]],"required":false}]),
        ),
    );
    let prepared = request.select(&receipts, NOW).unwrap();
    assert_eq!(prepared.selected().len(), 1);
    assert_eq!(prepared.selected()[0].request().query_id(), "valid");
    assert_eq!(
        prepared.selected()[0].values(NOW).unwrap(),
        json!({"name":"Fixture"})
    );
    let impossible = inventory_request(vec![valid, bad, absent], None);
    assert!(impossible.select(&receipts, NOW).is_err());
    assert!(request.select(&[], NOW).is_err());
    assert!(request.select(&receipts, NOW + 301).is_err());
    assert!(
        presentation::inventory::VerifiedCredential::verify(
            credential("dc+sd-jwt"),
            "dc+sd-jwt",
            PublicJwk::from_key(key(4).verifying_key()),
            PublicJwk::from_key(key(7).verifying_key()),
            ISSUER,
            "issuer",
            trust(),
            NOW
        )
        .is_err()
    );
    assert!(
        presentation::inventory::VerifiedCredential::verify(
            credential("mso_mdoc"),
            "mso_mdoc",
            PublicJwk::from_key(key(7).verifying_key()),
            PublicJwk::from_key(key(3).verifying_key()),
            ISSUER,
            "issuer",
            trust(),
            NOW
        )
        .is_err()
    );
}

#[test]
fn expired_inventory_entries_do_not_block_a_valid_alternative_but_expire_a_prepared_batch() {
    let short = presentation::inventory::VerifiedCredential::verify(
        credential_for_holder_deadline("dc+sd-jwt", 3, NOW + 60),
        "dc+sd-jwt",
        PublicJwk::from_key(key(4).verifying_key()),
        PublicJwk::from_key(key(3).verifying_key()),
        ISSUER,
        "issuer",
        trust(),
        NOW,
    )
    .unwrap();
    let receipts = [short, inventory_receipt("mso_mdoc")];
    let request = inventory_request(
        vec![
            inventory_query("short", "dc+sd-jwt", "name"),
            inventory_query("long", "mso_mdoc", "name"),
        ],
        Some(json!([{"options":[["short"],["long"]]}])),
    );
    let before = request.select(&receipts, NOW).unwrap();
    assert_eq!(before.expires_at(), NOW + 60);
    assert!(
        before
            .encrypt_response(
                &["unused".into()],
                NOW + 60,
                p256::SecretKey::from_slice(&[7; 32]).unwrap(),
                [8; 12]
            )
            .is_err()
    );
    let after = request.select(&receipts, NOW + 60).unwrap();
    assert_eq!(after.selected()[0].inventory_index(), 1);
    assert_eq!(after.selected()[0].request().query_id(), "long");
    assert!(before.selected()[0].values(NOW + 60).is_err());
    let too_many: Vec<_> = (0..9).map(|_| inventory_receipt("dc+sd-jwt")).collect();
    assert!(request.select(&too_many, NOW).is_err());
}
