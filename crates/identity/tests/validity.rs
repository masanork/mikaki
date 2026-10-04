use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use der::{Decode, Encode};
use mikaki_identity::{
    card::{CardPreview, DocumentType},
    evidence::{VerifiedDocument, date_end},
    issuance::{self, PublicJwk, Validity},
    mdoc,
};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use serde_json::Value;
const NOW: u64 = 1790899200;
fn document(expiry: Option<&str>) -> VerifiedDocument {
    VerifiedDocument {
        attributes: CardPreview {
            name: "Fixture".into(),
            address: "Private".into(),
            birth_date: "1990-02-28".into(),
            gender: "1".into(),
            verification: "issuer_signed_static_data".into(),
            document_type: if expiry.is_some() {
                DocumentType::DrivingLicense
            } else {
                DocumentType::MyNumberCard
            },
            expiry_date: expiry.map(str::to_string),
            backend_verifiable: true,
        },
        trusted_key_id: "fixture".into(),
        verified_at: NOW,
        assurance: "issuer_signed_static_data".into(),
        attributes_source: "fixture".into(),
    }
}
fn keys() -> (SigningKey, PublicJwk, PublicJwk) {
    let issuer = SigningKey::from_slice(&[4; 32]).unwrap();
    let public = PublicJwk::from_key(issuer.verifying_key());
    let holder = PublicJwk::from_key(SigningKey::from_slice(&[2; 32]).unwrap().verifying_key());
    (issuer, public, holder)
}
#[test]
fn both_formats_obey_external_deadline_and_expire_at_the_exact_boundary() {
    let (key, public, holder) = keys();
    let doc = document(None);
    for lifetime in [1, 17, 300, 1000] {
        let validity = Validity::new(&doc, NOW, NOW + lifetime).unwrap();
        let end = NOW + lifetime.min(300);
        assert_eq!(validity.expires_at(), end);
        let sd = issuance::issue_with_validity(
            &key,
            "issuer",
            "https://issuer.example",
            &holder,
            &doc,
            validity,
            &[[1; 16]; 4],
        )
        .unwrap();
        let claims = issuance::verify_receipt(
            &sd,
            &public,
            "issuer",
            &holder,
            "https://issuer.example",
            end - 1,
        )
        .unwrap();
        assert_eq!(claims["exp"], end);
        assert!(
            issuance::verify_receipt(
                &sd,
                &public,
                "issuer",
                &holder,
                "https://issuer.example",
                end
            )
            .is_err()
        );
        let credential = mdoc::issue_with_validity(
            &key,
            include_bytes!("fixtures/mdoc-ds.der"),
            &holder,
            &doc,
            validity,
            &[[1; 16]; 4],
        )
        .unwrap();
        assert_eq!(
            mdoc::verify_receipt(&credential, &public, &holder, end - 1)
                .unwrap()
                .expires_at,
            end
        );
        assert!(mdoc::verify_receipt(&credential, &public, &holder, end).is_err());
    }
    for deadline in [0, NOW - 1, NOW] {
        assert!(Validity::new(&doc, NOW, deadline).is_err());
    }
    assert!(Validity::new(&doc, u64::MAX, u64::MAX).is_err());
}
#[test]
fn licence_day_end_bounds_both_formats_and_receipt_rejects_overlong_signed_claims() {
    let (key, public, holder) = keys();
    let doc = document(Some("2026-10-02"));
    let end = date_end("2026-10-02").unwrap();
    let time = end - 9;
    let sd = issuance::issue(
        &key,
        "issuer",
        "https://issuer.example",
        &holder,
        &doc,
        time,
        &[[1; 16]; 5],
    )
    .unwrap();
    assert_eq!(
        issuance::verify_receipt(
            &sd,
            &public,
            "issuer",
            &holder,
            "https://issuer.example",
            time
        )
        .unwrap()["exp"],
        end
    );
    let m = mdoc::issue(
        &key,
        include_bytes!("fixtures/mdoc-ds.der"),
        &holder,
        &doc,
        time,
        &[[1; 16]; 5],
    )
    .unwrap();
    assert_eq!(
        mdoc::verify_receipt(&m, &public, &holder, time)
            .unwrap()
            .expires_at,
        end
    );
    assert!(Validity::new(&doc, end, u64::MAX).is_err());
    let (jwt, disclosures) = sd.split_once('~').unwrap();
    let mut claims: Value =
        serde_json::from_slice(&B64.decode(jwt.split('.').nth(1).unwrap()).unwrap()).unwrap();
    let header: Value =
        serde_json::from_slice(&B64.decode(jwt.split('.').next().unwrap()).unwrap()).unwrap();
    claims["exp"] = (time + 300).into();
    let overlong = format!(
        "{}~{}",
        issuance::sign_jwt(&key, header, claims).unwrap(),
        disclosures
    );
    assert!(
        issuance::verify_receipt(
            &overlong,
            &public,
            "issuer",
            &holder,
            "https://issuer.example",
            time
        )
        .is_err()
    );
    assert!(Validity::new(&document(Some("2026-02-30")), NOW, u64::MAX).is_err());
    let mut missing = document(None);
    missing.attributes.document_type = DocumentType::DrivingLicense;
    assert!(Validity::new(&missing, NOW, u64::MAX).is_err());
}
#[test]
fn mdoc_shortens_validity_to_document_signer_certificate_end() {
    let (key, public, holder) = keys();
    let doc = document(None);
    let mut cert =
        x509_cert::Certificate::from_der(include_bytes!("fixtures/mdoc-ds.der")).unwrap();
    let end = NOW + 7;
    cert.tbs_certificate.validity.not_after = x509_cert::time::Time::UtcTime(
        der::asn1::UtcTime::from_unix_duration(std::time::Duration::from_secs(end)).unwrap(),
    );
    let sig: Signature = key.sign(&cert.tbs_certificate.to_der().unwrap());
    cert.signature = der::asn1::BitString::from_bytes(sig.to_der().as_bytes()).unwrap();
    let cert = cert.to_der().unwrap();
    let cred = mdoc::issue(&key, &cert, &holder, &doc, NOW, &[[1; 16]; 4]).unwrap();
    assert_eq!(
        mdoc::verify_receipt(&cred, &public, &holder, end - 1)
            .unwrap()
            .expires_at,
        end
    );
    assert!(mdoc::verify_receipt(&cred, &public, &holder, end).is_err());
    assert!(mdoc::issue(&key, &cert, &holder, &doc, end, &[[1; 16]; 4]).is_err());
}

#[test]
fn sd_jwt_x5c_receipt_uses_pinned_key_and_caps_expiry_at_signer_certificate_end() {
    use base64::engine::general_purpose::STANDARD;
    use mikaki_identity::{
        certificate::decode_certificate,
        credential_certificate::{Purpose, SigningTrust, verify},
    };
    let (key, public, holder) = keys();
    let trust = SigningTrust {
        chain: vec![STANDARD.encode(include_bytes!("fixtures/credential/sd-signer.der"))],
        trust_anchors: vec![STANDARD.encode(include_bytes!("fixtures/credential/sd-ca.der"))],
        revocation: None,
    };
    let leaf =
        x509_cert::Certificate::from_der(&decode_certificate(&trust.chain[0]).unwrap()).unwrap();
    let end = leaf
        .tbs_certificate
        .validity
        .not_after
        .to_unix_duration()
        .as_secs();
    let time = end - 60;
    let doc = document(None);
    assert_eq!(
        verify(&trust, &public, Purpose::SdJwt, time).unwrap().1,
        end
    );
    let token = issuance::issue_with_certificate_trust(
        &key,
        "issuer",
        "https://issuer.example",
        &holder,
        &doc,
        Validity::new(&doc, time, u64::MAX).unwrap(),
        &[[1; 16]; 4],
        &trust,
    )
    .unwrap();
    let claims = issuance::verify_receipt(
        &token,
        &public,
        "issuer",
        &holder,
        "https://issuer.example",
        time,
    )
    .unwrap();
    assert_eq!(claims["exp"], end);
    assert!(
        issuance::verify_receipt(
            &token,
            &public,
            "issuer",
            &holder,
            "https://issuer.example",
            end
        )
        .is_err()
    );
    let mut parts = token.split('~');
    let original = parts.next().unwrap();
    let header: Value =
        serde_json::from_slice(&B64.decode(original.split('.').next().unwrap()).unwrap()).unwrap();
    assert_eq!(header["x5c"], serde_json::json!(trust.chain));
    let payload: Value =
        serde_json::from_slice(&B64.decode(original.split('.').nth(1).unwrap()).unwrap()).unwrap();
    let mut overlong = payload;
    overlong["exp"] = serde_json::json!(end + 1);
    let signed = issuance::sign_jwt(&key, header.clone(), overlong).unwrap();
    let mutated = format!("{signed}~{}", parts.collect::<Vec<_>>().join("~"));
    assert!(
        issuance::verify_receipt(
            &mutated,
            &public,
            "issuer",
            &holder,
            "https://issuer.example",
            time
        )
        .is_err()
    );
    let mut bad_header = header;
    bad_header["x5c"] =
        serde_json::json!([STANDARD.encode(include_bytes!("fixtures/credential/mdoc-signer.der"))]);
    let signed = issuance::sign_jwt(&key, bad_header, claims).unwrap();
    assert!(
        issuance::verify_receipt(
            &format!("{signed}~"),
            &public,
            "issuer",
            &holder,
            "https://issuer.example",
            time
        )
        .is_err()
    );
}

#[test]
fn privacy_rounding_never_extends_document_or_external_deadlines() {
    let doc = document(None);
    let fresh = Validity::new(&doc, NOW + 15, NOW + 300)
        .unwrap()
        .rounded_minutes(NOW + 10)
        .unwrap();
    assert_eq!(fresh.issued_at(), NOW + 10);
    assert!(
        Validity::new(&doc, NOW, NOW + 300)
            .unwrap()
            .rounded_minutes(NOW + 1)
            .is_err()
    );
    for offset in [0, 1, 59, 60, 61] {
        for remaining in [1, 17, 59, 60, 61, 300, 1000] {
            let now = NOW + offset;
            let exact = Validity::new(&doc, now, now + remaining).unwrap();
            match exact.rounded_minutes(0) {
                Ok(v) => {
                    assert_eq!(v.issued_at() % 60, 0);
                    assert_eq!(v.expires_at() % 60, 0);
                    assert!(v.issued_at() <= now && now < v.expires_at());
                    assert!(v.expires_at() <= exact.expires_at());
                    assert!(v.expires_at() - v.issued_at() <= 300);
                }
                Err(_) => assert!(exact.expires_at() / 60 * 60 <= now),
            }
        }
    }
}
