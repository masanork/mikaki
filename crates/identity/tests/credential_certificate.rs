#[path = "support/certificate.rs"]
mod mutable_certificate;
use mutable_certificate::Certificate;

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use der::{
    Decode, Encode,
    asn1::{BitString, Ia5String, ObjectIdentifier, OctetString},
};
use mikaki_identity::{
    credential_certificate::{Purpose, SigningTrust, pinned_leaf, validate_roots, verify},
    issuance::PublicJwk,
};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use x509_cert::ext::{
    Extension,
    pkix::{
        AuthorityKeyIdentifier, BasicConstraints, CrlDistributionPoints, ExtendedKeyUsage,
        IssuerAltName, KeyUsage, KeyUsages, SubjectKeyIdentifier,
        crl::dp::{DistributionPoint, Reasons},
        name::{DistributionPointName, GeneralName},
    },
};
const NOW: u64 = 1791000000;
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
fn trust(prefix: &str) -> SigningTrust {
    SigningTrust {
        chain: vec![B64.encode(bytes(&format!("{prefix}-signer")))],
        trust_anchors: vec![B64.encode(bytes(&format!("{prefix}-ca")))],
        revocation: None,
    }
}
fn mutate(name: &str, edit: impl FnOnce(&mut Certificate)) -> String {
    let mut cert = Certificate::from_der(&bytes(name)).unwrap();
    edit(&mut cert);
    let sig: Signature = key(9).sign(&cert.tbs_certificate.to_der().unwrap());
    cert.signature = BitString::from_bytes(sig.to_der().as_bytes()).unwrap();
    B64.encode(cert.to_der().unwrap())
}
fn check(t: &SigningTrust, p: Purpose) -> bool {
    verify(t, &PublicJwk::from_key(key(4).verifying_key()), p, NOW).is_ok()
}
fn extension<'a>(c: &'a mut Certificate, oid: &str) -> &'a mut Extension {
    c.tbs_certificate
        .extensions
        .as_mut()
        .unwrap()
        .iter_mut()
        .find(|e| e.extn_id.to_string() == oid)
        .unwrap()
}
fn set_extension(c: &mut Certificate, oid: &str, value: &impl Encode) {
    extension(c, oid).extn_value = OctetString::new(value.to_der().unwrap()).unwrap();
}
fn pinned(encoded: &str, purpose: Purpose, now: u64) -> Result<u64, &'static str> {
    pinned_leaf(
        &B64.decode(encoded).unwrap(),
        &PublicJwk::from_key(key(4).verifying_key()),
        purpose,
        now,
    )
}
#[test]
fn separate_credentials_bind_chain_key_purpose_and_current_validity() {
    assert!(check(&trust("sd"), Purpose::SdJwt));
    assert!(check(&trust("mdoc"), Purpose::Mdoc));
    assert!(!check(&trust("sd"), Purpose::Mdoc));
    assert!(!check(&trust("mdoc"), Purpose::SdJwt));
    let public = PublicJwk::from_key(key(5).verifying_key());
    assert!(verify(&trust("sd"), &public, Purpose::SdJwt, NOW).is_err());
    let t = trust("mdoc");
    let leaf = Certificate::from_der(&bytes("mdoc-signer")).unwrap();
    let end = leaf
        .tbs_certificate
        .validity
        .not_after
        .to_unix_duration()
        .as_secs();
    let public = PublicJwk::from_key(key(4).verifying_key());
    assert!(verify(&t, &public, Purpose::Mdoc, 0).is_err());
    assert!(verify(&t, &public, Purpose::Mdoc, end).is_err());
}
#[test]
fn untrusted_included_or_tampered_certificates_are_rejected() {
    for (prefix, purpose) in [("sd", Purpose::SdJwt), ("mdoc", Purpose::Mdoc)] {
        let mut t = trust(prefix);
        t.chain.push(t.trust_anchors[0].clone());
        assert!(!check(&t, purpose));
        let mut t = trust(prefix);
        t.trust_anchors = trust(if prefix == "sd" { "mdoc" } else { "sd" }).trust_anchors;
        assert!(!check(&t, purpose));
        let mut t = trust(prefix);
        let mut b = bytes(&format!("{prefix}-signer"));
        *b.last_mut().unwrap() ^= 1;
        t.chain[0] = B64.encode(b);
        assert!(!check(&t, purpose));
        let mut t = trust(prefix);
        t.trust_anchors.push(t.trust_anchors[0].clone());
        assert!(!check(&t, purpose));
    }
    let mut extra = trust("sd");
    extra.chain.push(trust("mdoc").trust_anchors[0].clone());
    assert!(
        !check(&extra, Purpose::SdJwt),
        "Unrelated CA cannot be appended to an otherwise valid x5c"
    );
    let mut t = trust("mdoc");
    let mut b = bytes("mdoc-ca");
    *b.last_mut().unwrap() ^= 1;
    t.trust_anchors[0] = B64.encode(b);
    assert!(!check(&t, Purpose::Mdoc));
}
#[test]
fn mdoc_profile_requires_identifiers_contacts_revocation_pointer_and_critical_eku() {
    for oid in [
        "2.5.29.14",
        "2.5.29.35",
        "2.5.29.18",
        "2.5.29.31",
        "2.5.29.37",
        "2.5.29.15",
    ] {
        let mut t = trust("mdoc");
        t.chain[0] = mutate("mdoc-signer", |c| {
            c.tbs_certificate
                .extensions
                .as_mut()
                .unwrap()
                .retain(|e| e.extn_id.to_string() != oid)
        });
        assert!(!check(&t, Purpose::Mdoc), "missing {oid}");
    }
    for oid in ["2.5.29.15", "2.5.29.37"] {
        let mut t = trust("mdoc");
        t.chain[0] = mutate("mdoc-signer", |c| {
            c.tbs_certificate
                .extensions
                .as_mut()
                .unwrap()
                .iter_mut()
                .find(|e| e.extn_id.to_string() == oid)
                .unwrap()
                .critical = false
        });
        assert!(!check(&t, Purpose::Mdoc));
    }
    let mut t = trust("mdoc");
    t.chain[0] = mutate("mdoc-signer", |c| {
        let e = c
            .tbs_certificate
            .extensions
            .as_mut()
            .unwrap()
            .iter_mut()
            .find(|e| e.extn_id.to_string() == "2.5.29.35")
            .unwrap();
        e.extn_value = OctetString::new(
            AuthorityKeyIdentifier {
                key_identifier: Some(OctetString::new([0; 20]).unwrap()),
                ..Default::default()
            }
            .to_der()
            .unwrap(),
        )
        .unwrap();
    });
    assert!(!check(&t, Purpose::Mdoc));
    let mut t = trust("mdoc");
    t.chain[0] = mutate("mdoc-signer", |c| {
        let e = c.tbs_certificate.extensions.as_ref().unwrap()[0].clone();
        c.tbs_certificate.extensions.as_mut().unwrap().push(e);
    });
    assert!(!check(&t, Purpose::Mdoc));
}
#[test]
fn mdoc_rejects_excessive_ds_lifetime_and_iaca_path_length() {
    let mut t = trust("mdoc");
    t.chain[0] = mutate("mdoc-signer", |c| {
        c.tbs_certificate.validity.not_after = Certificate::from_der(&bytes("mdoc-ca"))
            .unwrap()
            .tbs_certificate
            .validity
            .not_after;
    });
    assert!(!check(&t, Purpose::Mdoc));
    let mut t = trust("mdoc");
    t.trust_anchors[0] = mutate("mdoc-ca", |c| {
        let e = c
            .tbs_certificate
            .extensions
            .as_mut()
            .unwrap()
            .iter_mut()
            .find(|e| e.extn_id == ObjectIdentifier::new_unwrap("2.5.29.19"))
            .unwrap();
        e.extn_value = OctetString::new(
            BasicConstraints {
                ca: true,
                path_len_constraint: Some(1),
            }
            .to_der()
            .unwrap(),
        )
        .unwrap();
    });
    assert!(!check(&t, Purpose::Mdoc));
}

#[test]
fn configured_crls_reject_revoked_stale_missing_and_untrusted_status() {
    use mikaki_identity::certificate::CrlPolicy;
    let crl = |name: &str| {
        std::fs::read(format!(
            "{}/tests/fixtures/credential/mdoc-{name}.crl",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    };
    let mut t = trust("mdoc");
    t.revocation = Some(CrlPolicy {
        crls: vec![B64.encode(crl("clean"))],
        max_age_seconds: 604800,
    });
    assert!(check(&t, Purpose::Mdoc));
    let public = PublicJwk::from_key(key(4).verifying_key());
    assert!(verify(&t, &public, Purpose::Mdoc, NOW + 604800).is_err());
    t.revocation.as_mut().unwrap().crls = vec![B64.encode(crl("revoked"))];
    assert!(!check(&t, Purpose::Mdoc));
    t.revocation.as_mut().unwrap().crls.clear();
    assert!(!check(&t, Purpose::Mdoc));
    let mut bad = crl("clean");
    *bad.last_mut().unwrap() ^= 1;
    t.revocation.as_mut().unwrap().crls = vec![B64.encode(bad)];
    assert!(!check(&t, Purpose::Mdoc));
}

#[test]
fn pinned_validity_is_inclusive_at_start_and_exclusive_at_end() {
    let leaf = Certificate::from_der(&bytes("mdoc-signer")).unwrap();
    let validity = leaf.tbs_certificate.validity;
    let start = validity.not_before.to_unix_duration().as_secs();
    let end = validity.not_after.to_unix_duration().as_secs();
    let encoded = B64.encode(bytes("mdoc-signer"));
    assert_eq!(pinned(&encoded, Purpose::Mdoc, start), Ok(end));
    assert_eq!(pinned(&encoded, Purpose::Mdoc, end - 1), Ok(end));
    for now in [start - 1, end] {
        assert_eq!(
            pinned(&encoded, Purpose::Mdoc, now),
            Err("invalid_credential_certificate")
        );
    }
}

#[test]
fn mdoc_subject_requires_one_country_and_nonempty_supported_common_name() {
    for (subject, accepted) in [
        ("C=JP,CN=Signer", true),
        ("C=JP,CN=#13065369676e6572", true),
        ("C=JP,CN=署名者,OU=Wallet", true),
        ("C=JP+CN=Signer,O=Issuer", true),
        ("C=JP,C=US,CN=Signer", false),
        ("C=jp,CN=Signer", false),
        ("C=JPN,CN=Signer", false),
        ("C=#0c024a50,CN=Signer", false),
        ("CN=Signer", false),
        ("C=JP", false),
        ("C=JP,CN=", false),
        ("C=JP,CN=#16065369676e6572", false),
        ("C=JP,CN=Signer,O=#1606497373756572", false),
    ] {
        let encoded = mutate("mdoc-signer", |c| {
            c.tbs_certificate.subject = subject.parse().unwrap();
        });
        assert_eq!(
            pinned(&encoded, Purpose::Mdoc, NOW).is_ok(),
            accepted,
            "{subject}"
        );
    }
}

#[test]
fn mdoc_contacts_key_identifiers_and_signing_purpose_are_bound() {
    for (contact, accepted) in [
        (
            GeneralName::Rfc822Name(Ia5String::new("issuer@example.test").unwrap()),
            true,
        ),
        (
            GeneralName::UniformResourceIdentifier(
                Ia5String::new("https://issuer.example.test").unwrap(),
            ),
            true,
        ),
        (
            GeneralName::DnsName(Ia5String::new("issuer.example.test").unwrap()),
            false,
        ),
        (GeneralName::Rfc822Name(Ia5String::new("").unwrap()), false),
    ] {
        let encoded = mutate("mdoc-signer", |c| {
            set_extension(c, "2.5.29.18", &IssuerAltName(vec![contact]));
        });
        assert_eq!(pinned(&encoded, Purpose::Mdoc, NOW).is_ok(), accepted);
    }
    let bad_ski = mutate("mdoc-signer", |c| {
        set_extension(
            c,
            "2.5.29.14",
            &SubjectKeyIdentifier(OctetString::new([0; 20]).unwrap()),
        );
    });
    assert_eq!(
        pinned(&bad_ski, Purpose::Mdoc, NOW),
        Err("invalid_credential_certificate")
    );
    let missing_aki_key = mutate("mdoc-signer", |c| {
        set_extension(c, "2.5.29.35", &AuthorityKeyIdentifier::default());
    });
    assert_eq!(
        pinned(&missing_aki_key, Purpose::Mdoc, NOW),
        Err("invalid_credential_certificate")
    );
    for oids in [
        vec![],
        vec!["1.3.6.1.5.5.7.3.3"],
        vec!["1.0.18013.5.1.2", "1.3.6.1.5.5.7.3.3"],
    ] {
        let encoded = mutate("mdoc-signer", |c| {
            set_extension(
                c,
                "2.5.29.37",
                &ExtendedKeyUsage(oids.into_iter().map(|s| s.parse().unwrap()).collect()),
            );
        });
        assert_eq!(
            pinned(&encoded, Purpose::Mdoc, NOW),
            Err("invalid_credential_certificate")
        );
    }
}

#[test]
fn mdoc_distribution_points_reject_partial_or_indirect_revocation() {
    let uri = GeneralName::UniformResourceIdentifier(
        Ia5String::new("https://issuer.example.test/status.crl").unwrap(),
    );
    let valid = DistributionPoint {
        distribution_point: Some(DistributionPointName::FullName(vec![uri.clone()])),
        reasons: None,
        crl_issuer: None,
    };
    let mut partial = valid.clone();
    partial.reasons = Some(Reasons::KeyCompromise.into());
    let mut indirect = valid.clone();
    indirect.crl_issuer = Some(vec![uri]);
    let mut dns_only = valid.clone();
    dns_only.distribution_point =
        Some(DistributionPointName::FullName(vec![GeneralName::DnsName(
            Ia5String::new("issuer.example.test").unwrap(),
        )]));
    for (points, accepted) in [
        (vec![valid.clone()], true),
        (vec![], false),
        (vec![partial], false),
        (vec![indirect], false),
        (vec![dns_only.clone()], false),
        (vec![dns_only, valid], true),
    ] {
        let encoded = mutate("mdoc-signer", |c| {
            set_extension(c, "2.5.29.31", &CrlDistributionPoints(points));
        });
        assert_eq!(pinned(&encoded, Purpose::Mdoc, NOW).is_ok(), accepted);
    }
}

#[test]
fn mdoc_rejects_unsupported_extensions_and_malformed_profile_values() {
    for oid in [
        "2.5.29.33",
        "2.5.29.30",
        "2.5.29.36",
        "2.5.29.54",
        "2.5.29.46",
        "1.2.3.4",
    ] {
        let encoded = mutate("mdoc-signer", |c| {
            c.tbs_certificate
                .extensions
                .as_mut()
                .unwrap()
                .push(Extension {
                    extn_id: oid.parse().unwrap(),
                    critical: oid == "1.2.3.4",
                    extn_value: OctetString::new([0x30, 0]).unwrap(),
                });
        });
        assert_eq!(
            pinned(&encoded, Purpose::Mdoc, NOW),
            Err("invalid_credential_certificate"),
            "{oid}"
        );
    }
    for oid in [
        "2.5.29.15",
        "2.5.29.14",
        "2.5.29.18",
        "2.5.29.37",
        "2.5.29.35",
        "2.5.29.31",
    ] {
        let encoded = mutate("mdoc-signer", |c| {
            extension(c, oid).extn_value = OctetString::new([0xff]).unwrap();
        });
        assert_eq!(
            pinned(&encoded, Purpose::Mdoc, NOW),
            Err("invalid_credential_certificate"),
            "{oid}"
        );
    }
}

#[test]
fn certificate_usage_and_sd_jwt_errors_retain_their_priority() {
    let eku = |c: &mut Certificate| {
        c.tbs_certificate
            .extensions
            .as_mut()
            .unwrap()
            .push(Extension {
                extn_id: "2.5.29.37".parse().unwrap(),
                critical: false,
                extn_value: OctetString::new([0xff]).unwrap(),
            });
    };
    let encoded = mutate("sd-signer", eku);
    assert_eq!(
        pinned(&encoded, Purpose::SdJwt, NOW),
        Err("unsupported_credential_eku")
    );
    let encoded = mutate("sd-signer", |c| {
        eku(c);
        extension(c, "2.5.29.15").critical = false;
    });
    assert_eq!(
        pinned(&encoded, Purpose::SdJwt, NOW),
        Err("invalid_credential_certificate")
    );
    let encoded = mutate("sd-signer", |c| {
        set_extension(
            c,
            "2.5.29.19",
            &BasicConstraints {
                ca: true,
                path_len_constraint: None,
            },
        );
    });
    assert_eq!(
        pinned(&encoded, Purpose::SdJwt, NOW),
        Err("invalid_credential_certificate")
    );
    for usage in [KeyUsages::DigitalSignature, KeyUsages::CRLSign] {
        let encoded = mutate("mdoc-ca", |c| {
            set_extension(c, "2.5.29.15", &KeyUsage(usage.into()));
        });
        assert_eq!(
            validate_roots(&[encoded], Purpose::Mdoc, NOW),
            Err("invalid_credential_certificate")
        );
    }
}
