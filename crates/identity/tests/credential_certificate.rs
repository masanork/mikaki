use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use der::{
    Decode, Encode,
    asn1::{BitString, ObjectIdentifier, OctetString},
};
use mikaki_identity::{
    credential_certificate::{Purpose, SigningTrust, verify},
    issuance::PublicJwk,
};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use x509_cert::{
    Certificate,
    ext::pkix::{AuthorityKeyIdentifier, BasicConstraints},
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
