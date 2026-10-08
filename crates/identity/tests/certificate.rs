#[path = "support/certificate.rs"]
mod mutable_certificate;
use mutable_certificate::Certificate;

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use mikaki_identity::{
    certificate::{ReaderTrust, verify_reader_chain},
    issuance::PublicJwk,
};
use p256::ecdsa::SigningKey;
const NOW: u64 = 1790899200; // 2026-10-02 UTC
fn cert(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/trust/{name}.der",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}
fn key(n: u8) -> PublicJwk {
    PublicJwk::from_key(SigningKey::from_slice(&[n; 32]).unwrap().verifying_key())
}
fn policy() -> ReaderTrust {
    ReaderTrust {
        trust_anchors: vec![B64.encode(cert("root"))],
        dns_name: Some("verifier.example".into()),
        revocation: None,
    }
}
#[test]
fn registered_ca_chain_binds_key_name_purpose_and_time() {
    let chain = vec![cert("leaf"), cert("intermediate")];
    verify_reader_chain(&chain, &policy(), &key(5), NOW).unwrap();
    assert!(verify_reader_chain(&chain, &policy(), &key(4), NOW).is_err());
    for time in [0, 2082758400] {
        assert!(verify_reader_chain(&chain, &policy(), &key(5), time).is_err());
    }
    let mut p = policy();
    p.dns_name = Some("other.example".into());
    assert!(verify_reader_chain(&chain, &p, &key(5), NOW).is_err());
    p.trust_anchors = vec![B64.encode(cert("wrong-root"))];
    assert!(verify_reader_chain(&chain, &p, &key(5), NOW).is_err());
}
#[test]
fn rejects_invalid_chains_and_unsupported_certificates() {
    for name in [
        "wrong-san",
        "wrong-eku",
        "unknown-critical",
        "expired",
        "future",
        "ca-leaf",
        "wildcard",
        "missing-san",
        "missing-eku",
    ] {
        assert!(
            verify_reader_chain(&[cert(name), cert("intermediate")], &policy(), &key(5), NOW)
                .is_err(),
            "{name}"
        );
    }
    assert!(verify_reader_chain(&[cert("leaf")], &policy(), &key(5), NOW).is_err());
    assert!(verify_reader_chain(&[cert("leaf"), cert("bad-ca")], &policy(), &key(5), NOW).is_err());
    assert!(
        verify_reader_chain(
            &[cert("too-deep"), cert("sub-ca"), cert("intermediate")],
            &policy(),
            &key(5),
            NOW
        )
        .is_err()
    );
    let mut intermediate = cert("intermediate");
    *intermediate.last_mut().unwrap() ^= 1;
    assert!(verify_reader_chain(&[cert("leaf"), intermediate], &policy(), &key(5), NOW).is_err());
}
#[test]
fn supplied_roots_do_not_establish_trust_and_limits_fail_closed() {
    let mut p = policy();
    p.trust_anchors.clear();
    assert!(
        verify_reader_chain(
            &[cert("leaf"), cert("intermediate"), cert("root")],
            &p,
            &key(5),
            NOW
        )
        .is_err()
    );
    assert!(verify_reader_chain(&[], &policy(), &key(5), NOW).is_err());
    assert!(verify_reader_chain(&vec![cert("leaf"); 5], &policy(), &key(5), NOW).is_err());
    assert!(verify_reader_chain(&[vec![0; 4097]], &policy(), &key(5), NOW).is_err());
    let mut p = policy();
    p.trust_anchors.push(p.trust_anchors[0].clone());
    assert!(p.validate().is_err());
    for name in [
        "*.example",
        "verifier.example.",
        "VerIfier.example",
        "127.0.0.1",
        "verifier",
    ] {
        let mut p = policy();
        p.dns_name = Some(name.into());
        assert!(p.validate().is_err(), "{name}");
    }
}

#[test]
fn ca_usage_restrictions_and_duplicate_extensions_are_enforced() {
    use der::{Decode, Encode, asn1::BitString};
    use p256::ecdsa::{Signature, signature::Signer};
    let mut leaf = Certificate::from_der(&cert("leaf")).unwrap();
    let extensions = leaf.tbs_certificate.extensions.as_mut().unwrap();
    extensions.push(extensions[0].clone());
    let signer = SigningKey::from_slice(&[8; 32]).unwrap();
    let signature: Signature = signer.sign(&leaf.tbs_certificate.to_der().unwrap());
    leaf.signature = BitString::from_bytes(signature.to_der().as_bytes()).unwrap();
    assert!(
        verify_reader_chain(
            &[leaf.to_der().unwrap(), cert("intermediate")],
            &policy(),
            &key(5),
            NOW
        )
        .is_err()
    );
    assert!(
        verify_reader_chain(
            &[cert("leaf"), cert("wrong-ca-eku")],
            &policy(),
            &key(5),
            NOW
        )
        .is_err()
    );
    let mut p = policy();
    p.trust_anchors = vec![B64.encode(cert("wrong-root-eku"))];
    assert!(p.validate().is_err());
}

fn crl(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/trust/{name}.crl",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}
fn with_status(names: &[&str]) -> ReaderTrust {
    let mut p = policy();
    p.revocation = Some(mikaki_identity::certificate::CrlPolicy {
        crls: names.iter().map(|s| B64.encode(crl(s))).collect(),
        max_age_seconds: 604800,
    });
    p
}
#[test]
fn whole_chain_crls_reject_revoked_unknown_and_bad_signatures() {
    let chain = [cert("leaf"), cert("intermediate")];
    let check = |names: &[&str]| verify_reader_chain(&chain, &with_status(names), &key(5), NOW);
    assert_eq!(
        check(&["clean-intermediate", "clean-root"]).unwrap(),
        1791331200
    );
    for names in [
        ["revoked-leaf", "clean-root"],
        ["clean-intermediate", "revoked-intermediate"],
    ] {
        assert_eq!(check(&names), Err("certificate_revoked"));
    }
    for names in [
        vec!["clean-intermediate"],
        vec!["clean-root"],
        vec!["wrong-issuer", "clean-root"],
    ] {
        assert_eq!(check(&names), Err("certificate_status_unknown"));
    }
    assert_eq!(check(&["wrong-key", "clean-root"]), Err("invalid_crl"));
    let mut p = with_status(&["clean-intermediate", "clean-root"]);
    let mut bytes = crl("clean-intermediate");
    *bytes.last_mut().unwrap() ^= 1;
    p.revocation.as_mut().unwrap().crls[0] = B64.encode(bytes);
    assert_eq!(
        verify_reader_chain(&chain, &p, &key(5), NOW),
        Err("invalid_crl")
    );
}
#[test]
fn crl_time_and_age_limits_are_strict_and_bound_consent_deadline() {
    let chain = [cert("leaf"), cert("intermediate")];
    for (name, error) in [
        ("expired", "crl_expired"),
        ("future", "crl_not_yet_valid"),
        ("stale", "crl_stale"),
    ] {
        assert_eq!(
            verify_reader_chain(&chain, &with_status(&[name, "clean-root"]), &key(5), NOW),
            Err(error)
        );
    }
    let mut p = with_status(&["clean-intermediate", "clean-root"]);
    p.revocation.as_mut().unwrap().max_age_seconds = 172801;
    assert_eq!(
        verify_reader_chain(&chain, &p, &key(5), NOW).unwrap(),
        NOW + 1
    );
    assert_eq!(
        verify_reader_chain(&chain, &p, &key(5), NOW + 1),
        Err("crl_stale")
    );
    assert_eq!(
        verify_reader_chain(
            &chain,
            &with_status(&["clean-intermediate", "clean-root"]),
            &key(5),
            1791331200
        ),
        Err("crl_expired")
    );
}
#[test]
fn unsupported_crl_formats_and_ambiguous_policies_do_not_downgrade() {
    for name in [
        "delta",
        "indirect",
        "unknown-critical",
        "missing-aki",
        "missing-number",
    ] {
        assert!(
            with_status(&[name, "clean-root"]).validate().is_err(),
            "{name}"
        );
    }
    assert!(with_status(&[]).validate().is_err());
    assert!(
        with_status(&["clean-intermediate", "revoked-leaf", "clean-root"])
            .validate()
            .is_err()
    );
    for age in [0, 59, 604801, u64::MAX] {
        let mut p = with_status(&["clean-intermediate", "clean-root"]);
        p.revocation.as_mut().unwrap().max_age_seconds = age;
        assert!(p.validate().is_err());
    }
    let mut p = with_status(&["clean-intermediate", "clean-root"]);
    p.revocation.as_mut().unwrap().crls[0] = B64.encode(vec![0; 32769]);
    assert!(p.validate().is_err());
    let mut p = with_status(&["clean-intermediate", "clean-root"]);
    p.revocation.as_mut().unwrap().crls[0].push('=');
    assert!(p.validate().is_err());
}
