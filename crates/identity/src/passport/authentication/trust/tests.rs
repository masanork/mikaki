use super::*;
type Crl = CertificateList;
const DG1: &[u8] = include_bytes!("../../fixtures/dg1.bin");
struct Fixture {
    root: &'static [u8],
    sod: &'static [u8],
    good: &'static [u8],
    revoked: &'static [u8],
}
const FIXTURES: &[Fixture] = &[
    Fixture {
        root: include_bytes!("../../fixtures/trust-rsa-root.der"),
        sod: include_bytes!("../../fixtures/trust-rsa.sod"),
        good: include_bytes!("../../fixtures/trust-rsa-good.crl"),
        revoked: include_bytes!("../../fixtures/trust-rsa-revoked.crl"),
    },
    Fixture {
        root: include_bytes!("../../fixtures/trust-p256-root.der"),
        sod: include_bytes!("../../fixtures/trust-p256.sod"),
        good: include_bytes!("../../fixtures/trust-p256-good.crl"),
        revoked: include_bytes!("../../fixtures/trust-p256-revoked.crl"),
    },
    Fixture {
        root: include_bytes!("../../fixtures/trust-p384-root.der"),
        sod: include_bytes!("../../fixtures/trust-p384.sod"),
        good: include_bytes!("../../fixtures/trust-p384-good.crl"),
        revoked: include_bytes!("../../fixtures/trust-p384-revoked.crl"),
    },
];
fn time(f: &Fixture) -> u64 {
    Crl::from_der(f.good)
        .unwrap()
        .tbs_cert_list
        .this_update
        .to_unix_duration()
        .as_secs()
        + 1
}
fn setup(f: &Fixture) -> (Certificate, Vec<Certificate>) {
    (
        verify_inner(f.sod, DG1).unwrap(),
        vec![parse_certificate(f.root).unwrap()],
    )
}
#[test]
fn pinned_japan_roots_and_current_snapshot_crl_verify_including_explicit_p384() {
    for (i, a) in ANCHORS.iter().enumerate() {
        let c = parse_certificate(a.der).unwrap_or_else(|e| panic!("parse anchor {i}: {e}"));
        profile(&c, true).unwrap_or_else(|e| panic!("profile anchor {i}: {e}"));
        verify_signed(
            &c,
            c.signature_algorithm(),
            c.signature().as_bytes().unwrap(),
            &c.tbs_certificate().to_der().unwrap(),
        )
        .unwrap_or_else(|e| panic!("signature anchor {i}: {e:?}"));
    }
    let roots = anchors().unwrap();
    assert_eq!(roots.len(), 4);
    let crl = include_bytes!("../../trust/jpn-20260914.crl");
    let now = Crl::from_der(crl)
        .unwrap()
        .tbs_cert_list
        .this_update
        .to_unix_duration()
        .as_secs()
        + 1;
    // Revocation helper tests the real CRL's signature/issuer/AKI/freshness without
    // claiming a real DSC or physical passport fixture exists.
    assert_eq!(
        revocation(&roots[0], &roots[0], &roots, &[crl.to_vec()], now)
            .unwrap()
            .0,
        "good"
    );
    assert_eq!(
        revocation(&roots[0], &roots[0], &roots, &[crl.to_vec()], now + MAX_AGE),
        Err("stale")
    );
}
#[test]
fn readiness_requires_current_authenticated_crls_without_a_passport_or_synthetic_anchor() {
    let policy = crate::passport::Policy::default();
    let crl = include_bytes!("../../trust/jpn-20260914.crl");
    let parsed = Crl::from_der(crl).unwrap();
    let start = parsed
        .tbs_cert_list
        .this_update
        .to_unix_duration()
        .as_secs();
    let end = parsed
        .tbs_cert_list
        .next_update
        .unwrap()
        .to_unix_duration()
        .as_secs()
        .min(start + MAX_AGE);
    assert_eq!(policy.valid_until(start + 1), Ok(end));
    assert!(policy.valid_until(start - 1).is_err());
    assert!(policy.valid_until(end).is_err());
    assert!(
        crate::passport::Policy::from_json("[]")
            .unwrap()
            .valid_until(start + 1)
            .is_err()
    );
    assert!(policy_valid_until(&[FIXTURES[0].good.to_vec()], start + 1).is_err());
    let mut changed = crl.to_vec();
    *changed.last_mut().unwrap() ^= 1;
    assert!(policy_valid_until(&[changed], start + 1).is_err());
}
#[test]
fn independent_chains_and_complete_crls_distinguish_good_missing_revoked_and_stale() {
    for f in FIXTURES {
        let (cert, roots) = setup(f);
        let now = time(f);
        let end = Crl::from_der(f.good)
            .unwrap()
            .tbs_cert_list
            .next_update
            .unwrap()
            .to_unix_duration()
            .as_secs();
        assert_eq!(
            evaluate(&cert, &roots, &[f.good.to_vec()], now),
            Ok(("good", end))
        );
        assert_eq!(
            evaluate(&cert, &roots, &[f.revoked.to_vec()], now),
            Ok(("revoked", end))
        );
        assert_eq!(evaluate(&cert, &roots, &[], now).unwrap().0, "missing");
        assert_eq!(
            evaluate(&cert, &roots, &[f.good.to_vec()], end).unwrap().0,
            "stale"
        );
        assert_eq!(
            evaluate(&cert, &roots, &[f.good.to_vec()], now - 2)
                .unwrap()
                .0,
            "not_yet_valid"
        );
        assert_eq!(
            evaluate(&cert, &roots, &[f.good.to_vec(), f.good.to_vec()], now)
                .unwrap()
                .0,
            "invalid"
        );
        assert_eq!(
            evaluate(&cert, &[], &[f.good.to_vec()], now),
            Err("unknown_issuer")
        );
        let expired = cert
            .tbs_certificate()
            .validity()
            .not_after
            .to_unix_duration()
            .as_secs();
        assert_eq!(
            evaluate(&cert, &roots, &[f.good.to_vec()], expired),
            Err("certificate_expired")
        );
    }
}
#[test]
fn same_name_wrong_keys_embedded_roots_and_changed_crl_do_not_establish_trust() {
    let (cert, roots) = setup(&FIXTURES[0]);
    let now = time(&FIXTURES[0]);
    let other = parse_certificate(FIXTURES[1].root).unwrap();
    assert_eq!(
        evaluate(&cert, &[other], &[FIXTURES[0].good.to_vec()], now),
        Err("unknown_issuer")
    );
    assert_eq!(
        evaluate(&cert, &roots, &[FIXTURES[1].good.to_vec()], now)
            .unwrap()
            .0,
        "invalid"
    );
    let mut changed = FIXTURES[0].good.to_vec();
    *changed.last_mut().unwrap() ^= 1;
    assert_eq!(
        evaluate(&cert, &roots, &[changed], now).unwrap().0,
        "invalid"
    );
    // Even a valid chain to an unpinned synthetic CSCA remains unknown in production.
    assert_eq!(verify(FIXTURES[0].sod, DG1).issuer_trust, "unknown_issuer");
    let with_root = tests_with_embedded_root(FIXTURES[0].sod, FIXTURES[0].root);
    assert_eq!(verify(&with_root, DG1).issuer_trust, "unknown_issuer");
}
fn tests_with_embedded_root(sod: &[u8], root: &[u8]) -> Vec<u8> {
    super::super::tests::mutate(sod, |s| {
        let mut certs = s.certificates.take().unwrap().into_vec();
        certs.push(Any::from_der(root).unwrap());
        s.certificates = Some(SetOfVec::try_from(certs).unwrap());
    })
}
#[test]
fn malformed_and_partial_crls_never_become_good() {
    let f = &FIXTURES[0];
    let (cert, roots) = setup(f);
    for changed in
        [
            vec![],
            vec![0; 65537],
            {
                let mut v = f.good.to_vec();
                v.push(0);
                v
            },
            {
                let mut crl = Crl::from_der(f.good).unwrap();
                crl.tbs_cert_list.crl_extensions.as_mut().unwrap().push(
                    x509_cert::ext::Extension {
                        extn_id: ObjectIdentifier::new_unwrap("2.5.29.28"),
                        critical: true,
                        extn_value: OctetString::new(vec![0x30, 0]).unwrap(),
                    },
                );
                crl.to_der().unwrap()
            },
        ]
    {
        assert_ne!(
            evaluate(&cert, &roots, &[changed], time(f)).unwrap().0,
            "good"
        );
    }
}
#[test]
fn csca_revocation_and_invalid_dsc_signature_cannot_pass() {
    for (f, crl) in FIXTURES.iter().zip([
        include_bytes!("../../fixtures/trust-rsa-root-revoked.crl").as_slice(),
        include_bytes!("../../fixtures/trust-p256-root-revoked.crl").as_slice(),
        include_bytes!("../../fixtures/trust-p384-root-revoked.crl").as_slice(),
    ]) {
        let (cert, roots) = setup(f);
        assert_eq!(
            evaluate(&cert, &roots, &[crl.to_vec()], time(f)).unwrap().0,
            "revoked"
        );
        let mut bytes = cert.to_der().unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        let changed = parse_certificate(&bytes).unwrap();
        assert_eq!(
            evaluate(&changed, &roots, &[f.good.to_vec()], time(f)),
            Err("invalid_certificate")
        );
    }
}
#[test]
fn build_time_crl_overrides_are_bounded_canonical_and_fail_closed() {
    assert!(decode_crls("[]").unwrap().is_empty());
    let value = B64.encode(FIXTURES[0].good);
    assert_eq!(
        decode_crls(&serde_json::to_string(&vec![value.clone()]).unwrap()).unwrap()[0],
        FIXTURES[0].good
    );
    for json in [
        "null".to_owned(),
        "{}".to_owned(),
        "[\"\"]".to_owned(),
        "[\"not base64\"]".to_owned(),
        serde_json::to_string(&vec![value; 9]).unwrap(),
        serde_json::to_string(&vec![B64.encode(vec![0; 65537])]).unwrap(),
    ] {
        assert_eq!(decode_crls(&json), Err("policy_invalid"));
    }
}
#[test]
fn explicit_curve_parameters_are_bound_not_inferred_from_public_point() {
    use super::super::curves;
    for bytes in [
        include_bytes!("../../trust/p256-parameters.der").as_slice(),
        include_bytes!("../../trust/p384-parameters.der").as_slice(),
    ] {
        assert!(curves::identify(&Any::from_der(bytes).unwrap()).is_ok());
        let mut changed = bytes.to_vec();
        *changed.last_mut().unwrap() = 2; // cofactor 1 -> 2, same public-point width
        assert!(curves::identify(&Any::from_der(&changed).unwrap()).is_err());
        let mut changed = bytes.to_vec();
        changed[40] ^= 1;
        assert!(curves::identify(&Any::from_der(&changed).unwrap()).is_err());
    }
}
