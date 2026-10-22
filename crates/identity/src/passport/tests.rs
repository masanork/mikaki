use super::*;
use serde_json::json;
const DG1: &[u8] = include_bytes!("fixtures/dg1.bin");
const SOD: &[u8] = include_bytes!("fixtures/rsa-sha256.sod");
const NOW: u64 = 1792627200;

#[test]
fn evidence_roundtrip_retains_only_original_bounded_chip_evidence() {
    let evidence = Evidence::from_bytes(DG1.to_vec(), SOD.to_vec()).unwrap();
    let value = serde_json::to_value(&evidence).unwrap();
    assert_eq!(value.as_object().unwrap().len(), 2);
    let restored: Evidence = serde_json::from_value(value).unwrap();
    assert_eq!(&*restored.dg1, DG1);
    assert_eq!(&*restored.sod, SOD);
    let report = restored.inspect(&Policy::default(), NOW);
    assert_eq!(report.state, State::Consistent);
    assert_eq!(report.issuer_trust, "unknown_issuer");
    assert!(matches!(
        restored.verify(&Policy::default(), NOW),
        Err(VerificationError::UntrustedIssuer)
    ));
}
#[test]
fn evidence_rejects_injected_claims_results_keys_noncanonical_encoding_and_size() {
    let wire = json!({"dg1":B64.encode(DG1),"sod":B64.encode(SOD)});
    for field in [
        "name",
        "birthdate",
        "expiry_date",
        "report",
        "issuer_trust",
        "trusted_roots",
        "holder_key",
        "session_key",
    ] {
        let mut changed = wire.clone();
        changed[field] = json!("caller supplied");
        assert!(
            serde_json::from_value::<Evidence>(changed).is_err(),
            "{field}"
        );
    }
    for changed in [
        json!({"dg1":B64.encode(DG1),"sod":B64.encode(SOD)+"="}),
        json!({"dg1":B64.encode(vec![0;94]),"sod":B64.encode(SOD)}),
        json!({"dg1":B64.encode(DG1),"sod":B64.encode(vec![0;MAX_SOD+1])}),
        json!({"dg1":B64.encode(DG1),"sod":""}),
        json!({"dg1":[1,2],"sod":[3,4]}),
    ] {
        assert!(serde_json::from_value::<Evidence>(changed).is_err());
    }
    assert!(
        serde_json::from_str::<Evidence>(&format!(
            "{{\"dg1\":\"{}\",\"dg1\":\"{}\",\"sod\":\"{}\"}}",
            B64.encode(DG1),
            B64.encode(DG1),
            B64.encode(SOD)
        ))
        .is_err()
    );
    assert!(Evidence::from_bytes(vec![], SOD.to_vec()).is_err());
}
#[test]
fn claims_preserve_signed_mrz_dates_without_inventing_century_or_identifiers() {
    let claims = mrz::claims(DG1).unwrap();
    assert_eq!(claims.name_mrz, "ERIKSSON ANNA MARIA");
    assert_eq!(claims.birth_date_mrz, "690806");
    assert_eq!(claims.expiry_date_mrz, "940623");
    assert_eq!(claims.issuing_state, "UTO");
    let wire = serde_json::to_value(claims).unwrap();
    for field in [
        "birthdate",
        "birth_date",
        "expiry_date",
        "document_number",
        "personal_number",
        "mrz",
        "address",
        "portrait",
        "age_over_18",
    ] {
        assert!(wire.get(field).is_none(), "{field}");
    }
    assert!(!wire.to_string().contains("L898902C"));
}
#[test]
fn mrz_scope_calendar_and_checksums_are_validated_without_bac_access_input() {
    for offset in [0, 1, 4, 5, 30, 49, 58, 62, 70, 90, 92] {
        let mut changed = DG1.to_vec();
        changed[offset] = b'?';
        assert!(mrz::claims(&changed).is_err(), "offset {offset}");
        let e = Evidence::from_bytes(changed, SOD.to_vec()).unwrap();
        assert_eq!(e.inspect(&Policy::default(), NOW).state, State::Invalid);
    }
    for raw in [b"000229".as_slice(), b"040229", b"691231"] {
        assert!(mrz::date(raw));
    }
    for raw in [b"010229".as_slice(), b"690000", b"691332", b"69<<<<"] {
        assert!(!mrz::date(raw));
    }
}
fn report(revocation: &'static str) -> Report {
    Report {
        state: State::Consistent,
        checked_data_groups: vec![1],
        issuer_trust: "csca_verified",
        revocation,
        checked_at: Some(NOW),
        valid_until: Some(NOW + 60),
    }
}
#[test]
fn strict_result_requires_every_check_together_and_cannot_be_built_from_partial_success() {
    let result = authorize(report("good"), Some(mrz::claims(DG1).unwrap()), NOW).unwrap();
    assert_eq!(result.claims().birth_date_mrz, "690806");
    assert_eq!(result.evidence_valid_until(), NOW + 60);
    for state in [
        "missing",
        "stale",
        "invalid",
        "unsupported",
        "not_yet_valid",
        "not_checked",
    ] {
        assert!(matches!(
            authorize(report(state), Some(mrz::claims(DG1).unwrap()), NOW),
            Err(VerificationError::RevocationUnknown)
        ));
    }
    assert!(matches!(
        authorize(report("revoked"), Some(mrz::claims(DG1).unwrap()), NOW),
        Err(VerificationError::Revoked)
    ));
    let mut invalid = report("good");
    invalid.checked_data_groups = vec![1, 2];
    assert!(matches!(
        authorize(invalid, Some(mrz::claims(DG1).unwrap()), NOW),
        Err(VerificationError::InvalidEvidence)
    ));
    let mut expired = report("good");
    expired.valid_until = Some(NOW);
    assert!(matches!(
        authorize(expired, Some(mrz::claims(DG1).unwrap()), NOW),
        Err(VerificationError::InvalidTime)
    ));
    let mut future = report("good");
    future.checked_at = Some(NOW + 1);
    assert!(matches!(
        authorize(future, Some(mrz::claims(DG1).unwrap()), NOW),
        Err(VerificationError::InvalidTime)
    ));
    assert!(matches!(
        authorize(report("good"), None, NOW),
        Err(VerificationError::InvalidEvidence)
    ));
}
#[test]
fn framing_rejects_noncanonical_indefinite_and_overflowing_input_without_panics() {
    for bytes in [
        vec![0x77, 0x80],
        vec![0x77, 0x81, 0x7f],
        vec![0x77, 0x82, 0, 128],
        vec![0x77, 0xff],
        vec![0x77, 0x82, 0x21, 0],
    ] {
        assert!(encoding::value(&bytes, &mut 0, &[0x77]).is_err());
    }
    let mut offset = usize::MAX;
    assert!(encoding::value(&[], &mut offset, &[0x77]).is_err());
}
