use mikaki_identity::{
    card::{CardPreview, DocumentType},
    claim_profile::{Claim, ClaimProfile, age_over},
    evidence::VerifiedDocument,
    issuance::{self, PublicJwk, Validity},
    mdoc,
};
use p256::ecdsa::SigningKey;
use serde_json::json;

fn at(date: &str) -> u64 {
    mikaki_identity::evidence::date_end(date).unwrap() - 86400
}
fn document(birth: &str) -> VerifiedDocument {
    VerifiedDocument {
        attributes: CardPreview {
            name: "Private Name".into(),
            address: "Private Address".into(),
            birth_date: birth.into(),
            gender: "1".into(),
            verification: "issuer_signed_static_data".into(),
            document_type: DocumentType::MyNumberCard,
            expiry_date: None,
            backend_verifiable: true,
        },
        trusted_key_id: "fixture".into(),
        verified_at: at("2026-10-12"),
        assurance: "issuer_signed_static_data".into(),
        attributes_source: "input_support_ef".into(),
    }
}

#[test]
fn utc_calendar_age_is_inclusive_and_invalid_dates_never_yield_predicates() {
    let birthday = at("2026-10-13");
    for n in [18, 20] {
        let birth = format!("{}-10-13", 2026 - n);
        assert_eq!(age_over(&birth, birthday - 1, n), Some(false));
        assert_eq!(age_over(&birth, birthday, n), Some(true));
        assert_eq!(age_over(&birth, birthday + 86399, n), Some(true));
    }
    assert_eq!(age_over("2008-02-29", at("2026-02-28"), 18), Some(false));
    assert_eq!(age_over("2008-02-29", at("2026-03-01"), 18), Some(true));
    assert_eq!(age_over("2004-02-29", at("2024-02-29"), 20), Some(true));
    assert_eq!(age_over("1900-02-28", birthday, 20), Some(true));
    for bad in [
        "",
        "2008-02-30",
        "1900-02-29",
        "2008-00-01",
        "0000-01-01",
        "+008-01-01",
        "2008-1-1",
        "令和元年",
        "2027-01-01",
    ] {
        assert_eq!(age_over(bad, birthday, 18), None, "{bad}");
        assert!(
            ClaimProfile::age_only()
                .values(&document(bad), birthday)
                .is_empty()
        );
    }
    assert_eq!(age_over("1990-01-01", u64::MAX, 18), None);
}

#[test]
fn both_formats_issue_only_independent_boolean_predicates_with_static_assurance() {
    let time = at("2026-10-13") + 45;
    let doc = document("2008-10-13");
    let validity = Validity::new(&doc, time, u64::MAX)
        .unwrap()
        .rounded_minutes(0)
        .unwrap();
    let signer = SigningKey::from_slice(&[4; 32]).unwrap();
    let issuer = PublicJwk::from_key(signer.verifying_key());
    let holder = PublicJwk::from_key(SigningKey::from_slice(&[2; 32]).unwrap().verifying_key());
    let profile = ClaimProfile::age_only();
    let sd = issuance::issue_with_profile(
        &signer,
        "fixture",
        "https://issuer.example",
        &holder,
        &doc,
        validity,
        &[[1; 16], [2; 16]],
        &profile,
    )
    .unwrap();
    let values = issuance::verify_receipt(
        &sd,
        &issuer,
        "fixture",
        &holder,
        "https://issuer.example",
        time,
    )
    .unwrap();
    assert_eq!(values["age_over_18"], true);
    assert_eq!(values["age_over_20"], false);
    assert_eq!(values["_sd"].as_array().unwrap().len(), 2);
    for name in [
        "name",
        "address",
        "birthdate",
        "gender",
        "document_expiry_date",
    ] {
        assert!(values.get(name).is_none());
    }
    let evidence = &values["evidence"];
    assert_eq!(evidence["verified_at"], time);
    assert_eq!(evidence["source_verified_at"], doc.verified_at);
    assert_eq!(evidence["assurance"], "issuer_signed_static_data");
    assert_eq!(evidence["live_possession_verified"], false);
    assert_eq!(evidence["government_credential"], false);
    assert_eq!(evidence["predicate_source"], "birthdate");
    let m = mdoc::issue_with_profile(
        &signer,
        include_bytes!("fixtures/mdoc-ds.der"),
        &holder,
        &doc,
        validity,
        &[[1; 16], [2; 16]],
        &profile,
    )
    .unwrap();
    let verified = mdoc::verify_receipt(&m, &issuer, &holder, time).unwrap();
    assert_eq!(
        verified.values,
        json!({"age_over_18":true,"age_over_20":false})
    );
    let provenance = verified.evidence.unwrap();
    for (name, value) in evidence.as_object().unwrap() {
        assert_eq!(&provenance[name], value);
    }
    assert_eq!(provenance["document_type"], "my_number_card");
    assert_eq!(
        mdoc::selected_values(
            &mdoc::verify_receipt(&m, &issuer, &holder, time).unwrap(),
            &["birthdate".into()]
        )
        .unwrap_err(),
        "credential_does_not_match"
    );
}

#[test]
fn profiles_choose_each_raw_attribute_independently_and_reject_invalid_configuration() {
    let doc = document("2008-10-13");
    let time = at("2026-10-13");
    let signer = SigningKey::from_slice(&[4; 32]).unwrap();
    let issuer = PublicJwk::from_key(signer.verifying_key());
    let holder = PublicJwk::from_key(SigningKey::from_slice(&[2; 32]).unwrap().verifying_key());
    let raw = [Claim::Name, Claim::Address, Claim::Birthdate, Claim::Gender];
    for mask in 0..16 {
        let mut claims = vec![Claim::AgeOver18];
        claims.extend(
            raw.iter()
                .enumerate()
                .filter(|(i, _)| mask & (1 << i) != 0)
                .map(|(_, c)| *c),
        );
        let profile = ClaimProfile::new(claims).unwrap();
        let salts = vec![[1; 16]; profile.values(&doc, time).len()];
        let validity = Validity::new(&doc, time, u64::MAX).unwrap();
        let sd = issuance::issue_with_profile(
            &signer,
            "fixture",
            "https://issuer.example",
            &holder,
            &doc,
            validity,
            &salts,
            &profile,
        )
        .unwrap();
        let values = issuance::verify_receipt(
            &sd,
            &issuer,
            "fixture",
            &holder,
            "https://issuer.example",
            time,
        )
        .unwrap();
        let m = mdoc::issue_with_profile(
            &signer,
            include_bytes!("fixtures/mdoc-ds.der"),
            &holder,
            &doc,
            validity,
            &salts,
            &profile,
        )
        .unwrap();
        let mv = mdoc::verify_receipt(&m, &issuer, &holder, time)
            .unwrap()
            .values;
        for (i, c) in raw.iter().enumerate() {
            assert_eq!(values.get(c.name()).is_some(), mask & (1 << i) != 0);
            assert_eq!(mv.get(c.name()).is_some(), mask & (1 << i) != 0);
        }
    }
    for bad in [
        "[]",
        "null",
        "{}",
        "[\"unknown\"]",
        "[\"age_over_18\",\"age_over_18\"]",
    ] {
        assert!(ClaimProfile::from_json(bad).is_err(), "{bad}");
    }
    assert_eq!(
        ClaimProfile::from_json("[\"age_over_18\"]")
            .unwrap()
            .values(&doc, time),
        vec![("age_over_18", json!(true))]
    );
    let invalid = document("2008-02-30");
    assert_eq!(
        issuance::issue_with_profile(
            &signer,
            "fixture",
            "https://issuer.example",
            &holder,
            &invalid,
            Validity::new(&invalid, time, u64::MAX).unwrap(),
            &[],
            &ClaimProfile::age_only()
        )
        .unwrap_err(),
        "no_issuable_claims"
    );
}
