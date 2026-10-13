use mikaki_identity::{
    card::{CardPreview, DocumentType},
    evidence::VerifiedDocument,
    op_age::{AgeRequest, Error, TRUST_FRAMEWORK_CANDIDATE, consumer_evidence},
};
use serde_json::{Value, json};
const NOW: u64 = 1791849600; // 2026-10-13T00:00:00Z
fn document() -> VerifiedDocument {
    VerifiedDocument {
        attributes: CardPreview {
            name: "Private Name".into(),
            address: "Private Address".into(),
            birth_date: "2008-10-13".into(),
            gender: "1".into(),
            verification: "issuer_signed_static_data".into(),
            document_type: DocumentType::MyNumberCard,
            expiry_date: None,
            backend_verifiable: true,
        },
        trusted_key_id: "operator-pinned-card-key".into(),
        verified_at: NOW - 60,
        assurance: "issuer_signed_static_data".into(),
        attributes_source: "input_support_ef".into(),
    }
}
fn claims() -> Value {
    json!({"userinfo":{"verified_claims":{"verification":{"trust_framework":{"value":TRUST_FRAMEWORK_CANDIDATE}},
        "claims":{":age_over_18":null}}},"_asc":{"transformed_claims":{
        "age_over_18":{"claim":"birthdate","fn":["years_ago",["gte",18]]},
        "age_over_20":{"claim":"birthdate","fn":["years_ago",["gte",20]]}}}})
}
fn parse(v: Value) -> AgeRequest {
    AgeRequest::parse(&serde_json::to_vec(&v).unwrap()).unwrap()
}

#[test]
fn asc_projection_selects_only_requested_predicate_with_exact_derivation_consent() {
    let request = parse(claims());
    assert_eq!(request.consent_fields(), ["age_over_18"]);
    let consent = vec!["age_over_18".into()];
    assert_eq!(
        request.project(&document(), &consent, NOW).unwrap(),
        json!({":age_over_18":true})
    );
    assert_eq!(
        request.project(&document(), &consent, NOW - 1).unwrap(),
        json!({":age_over_18":false})
    );
    assert_eq!(
        request.project(&document(), &[], NOW),
        Err(Error::ConsentRequired)
    );
    assert_eq!(
        request.project(&document(), &["birthdate".into()], NOW),
        Err(Error::ConsentRequired)
    );
    let mut both = claims();
    both["userinfo"]["verified_claims"]["claims"][":age_over_20"] = Value::Null;
    let request = parse(both);
    assert_eq!(
        request.project(&document(), &consent, NOW),
        Err(Error::ConsentRequired)
    );
    assert_eq!(
        request
            .project(
                &document(),
                &["age_over_18".into(), "age_over_20".into()],
                NOW
            )
            .unwrap(),
        json!({":age_over_18":true,":age_over_20":false})
    );
}

#[test]
fn unknown_functions_sources_reference_dates_frameworks_and_raw_claims_fail_closed() {
    for (pointer, value) in [
        ("/_asc/transformed_claims/age_over_18/claim", json!("name")),
        (
            "/_asc/transformed_claims/age_over_18/fn",
            json!(["years_ago", ["gte", 12]]),
        ),
        (
            "/_asc/transformed_claims/age_over_18/fn",
            json!(["hash", ["gte", 18]]),
        ),
        (
            "/_asc/transformed_claims/age_over_18/fn",
            json!([["years_ago", "2099-01-01"], ["gte", 18]]),
        ),
        (
            "/_asc/transformed_claims/age_over_18/fn",
            json!(["years_ago", ["gte", "18"]]),
        ),
        (
            "/_asc/transformed_claims/age_over_18/fn",
            json!(["years_ago", ["gte", 18.0]]),
        ),
        (
            "/_asc/transformed_claims/age_over_18/fn",
            json!(["years_ago", ["gte", 18], "any"]),
        ),
        (
            "/userinfo/verified_claims/verification/trust_framework",
            json!({"value":"eidas"}),
        ),
        (
            "/userinfo/verified_claims/claims",
            json!({"birthdate":null}),
        ),
        ("/userinfo/verified_claims/claims", json!({":missing":null})),
        (
            "/userinfo/verified_claims/claims",
            json!({"::age_over_18":null}),
        ),
        (
            "/userinfo/verified_claims/claims",
            json!({":age_over_18":{"essential":null}}),
        ),
        (
            "/userinfo/verified_claims/claims",
            json!({":age_over_18":{"value":"true"}}),
        ),
        (
            "/userinfo/verified_claims/claims",
            json!({":age_over_18":{"value":null}}),
        ),
        (
            "/userinfo/verified_claims/claims",
            json!({":age_over_18":{"values":[true]}}),
        ),
        ("/userinfo/verified_claims/claims", json!({})),
    ] {
        let mut input = claims();
        *input.pointer_mut(pointer).unwrap() = value;
        assert!(
            matches!(
                AgeRequest::parse(&serde_json::to_vec(&input).unwrap()),
                Err(Error::InvalidRequest)
            ),
            "{pointer}: {input}"
        );
    }
    for (key, value) in [
        ("id_token", json!({"birthdate":null})),
        ("other", json!({})),
    ] {
        let mut input = claims();
        input[key] = value;
        assert!(AgeRequest::parse(&serde_json::to_vec(&input).unwrap()).is_err());
    }
    let mut sao = claims();
    sao["_asc"]["sao"] = json!({});
    assert!(AgeRequest::parse(&serde_json::to_vec(&sao).unwrap()).is_err());
    let mut extra = claims();
    extra["_asc"]["transformed_claims"]["third"] =
        json!({"claim":"birthdate","fn":["years_ago",["gte",18]]});
    assert!(AgeRequest::parse(&serde_json::to_vec(&extra).unwrap()).is_err());
    let mut source = claims();
    source["userinfo"]["birthdate"] = Value::Null;
    assert!(AgeRequest::parse(&serde_json::to_vec(&source).unwrap()).is_err());
    assert!(AgeRequest::parse(&vec![b' '; 4097]).is_err());
    let raw = serde_json::to_string(&claims()).unwrap();
    let duplicate = raw.replacen(
        "\"claim\":\"birthdate\"",
        "\"claim\":\"name\",\"cl\\u0061im\":\"birthdate\"",
        1,
    );
    assert!(AgeRequest::parse(duplicate.as_bytes()).is_err());
}

#[test]
fn constraints_and_unavailable_evidence_never_return_a_partial_projection() {
    let mut input = claims();
    input["userinfo"]["verified_claims"]["claims"][":age_over_18"] =
        json!({"essential":true,"value":true});
    let request = parse(input);
    let consent = vec!["age_over_18".into()];
    assert_eq!(
        request.project(&document(), &consent, NOW - 1),
        Err(Error::ClaimUnavailable)
    );
    for birthday in ["0000-01-01", "2008-02-30", "2027-01-01"] {
        let mut doc = document();
        doc.attributes.birth_date = birthday.into();
        assert_eq!(
            request.project(&doc, &consent, NOW),
            Err(Error::ClaimUnavailable)
        );
    }
    let mut advisory = document();
    advisory.assurance = "holder_device_advisory".into();
    assert_eq!(
        request.project(&advisory, &consent, NOW),
        Err(Error::ClaimUnavailable)
    );
    assert_eq!(
        consumer_evidence(&advisory, NOW),
        Err(Error::ClaimUnavailable)
    );
    let mut future = document();
    future.verified_at = NOW + 1;
    assert_eq!(
        consumer_evidence(&future, NOW),
        Err(Error::ClaimUnavailable)
    );
}

#[test]
fn consumer_evidence_has_only_provenance_and_preserves_static_assurance() {
    let mut doc = document();
    for kind in [DocumentType::MyNumberCard, DocumentType::DrivingLicense] {
        doc.attributes.document_type = kind;
        let evidence = consumer_evidence(&doc, NOW).unwrap();
        assert_eq!(evidence["type"], "electronic_record");
        assert_eq!(evidence["check_details"][0]["check_method"], "data");
        assert_eq!(evidence["check_details"][0]["time"], "2026-10-12T23:59:00Z");
        assert_eq!(
            evidence["_mikaki"]["predicate_verified_at"],
            "2026-10-13T00:00:00Z"
        );
        assert_eq!(evidence["_mikaki"]["verifier"], "consumer");
        assert_eq!(
            evidence["_mikaki"]["assurance"],
            "issuer_signed_static_data"
        );
        for flag in [
            "live_possession_verified",
            "revocation_checked",
            "government_credential",
        ] {
            assert_eq!(evidence["_mikaki"][flag], false);
        }
        let raw = serde_json::to_string(&evidence).unwrap();
        for absent in [
            "Private",
            "2008-10-13",
            "DF31",
            "DF32",
            "DF33",
            "reader_id",
            "document_number",
        ] {
            assert!(!raw.contains(absent), "{absent}");
        }
        assert!(evidence.get("_civ").is_none());
    }
}
