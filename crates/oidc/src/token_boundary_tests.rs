use super::*;
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use serde_json::{Value, json};

const ENDPOINT: &str = "https://op.example/token";
const NOW: u64 = 1_000;

fn signing_key() -> SigningKey {
    SigningKey::from_slice(&[7; 32]).unwrap()
}
fn registered(client: &str, active: bool) -> ClientAssertionKey {
    ClientAssertionKey::new(
        client.into(),
        "registered-key".into(),
        2,
        3,
        active,
        signing_key()
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec(),
    )
}
fn claims() -> Value {
    json!({"iss":"rp","sub":"rp","aud":ENDPOINT,"iat":NOW,"exp":NOW+60,"jti":"operation-1"})
}
fn compact(header: &str, claims: &str, key: &SigningKey) -> String {
    let input = format!("{}.{}", B64.encode(header), B64.encode(claims));
    let signature: Signature = key.sign(input.as_bytes());
    format!("{input}.{}", B64.encode(signature.to_bytes()))
}
fn signed(claims: &Value) -> String {
    compact(
        r#"{"alg":"ES256","kid":"registered-key","typ":"JWT"}"#,
        &claims.to_string(),
        &signing_key(),
    )
}
fn verify(compact: &str) -> Result<VerifiedClientAssertion, InvalidClientAssertion> {
    registered("rp", true).verify_private_key_jwt(
        compact,
        ENDPOINT,
        NOW,
        ClientAssertionPolicy::from_seconds(60, 5).unwrap(),
        4096,
    )
}
fn token(client: &str, assertion: &str) -> TokenEndpointInput {
    serde_json::from_value(json!({
        "grant_type":"authorization_code", "code":B64.encode([4;32]),
        "redirect_uri":"https://rp.example/callback",
        "code_verifier":"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        "client_id":client, "client_assertion_type":PRIVATE_KEY_JWT_ASSERTION_TYPE,
        "client_assertion":assertion
    }))
    .unwrap()
}

#[test]
fn public_code_exchange_requires_pkce_and_rejects_confidential_credentials() {
    let form = format!(
        "grant_type=authorization_code&client_id=native-test&code={}&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        B64.encode([4; 32])
    );
    let input: PublicTokenEndpointInput = serde_urlencoded::from_str(&form).unwrap();
    let validated = input.validate().unwrap();
    assert_eq!(validated.client_id(), "native-test");
    assert_eq!(
        validated.exchange().pkce_challenge(),
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    );
    for invalid in [
        format!("{form}&client_secret=embedded"),
        format!("{form}&client_assertion=embedded"),
        format!("{form}&client_id=other"),
    ] {
        assert!(serde_urlencoded::from_str::<PublicTokenEndpointInput>(&invalid).is_err());
    }
    for invalid in [
        form.replace("authorization_code", "client_credentials"),
        form.replace("client_id=native-test", "client_id="),
        form.replace(
            "code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            "code_verifier=short",
        ),
    ] {
        let input: PublicTokenEndpointInput = serde_urlencoded::from_str(&invalid).unwrap();
        assert!(input.validate().is_err());
    }
}

#[test]
fn fapi_token_client_id_may_be_selected_from_assertion_but_must_verify() {
    let mut value = claims();
    value["aud"] = json!("https://op.example");
    let assertion = signed(&value);
    let mut form = json!({
        "grant_type":"authorization_code", "code":B64.encode([4;32]),
        "redirect_uri":"https://rp.example/callback",
        "code_verifier":"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        "client_assertion_type":PRIVATE_KEY_JWT_ASSERTION_TYPE,
        "client_assertion":assertion
    });
    let input: TokenEndpointInput = serde_json::from_value(form.clone()).unwrap();
    assert!(input.validate(4096).is_err());
    let input: TokenEndpointInput = serde_json::from_value(form.clone()).unwrap();
    let validated = input.validate_for_fapi(4096).unwrap();
    assert_eq!(validated.client_id(), "rp");
    let proof = registered("rp", true)
        .verify_fapi_private_key_jwt(&assertion, "https://op.example", NOW, 4096)
        .unwrap();
    assert!(validated.authenticate(proof, "https://op.example").is_ok());

    form["client_id"] = json!("other");
    let mismatch: TokenEndpointInput = serde_json::from_value(form.clone()).unwrap();
    let proof = registered("rp", true)
        .verify_fapi_private_key_jwt(&assertion, "https://op.example", NOW, 4096)
        .unwrap();
    assert!(
        mismatch
            .validate_for_fapi(4096)
            .unwrap()
            .authenticate(proof, "https://op.example")
            .is_err()
    );

    let mut missing_verifier = form.clone();
    missing_verifier
        .as_object_mut()
        .unwrap()
        .remove("code_verifier");
    let input: TokenEndpointInput = serde_json::from_value(missing_verifier).unwrap();
    assert!(matches!(
        input.validate_for_fapi(4096),
        Err(TokenEndpointInputError::InvalidGrant)
    ));
}

#[test]
fn private_key_assertion_uses_registered_key_and_preserves_binding_evidence() {
    let encoded = signed(&claims());
    assert_eq!(
        client_assertion_key_id(&encoded, 4096).unwrap(),
        "registered-key"
    );
    let proof = verify(&encoded).unwrap();
    assert_eq!(proof.client_id(), "rp");
    assert_eq!(proof.key_id(), "registered-key");
    assert_eq!(proof.client_revision(), 2);
    assert_eq!(proof.key_revision(), 3);
    assert_eq!(proof.audience(), ENDPOINT);
    assert_eq!(proof.jti(), "operation-1");
    assert_eq!(proof.issued_at(), NOW);
    assert_eq!(proof.retain_until(), NOW + 65);
    assert!(
        registered("other-rp", true)
            .verify_private_key_jwt(
                &encoded,
                ENDPOINT,
                NOW,
                ClientAssertionPolicy::from_seconds(60, 5).unwrap(),
                4096
            )
            .is_err()
    );
    assert!(
        registered("rp", false)
            .verify_private_key_jwt(
                &encoded,
                ENDPOINT,
                NOW,
                ClientAssertionPolicy::from_seconds(60, 5).unwrap(),
                4096
            )
            .is_err()
    );
    let other_key = SigningKey::from_slice(&[8; 32]).unwrap();
    assert!(
        verify(&compact(
            r#"{"alg":"ES256","kid":"registered-key"}"#,
            &claims().to_string(),
            &other_key
        ))
        .is_err()
    );
}

#[test]
fn private_key_assertion_rejects_rebinding_and_exact_expiry_boundaries() {
    for (field, value) in [
        ("iss", json!("other")),
        ("sub", json!("other")),
        ("aud", json!("https://other.example/token")),
        ("aud", json!([ENDPOINT, ENDPOINT])),
        ("jti", json!("")),
        ("jti", json!("line\nbreak")),
        ("exp", json!(NOW + 61)),
        ("iat", json!(NOW + 6)),
    ] {
        let mut value_claims = claims();
        value_claims[field] = value;
        assert!(verify(&signed(&value_claims)).is_err(), "{field}");
    }
    let mut expired = claims();
    expired["iat"] = json!(NOW - 60);
    expired["exp"] = json!(NOW - 5);
    assert!(verify(&signed(&expired)).is_err());
    expired["exp"] = json!(NOW - 4);
    assert!(verify(&signed(&expired)).is_ok());
    let mut one_audience = claims();
    one_audience["aud"] = json!([ENDPOINT]);
    assert!(verify(&signed(&one_audience)).is_ok());
    assert!(ClientAssertionPolicy::from_seconds(0, 5).is_err());
    assert!(ClientAssertionPolicy::from_seconds(60, 0).is_err());
    assert!(ClientAssertionPolicy::from_seconds(i64::MAX as u64, 1).is_err());
}

#[test]
fn fapi_assertion_requires_single_issuer_audience_and_bounded_iat_nbf() {
    let issuer = "https://op.example";
    let check = |value: &Value| {
        registered("rp", true).verify_fapi_private_key_jwt(&signed(value), issuer, NOW, 4096)
    };
    let mut value = claims();
    value["aud"] = json!(issuer);
    value["nbf"] = json!(NOW + 10);
    value["iat"] = json!(NOW + 10);
    value["exp"] = json!(NOW + 70);
    assert_eq!(check(&value).unwrap().audience(), issuer);
    assert!(
        verify(&signed(&value)).is_err(),
        "legacy endpoint contract stays separate"
    );
    for (field, replacement) in [
        ("aud", json!(ENDPOINT)),
        ("aud", json!([issuer])),
        ("aud", json!([issuer, issuer])),
        ("iat", json!(NOW + 11)),
        ("nbf", json!(NOW + 11)),
        ("nbf", json!(NOW + 71)),
        ("exp", json!(NOW + 71)),
    ] {
        let mut candidate = value.clone();
        candidate[field] = replacement;
        assert!(check(&candidate).is_err(), "{field}");
    }
    value["iat"] = json!(NOW);
    value["exp"] = json!(NOW + 60);
    value.as_object_mut().unwrap().remove("nbf");
    assert!(check(&value).is_ok());
}

#[test]
fn assertion_parser_rejects_duplicate_fields_untrusted_keys_and_noncanonical_segments() {
    for header in [
        r#"{"alg":"ES256","alg":"ES256","kid":"registered-key"}"#,
        r#"{"alg":"ES256","kid":"registered-key","jwk":{}}"#,
        r#"{"alg":"RS256","kid":"registered-key"}"#,
        r#"{"alg":"none","kid":"registered-key"}"#,
        r#"{"alg":"ES256","kid":"registered-key","typ":"logout+jwt"}"#,
    ] {
        let value = compact(header, &claims().to_string(), &signing_key());
        assert!(client_assertion_key_id(&value, 4096).is_err());
        assert!(verify(&value).is_err());
    }
    let duplicate = r#"{"iss":"rp","iss":"rp","sub":"rp","aud":"https://op.example/token","iat":1000,"exp":1060,"jti":"operation-1"}"#;
    assert!(
        verify(&compact(
            r#"{"alg":"ES256","kid":"registered-key"}"#,
            duplicate,
            &signing_key()
        ))
        .is_err()
    );
    let value = signed(&claims());
    assert!(client_assertion_key_id(&value, value.len() - 1).is_err());
    assert!(verify(&format!("{value}.extra")).is_err());
    assert!(verify(&format!("{value}=")).is_err());
}

#[test]
fn code_exchange_binds_pkce_client_and_verified_assertion_endpoint() {
    let compact = signed(&claims());
    let validated = token("rp", &compact).validate(4096).unwrap();
    assert_eq!(validated.client_id(), "rp");
    assert_eq!(validated.assertion().as_str(), compact);
    assert_eq!(
        validated.exchange().pkce_challenge(),
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    );
    assert_eq!(
        validated.exchange().redirect_uri(),
        "https://rp.example/callback"
    );
    let authenticated = validated
        .authenticate(verify(&compact).unwrap(), ENDPOINT)
        .unwrap();
    assert_eq!(authenticated.client_id(), "rp");
    assert_eq!(authenticated.assertion().key_revision(), 3);
    assert_eq!(
        authenticated.exchange().code_digest(),
        B64.encode(Sha256::digest([4; 32]))
    );
    assert!(
        token("other-rp", &compact)
            .validate(4096)
            .unwrap()
            .authenticate(verify(&compact).unwrap(), ENDPOINT)
            .is_err()
    );
    assert!(
        token("rp", &compact)
            .validate(4096)
            .unwrap()
            .authenticate(verify(&compact).unwrap(), "https://other.example/token")
            .is_err()
    );
    for (field, value, expected) in [
        (
            "grant_type",
            "refresh_token",
            TokenEndpointInputError::UnsupportedGrantType,
        ),
        (
            "client_assertion_type",
            "wrong",
            TokenEndpointInputError::InvalidClient,
        ),
        ("client_id", "", TokenEndpointInputError::InvalidClient),
        (
            "client_assertion",
            "",
            TokenEndpointInputError::InvalidClient,
        ),
        (
            "code",
            "not-a-code",
            TokenEndpointInputError::InvalidRequest,
        ),
        (
            "code_verifier",
            "short",
            TokenEndpointInputError::InvalidRequest,
        ),
        (
            "redirect_uri",
            "https://rp.example/\ncallback",
            TokenEndpointInputError::InvalidRequest,
        ),
    ] {
        let mut fields = json!({"grant_type":"authorization_code","code":B64.encode([4;32]),"redirect_uri":"https://rp.example/callback","code_verifier":"v".repeat(43),"client_id":"rp","client_assertion_type":PRIVATE_KEY_JWT_ASSERTION_TYPE,"client_assertion":compact});
        fields[field] = json!(value);
        let input: TokenEndpointInput = serde_json::from_value(fields).unwrap();
        assert!(
            matches!(input.validate(4096), Err(error) if error == expected),
            "{field}"
        );
    }
    let optional = || CodeExchangeInput {
        grant_type: "authorization_code".into(),
        code: B64.encode([4; 32]),
        redirect_uri: "https://rp.example/callback".into(),
        code_verifier: String::new(),
    };
    assert!(optional().validate().is_err());
    assert_eq!(
        optional()
            .validate_with_optional_pkce(true)
            .unwrap()
            .pkce_challenge(),
        ""
    );
}
