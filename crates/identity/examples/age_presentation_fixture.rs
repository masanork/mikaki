//! Synthetic age-only OID4VP vectors for the independent Node verifier.
use mikaki_identity::{
    card::{CardPreview, DocumentType},
    claim_profile::ClaimProfile,
    evidence::VerifiedDocument,
    issuance::{self, PublicJwk, Validity},
    mdoc,
    presentation::{self, VerifierRegistration},
};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use serde_json::json;
use std::io::Read;
fn main() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let issuer = "https://issuer.example/identity/issuer";
    let input: Option<serde_json::Value> = if std::env::args().any(|a| a == "--issued") {
        let mut raw = String::new();
        std::io::stdin().read_to_string(&mut raw).unwrap();
        Some(serde_json::from_str(&raw).unwrap())
    } else {
        None
    };
    let holder = if let Some(input) = &input {
        issuance::issuer_key(&input["holder_private_jwk"].to_string())
            .unwrap()
            .0
    } else {
        SigningKey::from_slice(&[2; 32]).unwrap()
    };
    let signer = SigningKey::from_slice(&[4; 32]).unwrap();
    let verifier = SigningKey::from_slice(&[5; 32]).unwrap();
    let holder_jwk = PublicJwk::from_key(holder.verifying_key());
    let registry = VerifierRegistration {
        client_id: "fixture-verifier".into(),
        name: "Age verifier".into(),
        response_uri: "https://verifier.example/response".into(),
        kid: "fixture-verifier-key".into(),
        jwk: PublicJwk::from_key(verifier.verifying_key()),
        certificate_trust: None,
        response_encryption: None,
        profile: presentation::Profile::Oid4vpFinal,
    };
    let document = VerifiedDocument {
        attributes: CardPreview {
            name: "Private Fixture Person".into(),
            address: "Private fixture address".into(),
            birth_date: "1990-02-28".into(),
            gender: "1".into(),
            verification: "issuer_signed_static_data".into(),
            document_type: DocumentType::MyNumberCard,
            expiry_date: None,
            backend_verifiable: true,
        },
        trusted_key_id: "fixture-card-issuer".into(),
        verified_at: now - 60,
        assurance: "issuer_signed_static_data".into(),
        attributes_source: "input_support_ef".into(),
    };
    let validity = Validity::new(&document, now, u64::MAX).unwrap();
    let profile = ClaimProfile::age_only();
    let sd = if let Some(input) = &input {
        input["sd"].as_str().unwrap().to_string()
    } else {
        issuance::issue_with_profile(
            &signer,
            "fixture-issuer",
            issuer,
            &holder_jwk,
            &document,
            validity,
            &[[1; 16], [2; 16]],
            &profile,
        )
        .unwrap()
    };
    let m = if let Some(input) = &input {
        input["mdoc"].as_str().unwrap().to_string()
    } else {
        mdoc::issue_with_profile(
            &signer,
            include_bytes!("../tests/fixtures/mdoc-ds.der"),
            &holder_jwk,
            &document,
            validity,
            &[[3; 16], [4; 16]],
            &profile,
        )
        .unwrap()
    };
    let kid = input
        .as_ref()
        .and_then(|i| i["issuer_kid"].as_str())
        .unwrap_or("fixture-issuer");
    let sd_values = issuance::verify_receipt(
        &sd,
        &PublicJwk::from_key(signer.verifying_key()),
        kid,
        &holder_jwk,
        issuer,
        now,
    )
    .unwrap();
    let mut outputs = vec![];
    for (format, credential) in [("dc+sd-jwt", &sd), ("mso_mdoc", &m)] {
        let request_claims = json!({"iss":registry.client_id,"aud":"https://self-issued.me/v2","client_id":registry.client_id,
            "response_type":"vp_token","response_mode":"direct_post","response_uri":registry.response_uri,
            "nonce":"N".repeat(43),"state":"S".repeat(43),"iat":now,"exp":now+120,
            "dcql_query":{"credentials":[{"id":"age","format":format,
                "meta":if format == "dc+sd-jwt" { json!({"vct_values":[format!("{issuer}/types/linked-document")]}) } else { json!({"doctype_value":mdoc::DOCTYPE}) },
                "claims":[{"path":if format == "dc+sd-jwt" { vec!["age_over_18"] } else { vec![mdoc::NAMESPACE,"age_over_18"] }}]}]}});
        let request = issuance::sign_jwt(
            &verifier,
            json!({"typ":"oauth-authz-req+jwt","alg":"ES256","kid":registry.kid}),
            request_claims.clone(),
        )
        .unwrap();
        let approved = presentation::verify_request(
            &request,
            std::slice::from_ref(&registry),
            &format!("{issuer}/types/linked-document"),
            now,
        )
        .unwrap();
        let (presentation, values) = if format == "dc+sd-jwt" {
            let (selected, values) =
                presentation::select_disclosures(credential, &approved).unwrap();
            (
                presentation::present(&holder, &selected, &approved, now).unwrap(),
                values,
            )
        } else {
            let receipt = mdoc::verify_receipt(
                credential,
                &PublicJwk::from_key(signer.verifying_key()),
                &holder_jwk,
                now,
            )
            .unwrap();
            let transcript = mdoc::oid4vp_transcript(
                &registry.client_id,
                request_claims["nonce"].as_str().unwrap(),
                &registry.response_uri,
            )
            .unwrap();
            let input = mdoc::device_authentication(&transcript).unwrap();
            let signature: Signature = holder.sign(&mdoc::signature_input(&input).unwrap());
            (
                mdoc::device_response(
                    &receipt,
                    &approved.fields,
                    &transcript,
                    &signature.to_bytes(),
                    &holder_jwk,
                )
                .unwrap(),
                mdoc::selected_values(&receipt, &approved.fields).unwrap(),
            )
        };
        let mut mismatches = Vec::new();
        for names in [vec!["birthdate"], vec!["age_over_18", "birthdate"]] {
            let mut unavailable = request_claims.clone();
            unavailable["dcql_query"]["credentials"][0]["claims"] = json!(names.into_iter().map(|name|
            json!({"path":if format == "dc+sd-jwt" {vec![name]} else {vec![mdoc::NAMESPACE,name]}})).collect::<Vec<_>>());
            let bad = issuance::sign_jwt(
                &verifier,
                json!({"typ":"oauth-authz-req+jwt","alg":"ES256","kid":registry.kid}),
                unavailable,
            )
            .unwrap();
            let bad = presentation::verify_request(
                &bad,
                std::slice::from_ref(&registry),
                &format!("{issuer}/types/linked-document"),
                now,
            )
            .unwrap();
            let mismatch = if format == "dc+sd-jwt" {
                presentation::select_disclosures(credential, &bad)
                    .unwrap_err()
                    .to_string()
            } else {
                let receipt = mdoc::verify_receipt(
                    credential,
                    &PublicJwk::from_key(signer.verifying_key()),
                    &holder_jwk,
                    now,
                )
                .unwrap();
                mdoc::selected_values(&receipt, &bad.fields)
                    .unwrap_err()
                    .to_string()
            };
            mismatches.push(mismatch);
        }
        outputs.push(json!({"format":format,"credential":credential,"request":request,"request_claims":request_claims,
            "presentation":presentation,"values":values,"mismatches":mismatches}));
    }
    println!(
        "{}",
        json!({"issuer":issuer,"issuer_jwk":PublicJwk::from_key(signer.verifying_key()),
        "holder_jwk":holder_jwk,"registry":registry,"now":now,"source_verified_at":sd_values["evidence"]["source_verified_at"],"vectors":outputs})
    );
}
