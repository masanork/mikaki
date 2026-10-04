//! Disposable, synthetic interoperability vector. Contains no real card or production keys.
use mikaki_identity::{
    card::{CardPreview, DocumentType},
    evidence::VerifiedDocument,
    issuance::{self, PublicJwk},
    presentation::{self, VerifierRegistration},
};
use p256::ecdsa::SigningKey;
use serde_json::json;
fn main() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let issuer = "https://issuer.example/identity/issuer";
    let holder = SigningKey::from_slice(&[2; 32]).unwrap();
    let issuer_key = SigningKey::from_slice(&[4; 32]).unwrap();
    let verifier = SigningKey::from_slice(&[5; 32]).unwrap();
    let registry = VerifierRegistration {
        client_id: "fixture-verifier".into(),
        name: "Fixture only".into(),
        response_uri: "https://verifier.example/response".into(),
        kid: "fixture-verifier-key".into(),
        jwk: PublicJwk::from_key(verifier.verifying_key()),
        certificate_trust: None,
        response_encryption: None,
        profile: mikaki_identity::presentation::Profile::Oid4vpFinal,
    };
    let request_claims = json!({"iss":registry.client_id,"aud":"https://self-issued.me/v2","client_id":registry.client_id,"response_type":"vp_token","response_mode":"direct_post","response_uri":registry.response_uri,"nonce":"N".repeat(43),"state":"S".repeat(43),"iat":now,"exp":now+120,"dcql_query":{"credentials":[{"id":"identity","format":"dc+sd-jwt","meta":{"vct_values":[format!("{issuer}/types/linked-document")]},"claims":[{"path":["name"]},{"path":["birthdate"]}]}]}});
    let request = issuance::sign_jwt(
        &verifier,
        json!({"typ":"oauth-authz-req+jwt","alg":"ES256","kid":registry.kid}),
        request_claims.clone(),
    )
    .unwrap();
    let document = VerifiedDocument {
        attributes: CardPreview {
            name: "Fixture Person".into(),
            address: "Private fixture address".into(),
            birth_date: "1990-02-28".into(),
            gender: "1".into(),
            verification: "issuer_signed_static_data".into(),
            document_type: DocumentType::MyNumberCard,
            expiry_date: None,
            backend_verifiable: true,
        },
        trusted_key_id: "fixture-card-issuer".into(),
        verified_at: now,
        assurance: "issuer_signed_static_data".into(),
        attributes_source: "input_support_ef".into(),
    };
    let holder_jwk = PublicJwk::from_key(holder.verifying_key());
    let credential = issuance::issue(
        &issuer_key,
        "fixture-issuer",
        issuer,
        &holder_jwk,
        &document,
        now,
        &[[1; 16], [2; 16], [3; 16], [4; 16]],
    )
    .unwrap();
    let approved = presentation::verify_request(
        &request,
        std::slice::from_ref(&registry),
        &format!("{issuer}/types/linked-document"),
        now,
    )
    .unwrap();
    let (selected, values) = presentation::select_disclosures(&credential, &approved).unwrap();
    let vp = presentation::present(&holder, &selected, &approved, now).unwrap();
    let certificate = include_bytes!("../tests/fixtures/mdoc-ds.der");
    let mdoc_credential = mikaki_identity::mdoc::issue(
        &issuer_key,
        certificate,
        &holder_jwk,
        &document,
        now,
        &[[1; 16], [2; 16], [3; 16], [4; 16]],
    )
    .unwrap();
    let validated = mikaki_identity::mdoc::verify_receipt(
        &mdoc_credential,
        &PublicJwk::from_key(issuer_key.verifying_key()),
        &holder_jwk,
        now,
    )
    .unwrap();
    let transcript = mikaki_identity::mdoc::oid4vp_transcript(
        &registry.client_id,
        &"N".repeat(43),
        &registry.response_uri,
    )
    .unwrap();
    let auth = mikaki_identity::mdoc::device_authentication(&transcript).unwrap();
    use p256::ecdsa::signature::Signer;
    let device_sig: p256::ecdsa::Signature =
        holder.sign(&mikaki_identity::mdoc::signature_input(&auth).unwrap());
    let mdoc_response = mikaki_identity::mdoc::device_response(
        &validated,
        &["name".into(), "birthdate".into()],
        &transcript,
        &device_sig.to_bytes(),
        &holder_jwk,
    )
    .unwrap();
    use base64::Engine;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let recipient = SigningKey::from_slice(&[6; 32]).unwrap();
    let mut encrypted_registry = registry.clone();
    encrypted_registry.response_encryption = Some(presentation::encryption::ResponseEncryption {
        kid: "fixture-recipient".into(),
        alg: "ECDH-ES".into(),
        enc: "A256GCM".into(),
        jwk: PublicJwk::from_key(recipient.verifying_key()),
    });
    let mut encrypted_claims = request_claims.clone();
    encrypted_claims["response_mode"] = json!("direct_post.jwt");
    let encrypt = |token: &str, checked: &presentation::ApprovedRequest| {
        use rand_core::{OsRng, RngCore};
        let mut iv = [0; 12];
        OsRng.fill_bytes(&mut iv);
        presentation::encryption::encrypt_response(
            token,
            checked,
            now,
            p256::SecretKey::random(&mut OsRng),
            iv,
        )
        .unwrap()
    };
    let signed_request = |claims| {
        issuance::sign_jwt(
            &verifier,
            json!({"typ":"oauth-authz-req+jwt","alg":"ES256","kid":registry.kid}),
            claims,
        )
        .unwrap()
    };
    let sd_request = signed_request(encrypted_claims.clone());
    let sd_checked = presentation::verify_request(
        &sd_request,
        std::slice::from_ref(&encrypted_registry),
        &format!("{issuer}/types/linked-document"),
        now,
    )
    .unwrap();
    let encrypted_sd = encrypt(&vp, &sd_checked);
    encrypted_claims["dcql_query"] = json!({"credentials":[{"id":"identity","format":"mso_mdoc","meta":{"doctype_value":mikaki_identity::mdoc::DOCTYPE},"claims":[{"path":[mikaki_identity::mdoc::NAMESPACE,"name"]},{"path":[mikaki_identity::mdoc::NAMESPACE,"birthdate"]}]}]});
    let encrypted_request = signed_request(encrypted_claims);
    let mdoc_checked = presentation::verify_request(
        &encrypted_request,
        std::slice::from_ref(&encrypted_registry),
        &format!("{issuer}/types/linked-document"),
        now,
    )
    .unwrap();
    let encrypted_transcript = mdoc_checked.mdoc_transcript().unwrap();
    let encrypted_auth =
        mikaki_identity::mdoc::device_authentication(&encrypted_transcript).unwrap();
    let sig: p256::ecdsa::Signature =
        holder.sign(&mikaki_identity::mdoc::signature_input(&encrypted_auth).unwrap());
    let encrypted_mdoc_vp = mikaki_identity::mdoc::device_response(
        &validated,
        &mdoc_checked.fields,
        &encrypted_transcript,
        &sig.to_bytes(),
        &holder_jwk,
    )
    .unwrap();
    let encrypted_mdoc = encrypt(&encrypted_mdoc_vp, &mdoc_checked);
    let encrypted_mdoc_again = encrypt(&encrypted_mdoc_vp, &mdoc_checked);
    let mut legacy_registry = encrypted_registry.clone();
    legacy_registry.profile = presentation::Profile::Oid4vpDraft18Mdoc;
    let legacy_claims = json!({"iss":registry.client_id,"aud":"https://self-issued.me/v2","client_id":registry.client_id,"client_id_scheme":"pre-registered","response_type":"vp_token","response_mode":"direct_post.jwt","response_uri":registry.response_uri,"nonce":"N".repeat(43),"state":"S".repeat(43),"iat":now,"exp":now+120,"require_signed_request_object":true,"presentation_definition":{"id":"legacy-definition","input_descriptors":[{"id":mikaki_identity::mdoc::DOCTYPE,"format":{"mso_mdoc":{"alg":["ES256"]}},"constraints":{"limit_disclosure":"required","fields":[{"path":[format!("$['{}']['name']",mikaki_identity::mdoc::NAMESPACE)],"intent_to_retain":true}]}}]}});
    let legacy_request = signed_request(legacy_claims);
    let mut legacy_nonce = [0; 32];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut legacy_nonce);
    let legacy = presentation::verify_request_with_wallet_nonce(
        &legacy_request,
        std::slice::from_ref(&legacy_registry),
        "",
        now,
        legacy_nonce,
    )
    .unwrap();
    let legacy_transcript = legacy.mdoc_transcript().unwrap();
    let legacy_auth = mikaki_identity::mdoc::device_authentication(&legacy_transcript).unwrap();
    let sig: p256::ecdsa::Signature =
        holder.sign(&mikaki_identity::mdoc::signature_input(&legacy_auth).unwrap());
    let legacy_vp = mikaki_identity::mdoc::device_response(
        &validated,
        &legacy.fields,
        &legacy_transcript,
        &sig.to_bytes(),
        &holder_jwk,
    )
    .unwrap();
    let legacy_response = encrypt(&legacy_vp, &legacy);
    let standard = base64::engine::general_purpose::STANDARD;
    let certificate_chain = vec![
        standard.encode(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/trust/leaf.der"
        ))),
        standard.encode(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/trust/intermediate.der"
        ))),
    ];
    let certificate_root = standard.encode(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/trust/root.der"
    )));
    let mut certificate_registry = registry.clone();
    certificate_registry.certificate_trust = Some(mikaki_identity::certificate::ReaderTrust {
        trust_anchors: vec![certificate_root.clone()],
        dns_name: Some("verifier.example".into()),
        revocation: None,
    });
    let certificate_request = issuance::sign_jwt(&verifier, json!({"typ":"oauth-authz-req+jwt","alg":"ES256","kid":registry.kid,"x5c":certificate_chain}), request_claims.clone()).unwrap();
    presentation::verify_request(
        &certificate_request,
        &[certificate_registry.clone()],
        &format!("{issuer}/types/linked-document"),
        now,
    )
    .unwrap();
    println!(
        "{}",
        json!({"certificate_request":certificate_request,"certificate_registry":certificate_registry,"certificate_root":certificate_root,"certificate_chain":certificate_chain,"legacy_response":legacy_response,"legacy_request":legacy_request,"encrypted_sd":encrypted_sd,"encrypted_mdoc":encrypted_mdoc,"encrypted_mdoc_again":encrypted_mdoc_again,"encryption_registry":encrypted_registry,"encrypted_request":encrypted_request,"mdoc_credential":mdoc_credential,"mdoc_response":mdoc_response,"mdoc_transcript":b64.encode(&transcript),"mdoc_authentication":b64.encode(&auth),"now":now,"issuer":issuer,"issuer_jwk":PublicJwk::from_key(issuer_key.verifying_key()),"holder_jwk":holder_jwk,"registry":registry,"request":request,"request_claims":request_claims,"credential":credential,"selected":selected,"values":values,"presentation":vp,"response":presentation::response_body(&vp,&approved)})
    );
}
