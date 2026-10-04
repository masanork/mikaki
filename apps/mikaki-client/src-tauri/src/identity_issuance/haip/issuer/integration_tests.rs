use super::*;
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD as B64},
    Engine,
};
use mikaki_identity::issuance_encryption::{
    decrypt_request, encrypt_response, RequestKey, ResponseEncryption,
};
use p256::ecdsa::{signature::Verifier, Signature, SigningKey};
use std::sync::Mutex;
fn key(n: u8) -> HolderKey {
    HolderKey::Memory(SigningKey::from_slice(&[n; 32]).unwrap())
}
fn credential_cert(name: &str) -> String {
    STANDARD.encode(
        std::fs::read(format!(
            "{}/../../../crates/identity/tests/fixtures/credential/{name}.der",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap(),
    )
}
pub(crate) fn credential_trust() -> identity_wallet::CredentialTrust {
    serde_json::from_value(json!({"sd_jwt":{"trust_anchors":[credential_cert("sd-ca")]},"mdoc":{"trust_anchors":[credential_cert("mdoc-ca")]}})).unwrap()
}
fn cert(name: &str) -> String {
    STANDARD.encode(
        std::fs::read(format!(
            "{}/../../../crates/identity/tests/fixtures/trust/{name}.der",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap(),
    )
}
fn fixture(configuration: &str) -> (Session, String, Vec<AttesterTrust>) {
    let session =
        Session::from_keys("native", CALLBACK, configuration, key(1), key(2), key(3)).unwrap();
    let authority = SigningKey::from_slice(&[5; 32]).unwrap();
    let at = now().unwrap();
    let attestation=issuance::sign_jwt(&authority,json!({"typ":"oauth-client-attestation+jwt","alg":"ES256","x5c":[cert("attester"),cert("intermediate")]}),
        json!({"iss":format!("{ROOT}/identity/attester"),"sub":"native","cnf":{"jwk":session.instance.public().unwrap()},"iat":at,"exp":at+300})).unwrap();
    (
        session,
        attestation,
        vec![AttesterTrust {
            issuer: format!("{ROOT}/identity/attester"),
            trust_anchors: vec![cert("root")],
        }],
    )
}
fn response(status: u16, body: Value, nonce: Option<&str>) -> Response {
    let mut r = openidconnect::http::Response::builder()
        .status(status)
        .header("content-type", "application/json");
    if let Some(n) = nonce {
        r = r.header("dpop-nonce", n);
    }
    r.body(body.to_string()).unwrap().into()
}
fn jwt(token: &str, public: &PublicJwk) -> Value {
    let parts: Vec<_> = token.split('.').collect();
    public
        .verifying_key()
        .unwrap()
        .verify(
            format!("{}.{}", parts[0], parts[1]).as_bytes(),
            &Signature::from_slice(&B64.decode(parts[2]).unwrap()).unwrap(),
        )
        .unwrap();
    strict(&B64.decode(parts[1]).unwrap()).unwrap()
}
#[test]
fn par_and_token_retry_regenerate_proofs_preserve_pkce_and_bind_callback() {
    tauri::async_runtime::block_on(async {
        let (mut session, attestation, trust) = fixture("linked_document");
        let state = IdentityState::default();
        let guard = gate(&state).unwrap();
        let parameters = session.protocol.par_parameters(now().unwrap()).unwrap();
        let calls = Mutex::new(Vec::<(Value, Value, Vec<u8>)>::new());
        let instance = session.instance.public().unwrap();
        let dpop = session.dpop.public().unwrap();
        let (par,nonce)=form(&mut session,&guard,&attestation,&trust,"par",None,|r|{
            let r=r.build().unwrap();assert_eq!(r.url().as_str(),format!("{ISSUER}/par"));
            let d=jwt(r.headers()["dpop"].to_str().unwrap(),&dpop);
            let p=jwt(r.headers()["OAuth-Client-Attestation-PoP"].to_str().unwrap(),&instance);
            let mut calls=calls.lock().unwrap();
            calls.push((d,p,r.body().unwrap().as_bytes().unwrap().to_vec()));
            let result=if calls.len()==1 {response(400,json!({"error":"use_dpop_nonce"}),Some("as-nonce"))}else{
                response(201,json!({"request_uri":format!("urn:ietf:params:oauth:request_uri:{}","p".repeat(43)),"expires_in":90}),Some("next-as-nonce"))};
            std::future::ready(Ok(result))
        }).await.unwrap();
        {
            let calls = calls.lock().unwrap();
            assert_eq!(calls.len(), 2);
            assert_eq!(calls[0].0["htu"], format!("{ISSUER}/par"));
            assert_eq!(calls[0].0["htm"], "POST");
            assert!(calls[0].0.get("nonce").is_none());
            assert_eq!(calls[1].0["nonce"], "as-nonce");
            assert_ne!(calls[0].0["jti"], calls[1].0["jti"]);
            assert_ne!(calls[0].1["jti"], calls[1].1["jti"]);
            assert_eq!(calls[0].2, calls[1].2);
            assert_eq!(calls[0].1["aud"], ISSUER);
        }
        let browser = session.protocol.accept_par(&par, now().unwrap()).unwrap();
        assert_eq!(browser.path(), "/identity/issuer/authorize");
        let mut callback = url::Url::parse(CALLBACK).unwrap();
        callback
            .query_pairs_mut()
            .append_pair("state", parameters["state"].as_str().unwrap())
            .append_pair("iss", ISSUER)
            .append_pair("code", &"c".repeat(43));
        assert!(session
            .protocol
            .accept_callback(callback.as_str(), now().unwrap())
            .unwrap());
        let calls = Mutex::new(0);
        let (token,_)=form(&mut session,&guard,&attestation,&trust,"token",nonce.as_deref(),|r|{
            let r=r.build().unwrap();assert_eq!(r.url().as_str(),format!("{ISSUER}/token"));
            let d=jwt(r.headers()["dpop"].to_str().unwrap(),&dpop);assert_eq!(d["nonce"],"next-as-nonce");
            let fields:std::collections::BTreeMap<_,_>=url::form_urlencoded::parse(r.body().unwrap().as_bytes().unwrap()).into_owned().collect();
            assert_eq!(fields["redirect_uri"],CALLBACK);assert_eq!(fields["grant_type"],"authorization_code");
            use sha2::{Digest,Sha256};assert_eq!(B64.encode(Sha256::digest(fields["code_verifier"].as_bytes())),parameters["code_challenge"]);
            *calls.lock().unwrap()+=1;
            std::future::ready(Ok(response(200,json!({"access_token":"a".repeat(43),"token_type":"DPoP","expires_in":120,"scope":"linked_document"}),None)))
        }).await.unwrap();
        assert_eq!(*calls.lock().unwrap(), 1);
        session
            .protocol
            .accept_token(token, now().unwrap())
            .unwrap();
        assert!(session.protocol.token_parameters(now().unwrap()).is_err());
    });
}
#[test]
fn retry_bound_and_cancellation_prevent_another_network_operation() {
    tauri::async_runtime::block_on(async {
        for (error, expected) in [("use_dpop_nonce", 2), ("invalid_grant", 1)] {
            let (mut session, attestation, trust) = fixture("linked_document");
            let state = IdentityState::default();
            let guard = gate(&state).unwrap();
            let calls = Mutex::new(0);
            assert!(form(
                &mut session,
                &guard,
                &attestation,
                &trust,
                "par",
                None,
                |_| {
                    *calls.lock().unwrap() += 1;
                    std::future::ready(Ok(response(400, json!({"error":error}), Some("nonce"))))
                }
            )
            .await
            .is_err());
            assert_eq!(*calls.lock().unwrap(), expected);
        }
        let (mut session, attestation, trust) = fixture("linked_document");
        let state = IdentityState::default();
        let guard = gate(&state).unwrap();
        let calls = Mutex::new(0);
        let error = form(
            &mut session,
            &guard,
            &attestation,
            &trust,
            "par",
            None,
            |_| {
                *calls.lock().unwrap() += 1;
                state.0.lock().unwrap().generation += 1;
                std::future::ready(Ok(response(
                    400,
                    json!({"error":"use_dpop_nonce"}),
                    Some("nonce"),
                )))
            },
        )
        .await
        .unwrap_err();
        assert_eq!(error, "cancelled");
        assert_eq!(*calls.lock().unwrap(), 1);
    });
}
fn request_jwk() -> Value {
    let mut jwk = serde_json::to_value(key(0x11).public().unwrap()).unwrap();
    jwk["alg"] = json!("ECDH-ES");
    jwk["use"] = json!("enc");
    jwk["kid"] = json!("request");
    jwk
}
fn context() -> Context {
    let metadata = json!({"credential_request_encryption":{"jwks":{"keys":[request_jwk()]},"enc_values_supported":["A256GCM"],"encryption_required":false},"credential_response_encryption":{"alg_values_supported":["ECDH-ES"],"enc_values_supported":["A256GCM"],"encryption_required":false}});
    Context {
        encryption: WalletEncryption::from_metadata(&metadata, [0x22; 32], "native-test")
            .unwrap()
            .unwrap(),
        issuer_key: key(4).public().unwrap(),
        issuer_kid: "issuer".into(),
    }
}
#[test]
fn metadata_rejects_endpoint_substitution_missing_attestation_and_haip_downgrade() {
    let mut metadata = json!({"credential_issuer":ISSUER,"credential_endpoint":format!("{ISSUER}/credential"),"nonce_endpoint":format!("{ISSUER}/nonce"),"credential_configurations_supported":{}});
    for (id, format, binding, alg) in [
        ("linked_document", "dc+sd-jwt", "jwk", json!("ES256")),
        ("linked_document_mdoc", "mso_mdoc", "cose_key", json!(-7)),
    ] {
        metadata["credential_configurations_supported"][id] = json!({"format":format,"scope":id,"vct":format!("{ISSUER}/types/linked-document"),"doctype":mdoc::DOCTYPE,"cryptographic_binding_methods_supported":[binding],"credential_signing_alg_values_supported":[alg],"proof_types_supported":{"jwt":{"proof_signing_alg_values_supported":["ES256"],"key_attestations_required":{}}}});
    }
    let oauth = json!({"issuer":ISSUER,"token_endpoint":format!("{ISSUER}/token"),"jwks_uri":format!("{ISSUER}/jwks"),"authorization_endpoint":format!("{ISSUER}/authorize"),"pushed_authorization_request_endpoint":format!("{ISSUER}/par"),"require_pushed_authorization_requests":true,"authorization_response_iss_parameter_supported":true,"pre-authorized_grant_anonymous_access_supported":false,"token_endpoint_auth_methods_supported":["attest_jwt_client_auth"],"grant_types_supported":["authorization_code"],"response_types_supported":["code"],"code_challenge_methods_supported":["S256"],"dpop_signing_alg_values_supported":["ES256"],"client_attestation_signing_alg_values_supported":["ES256"],"client_attestation_pop_signing_alg_values_supported":["ES256"]});
    for configuration in ["linked_document", "linked_document_mdoc"] {
        assert!(validate_metadata(&metadata, &oauth, configuration).is_ok());
        let mut bad = metadata.clone();
        bad["credential_configurations_supported"][configuration]["proof_types_supported"]["jwt"]
            .as_object_mut()
            .unwrap()
            .remove("key_attestations_required");
        assert!(validate_metadata(&bad, &oauth, configuration).is_err());
    }
    for field in [
        "issuer",
        "token_endpoint",
        "jwks_uri",
        "authorization_endpoint",
        "pushed_authorization_request_endpoint",
    ] {
        let mut bad = oauth.clone();
        bad[field] = json!("https://evil.example");
        assert!(validate_metadata(&metadata, &bad, "linked_document").is_err());
    }
    for (field, value) in [
        ("require_pushed_authorization_requests", json!(false)),
        ("token_endpoint_auth_methods_supported", json!(["none"])),
        ("code_challenge_methods_supported", json!(["plain"])),
    ] {
        let mut bad = oauth.clone();
        bad[field] = value;
        assert!(validate_metadata(&metadata, &bad, "linked_document").is_err());
    }
    let mut bad = metadata.clone();
    bad["authorization_servers"] = json!(["https://evil.example"]);
    assert!(validate_metadata(&bad, &oauth, "linked_document").is_err());
}
#[test]
fn encrypted_native_issuance_binds_dpop_attestation_receipt_and_rejects_plaintext_or_other_holder()
{
    tauri::async_runtime::block_on(async {
        for configuration in ["linked_document", "linked_document_mdoc"] {
            let (mut session, _, _) = fixture(configuration);
            let state = IdentityState::default();
            let guard = gate(&state).unwrap();
            let at = now().unwrap();
            let parameters = session.protocol.par_parameters(at).unwrap();
            session.protocol.accept_par(&json!({"request_uri":format!("urn:ietf:params:oauth:request_uri:{}","p".repeat(43)),"expires_in":90}),at).unwrap();
            let mut callback = url::Url::parse(CALLBACK).unwrap();
            callback
                .query_pairs_mut()
                .append_pair("state", parameters["state"].as_str().unwrap())
                .append_pair("iss", ISSUER)
                .append_pair("code", &"c".repeat(43));
            session
                .protocol
                .accept_callback(callback.as_str(), at)
                .unwrap();
            session.protocol.accept_token(json!({"access_token":"a".repeat(43),"token_type":"DPoP","expires_in":120,"scope":configuration}),at).unwrap();
            let nonce = "n".repeat(43);
            let holder = session.holder.as_ref().unwrap().public().unwrap();
            let authority = SigningKey::from_slice(&[5; 32]).unwrap();
            let attestation=issuance::sign_jwt(&authority,json!({"typ":"key-attestation+jwt","alg":"ES256","x5c":[cert("attester"),cert("intermediate")]}),json!({"iat":at,"exp":at+60,"nonce":nonce,"attested_keys":[holder]})).unwrap();
            let trust = Trust {
                trust_anchors: vec![cert("root")],
                key_storage: None,
                user_authentication: None,
            };
            let payload = session
                .credential_request(&nonce, &attestation, &trust)
                .unwrap();
            let document=serde_json::from_value::<mikaki_identity::evidence::VerifiedDocument>(json!({"attributes":{"name":"Fixture","address":"Private","birth_date":"1990-02-28","gender":"1","verification":"issuer_signed_static_data","document_type":"my_number_card","expiry_date":null,"backend_verifiable":true},"trusted_key_id":"fixture","verified_at":at,"assurance":"issuer_signed_static_data","attributes_source":"input_support_ef"})).unwrap();
            let issuer = SigningKey::from_slice(&[4; 32]).unwrap();
            let compact = if configuration == "linked_document" {
                issuance::issue_with_certificate_trust(
                    &issuer,
                    "issuer",
                    ISSUER,
                    &holder,
                    &document,
                    issuance::Validity::new(&document, at, at + 300).unwrap(),
                    &[[1; 16], [2; 16], [3; 16], [4; 16]],
                    &mikaki_identity::credential_certificate::SigningTrust {
                        chain: vec![credential_cert("sd-signer")],
                        trust_anchors: vec![credential_cert("sd-ca")],
                        revocation: None,
                    },
                )
                .unwrap()
            } else {
                mdoc::issue(
                    &issuer,
                    include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/../../../crates/identity/tests/fixtures/credential/mdoc-signer.der"
                    )),
                    &holder,
                    &document,
                    at,
                    &[[1; 16], [2; 16], [3; 16], [4; 16]],
                )
                .unwrap()
            };
            let issued = json!({"credentials":[{"credential":compact}]});
            let calls = Mutex::new(Vec::<Value>::new());
            let ctx = context();
            let dpop = session.dpop.public().unwrap();
            let received = credential(&session, &guard, &ctx, payload.clone(), |r| {
                let r = r.build().unwrap();
                assert_eq!(r.url().as_str(), format!("{ISSUER}/credential"));
                assert_eq!(
                    r.headers()["authorization"],
                    format!("DPoP {}", "a".repeat(43))
                );
                let proof = jwt(r.headers()["dpop"].to_str().unwrap(), &dpop);
                use sha2::{Digest, Sha256};
                assert_eq!(
                    proof["ath"],
                    B64.encode(Sha256::digest("a".repeat(43).as_bytes()))
                );
                let mut private_jwk = request_jwk();
                private_jwk["d"] = json!(B64.encode([0x11; 32]));
                let private = RequestKey::parse(&private_jwk.to_string()).unwrap();
                let plain = decrypt_request(
                    std::str::from_utf8(r.body().unwrap().as_bytes().unwrap()).unwrap(),
                    &private,
                )
                .unwrap();
                let body = strict(&plain).unwrap();
                assert_eq!(body["credential_configuration_id"], configuration);
                let holder_proof = jwt(body["proofs"]["jwt"][0].as_str().unwrap(), &holder);
                assert_eq!(holder_proof["nonce"], nonce);
                assert_eq!(holder_proof["aud"], ISSUER);
                let recipient: ResponseEncryption =
                    serde_json::from_value(body["credential_response_encryption"].clone()).unwrap();
                let mut calls = calls.lock().unwrap();
                calls.push(proof);
                let response = if calls.len() == 1 {
                    response(401, json!({"error":"use_dpop_nonce"}), Some("rs-nonce"))
                } else {
                    let wire = encrypt_response(
                        &serde_json::to_vec(&issued).unwrap(),
                        &recipient,
                        [0x33; 32],
                        [4; 12],
                    )
                    .unwrap();
                    openidconnect::http::Response::builder()
                        .status(200)
                        .header("content-type", "application/jwt")
                        .body(wire)
                        .unwrap()
                        .into()
                };
                std::future::ready(Ok(response))
            })
            .await
            .unwrap();
            let proofs = calls.lock().unwrap();
            assert_eq!(proofs.len(), 2);
            assert_ne!(proofs[0]["jti"], proofs[1]["jti"]);
            assert_eq!(proofs[1]["nonce"], "rs-nonce");
            drop(proofs);
            let holder_key = session.holder.take().unwrap();
            assert!(super::super::flow::verified_receipt(
                received.clone(),
                context(),
                key(9),
                configuration,
                credential_trust()
            )
            .is_err());
            let receipt = super::super::flow::verified_receipt(
                received,
                ctx,
                holder_key,
                configuration,
                credential_trust(),
            )
            .unwrap();
            assert!(receipt.expires_at > at);
            assert!(credential(&session, &guard, &context(), payload, |_| {
                std::future::ready(Ok(response(200, issued.clone(), None)))
            })
            .await
            .is_err());
        }
    });
}
