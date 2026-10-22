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
        age_pool_claims: None,
        age_batch: false,
    }
}
#[test]
fn metadata_rejects_endpoint_substitution_missing_attestation_and_haip_downgrade() {
    let mut metadata = json!({"credential_issuer":ISSUER,"credential_endpoint":format!("{ISSUER}/credential"),"nonce_endpoint":format!("{ISSUER}/nonce"),"credential_configurations_supported":{}});
    for (id, format, binding, alg) in [
        ("linked_document", "dc+sd-jwt", "jwk", json!("ES256")),
        ("passport_dg1", "dc+sd-jwt", "jwk", json!("ES256")),
        ("linked_document_mdoc", "mso_mdoc", "cose_key", json!(-7)),
    ] {
        metadata["credential_configurations_supported"][id] = json!({"format":format,"scope":id,"vct":if id == "passport_dg1" {mikaki_identity::passport::credential::vct(ISSUER)} else {format!("{ISSUER}/types/linked-document")},"doctype":mdoc::DOCTYPE,"cryptographic_binding_methods_supported":[binding],"credential_signing_alg_values_supported":[alg],"proof_types_supported":{"jwt":{"proof_signing_alg_values_supported":["ES256"],"key_attestations_required":{}}}});
    }
    let oauth = json!({"issuer":ISSUER,"token_endpoint":format!("{ISSUER}/token"),"jwks_uri":format!("{ISSUER}/jwks"),"authorization_endpoint":format!("{ISSUER}/authorize"),"pushed_authorization_request_endpoint":format!("{ISSUER}/par"),"require_pushed_authorization_requests":true,"authorization_response_iss_parameter_supported":true,"pre-authorized_grant_anonymous_access_supported":false,"token_endpoint_auth_methods_supported":["attest_jwt_client_auth"],"grant_types_supported":["authorization_code"],"response_types_supported":["code"],"code_challenge_methods_supported":["S256"],"dpop_signing_alg_values_supported":["ES256"],"client_attestation_signing_alg_values_supported":["ES256"],"client_attestation_pop_signing_alg_values_supported":["ES256"]});
    for configuration in ["linked_document", "linked_document_mdoc", "passport_dg1"] {
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
            {
                let proofs = calls.lock().unwrap();
                assert_eq!(proofs.len(), 2);
                assert_ne!(proofs[0]["jti"], proofs[1]["jti"]);
                assert_eq!(proofs[1]["nonce"], "rs-nonce");
            }
            let holder_key = session.holder.take().unwrap();
            assert!(super::super::flow::verified_receipt(
                received.clone(),
                &context(),
                key(9),
                configuration,
                credential_trust()
            )
            .is_err());
            let receipt = super::super::flow::verified_receipt(
                received,
                &ctx,
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

#[test]
fn eight_fresh_attested_holders_are_verified_before_one_trusted_inventory_install() {
    use mikaki_identity::{
        age_pool::Budget, claim_profile::ClaimProfile, evidence::VerifiedDocument,
    };
    for mode in [
        mikaki_identity::age_pool::Mode::Sequential,
        mikaki_identity::age_pool::Mode::Batch,
    ] {
        for (configuration, format) in [
            (issuance::CONFIGURATION, "dc+sd-jwt"),
            (mdoc::CONFIGURATION, "mso_mdoc"),
        ] {
            let at = now().unwrap();
            let profile = ClaimProfile::age_only();
            let mut protocol = Authorization::new_pending_holder(
                ISSUER,
                "native",
                CALLBACK,
                configuration,
                [1; 32],
                [2; 32],
                key(1).public().unwrap(),
                key(2).public().unwrap(),
                at,
            )
            .unwrap();
            protocol
                .request_age_pool(
                    Budget {
                        mode,
                        size: 8,
                        claims_json: profile.to_json(),
                    },
                    at,
                )
                .unwrap();
            let parameters = protocol.par_parameters(at).unwrap();
            protocol.accept_par(&json!({"request_uri":format!("urn:ietf:params:oauth:request_uri:{}",B64.encode([3;32])),"expires_in":90}),at).unwrap();
            let mut callback = url::Url::parse(CALLBACK).unwrap();
            callback
                .query_pairs_mut()
                .append_pair("state", parameters["state"].as_str().unwrap())
                .append_pair("iss", ISSUER)
                .append_pair("code", &B64.encode([4; 32]));
            protocol.accept_callback(callback.as_str(), at).unwrap();
            protocol.accept_token(json!({"access_token":B64.encode([9;32]),"token_type":"DPoP","scope":configuration,"expires_in":120}),at).unwrap();
            let mut session = Session {
                protocol,
                instance: key(1),
                dpop: key(2),
                holder: None,
            };
            let authority = SigningKey::from_slice(&[5; 32]).unwrap();
            let issuer = SigningKey::from_slice(&[4; 32]).unwrap();
            let trust = Trust {
                trust_anchors: vec![cert("root")],
                key_storage: None,
                user_authentication: None,
            };
            let document:VerifiedDocument=serde_json::from_value(json!({"attributes":{"name":"Fixture","address":"Private","birth_date":"1990-02-28","gender":"1","verification":"issuer_signed_static_data","document_type":"my_number_card","expiry_date":null,"backend_verifiable":true},"trusted_key_id":"fixture","verified_at":at,"assurance":"issuer_signed_static_data","attributes_source":"input_support_ef"})).unwrap();
            let mut ctx = context();
            ctx.age_pool_claims = Some(profile.to_json());
            ctx.age_batch = mode == mikaki_identity::age_pool::Mode::Batch;
            let mut credentials = Vec::new();
            let mut keys = Vec::new();
            let mut receipts = Vec::new();
            let mut nonces = std::collections::HashSet::new();
            for seed in 10..18 {
                let holder = key(seed);
                let public = holder.public().unwrap();
                session.protocol.bind_holder(public.clone(), at).unwrap();
                session.holder = Some(holder);
                let nonce = B64.encode([if ctx.age_batch { 10 } else { seed }; 32]);
                if !ctx.age_batch {
                    assert!(nonces.insert(nonce.clone()));
                }
                let attestation=issuance::sign_jwt(&authority,json!({"typ":"key-attestation+jwt","alg":"ES256","x5c":[cert("attester"),cert("intermediate")]}),json!({"iat":at,"exp":at+60,"nonce":nonce,"attested_keys":[public]})).unwrap();
                if ctx.age_batch {
                    session
                        .protocol
                        .stage_credential_proof(
                            &nonce,
                            &attestation,
                            &trust,
                            session.holder.as_ref().unwrap(),
                            at,
                        )
                        .unwrap();
                } else {
                    let payload = session
                        .credential_request(&nonce, &attestation, &trust)
                        .unwrap();
                    let (bound, _) = issuance::verify_attested_wallet_proof(
                        payload["proofs"]["jwt"][0].as_str().unwrap(),
                        ISSUER,
                        &nonce,
                        "native",
                        &trust,
                        at,
                    )
                    .unwrap();
                    assert_eq!(bound, public);
                }
                let validity = issuance::Validity::new(&document, at, at + 50).unwrap();
                let credential = if format == "dc+sd-jwt" {
                    issuance::issue_with_certificate_trust_and_profile(
                        &issuer,
                        "issuer",
                        ISSUER,
                        &public,
                        &document,
                        validity,
                        &[[seed; 16], [seed + 1; 16]],
                        &mikaki_identity::credential_certificate::SigningTrust {
                            chain: vec![credential_cert("sd-signer")],
                            trust_anchors: vec![credential_cert("sd-ca")],
                            revocation: None,
                        },
                        &profile,
                    )
                    .unwrap()
                } else {
                    mdoc::issue_with_profile(
                        &issuer,
                        &STANDARD.decode(credential_cert("mdoc-signer")).unwrap(),
                        &public,
                        &document,
                        validity,
                        &[[seed; 16], [seed + 1; 16]],
                        &profile,
                    )
                    .unwrap()
                };
                if ctx.age_batch {
                    credentials.push(json!({"credential":credential}));
                    keys.push(session.holder.take().unwrap());
                    continue;
                }
                let receipt = super::super::flow::verified_receipt(
                    json!({"credentials":[{"credential":credential}]}),
                    &ctx,
                    session.holder.take().unwrap(),
                    configuration,
                    credential_trust(),
                )
                .unwrap();
                batch::validate_age_receipt(&receipt, &profile.to_json(), at).unwrap();
                session
                    .protocol
                    .finish_receipt(&receipt.key.public().unwrap(), at)
                    .unwrap();
                receipts.push(receipt);
            }
            if ctx.age_batch {
                let payload = session.protocol.batch_credential_request(at).unwrap();
                let state = IdentityState::default();
                let guard = gate(&state).unwrap();
                let calls = Mutex::new(0);
                let issued = tauri::async_runtime::block_on(credential(
                    &session,
                    &guard,
                    &ctx,
                    payload,
                    |r| {
                        let r = r.build().unwrap();
                        let compact =
                            std::str::from_utf8(r.body().unwrap().as_bytes().unwrap()).unwrap();
                        let mut private = request_jwk();
                        private["d"] = json!(B64.encode([0x11; 32]));
                        let plain = mikaki_identity::issuance_encryption::decrypt_batch_request(
                            compact,
                            &RequestKey::parse(&private.to_string()).unwrap(),
                        )
                        .unwrap();
                        let request: Value = serde_json::from_slice(&plain).unwrap();
                        let proofs = request["proofs"]["jwt"].as_array().unwrap();
                        assert_eq!(proofs.len(), 8);
                        for (i, proof) in proofs.iter().enumerate() {
                            let (holder, _) = issuance::verify_attested_wallet_proof(
                                proof.as_str().unwrap(),
                                ISSUER,
                                &B64.encode([10; 32]),
                                "native",
                                &trust,
                                at,
                            )
                            .unwrap();
                            assert_eq!(holder, keys[i].public().unwrap());
                        }
                        let mut calls = calls.lock().unwrap();
                        *calls += 1;
                        // Only an explicit DPoP nonce challenge permits a retry.
                        let result = if *calls == 1 {
                            response(401, json!({"error":"use_dpop_nonce"}), Some("batch-nonce"))
                        } else {
                            let recipient: ResponseEncryption = serde_json::from_value(
                                request["credential_response_encryption"].clone(),
                            )
                            .unwrap();
                            let wire =
                                mikaki_identity::issuance_encryption::encrypt_batch_response(
                                    &serde_json::to_vec(&json!({"credentials":credentials}))
                                        .unwrap(),
                                    &recipient,
                                    [3; 32],
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
                        std::future::ready(Ok(result))
                    },
                ))
                .unwrap();
                assert_eq!(*calls.lock().unwrap(), 2);
                let make_keys = || (10..18).map(key).collect();
                let mut partial = issued.clone();
                partial["credentials"].as_array_mut().unwrap().pop();
                assert!(super::super::flow::verified_batch(
                    partial,
                    &ctx,
                    make_keys(),
                    configuration,
                    credential_trust()
                )
                .is_err());
                let mut reordered = issued.clone();
                reordered["credentials"].as_array_mut().unwrap().swap(0, 7);
                assert!(super::super::flow::verified_batch(
                    reordered,
                    &ctx,
                    make_keys(),
                    configuration,
                    credential_trust()
                )
                .is_err());
                let mut tampered = issued.clone();
                tampered["credentials"][7]["credential"] = json!("invalid");
                assert!(super::super::flow::verified_batch(
                    tampered,
                    &ctx,
                    make_keys(),
                    configuration,
                    credential_trust()
                )
                .is_err());
                receipts = super::super::flow::verified_batch(
                    issued,
                    &ctx,
                    keys,
                    configuration,
                    credential_trust(),
                )
                .unwrap();
                let holders = receipts
                    .iter()
                    .map(|r| r.key.public().unwrap())
                    .collect::<Vec<_>>();
                session
                    .protocol
                    .finish_batch(&holders, now().unwrap())
                    .unwrap();
            }
            assert!(session.protocol.authorization_header(at).is_err());
            let mut writes = 0;
            let installed = batch::install(&[], receipts, at, |all| {
                writes += 1;
                assert_eq!(all.len(), 8);
                assert!(all.iter().all(|r| r.credential_trust.is_some()));
                Ok(())
            })
            .unwrap();
            assert_eq!(writes, 1);
            assert_eq!(installed.len(), 8);
            let mut inventory = Inner {
                receipt: installed.last().cloned(),
                receipts: installed,
                ..Default::default()
            };
            let original = inventory
                .receipts
                .iter()
                .map(|r| credential_hash(&r.credential))
                .collect::<Vec<_>>();
            assert!(inventory
                .retire_age_receipts_with(
                    &original[..1],
                    at,
                    |_, _| Err("storage failure".into()),
                    |_| panic!("storage must commit first")
                )
                .is_err());
            assert_eq!(inventory.receipts.len(), 8);
            let mut retire_writes = 0;
            let destroyed = std::cell::RefCell::new(std::collections::HashSet::new());
            for index in 0..8 {
                inventory
                    .retire_age_receipts_with(
                        &original[index..=index],
                        at,
                        |remaining, _| {
                            retire_writes += 1;
                            assert_eq!(remaining.len(), 7 - index);
                            // Encode/decode the complete committed snapshot, including
                            // the final v4 tombstone, with the production storage codec.
                            assert_eq!(
                                identity_wallet::roundtrip_host_snapshot(remaining)?,
                                remaining.len()
                            );
                            Ok(())
                        },
                        |key| {
                            assert!(destroyed
                                .borrow_mut()
                                .insert(key.public()?.thumbprint().unwrap()));
                            Ok(())
                        },
                    )
                    .unwrap();
                // Lost/failed delivery has no path to replenish a spent slot.
                assert!(inventory
                    .retire_age_receipts_with(
                        &original[index..=index],
                        at,
                        |_, _| panic!("no second persistence"),
                        |_| panic!("no second destruction")
                    )
                    .is_err());
            }
            assert_eq!(retire_writes, 8);
            assert_eq!(destroyed.borrow().len(), 8);
            assert!(inventory.receipts.is_empty() && inventory.receipt.is_none());
        }
    }
}

#[test]
fn passport_par_preserves_review_binding_and_never_transfers_evidence_in_oauth() {
    tauri::async_runtime::block_on(async {
        let (mut session, attestation, trust) = fixture("passport_dg1");
        session
            .protocol
            .bind_issuer_state(&"t".repeat(43), now().unwrap())
            .unwrap();
        let state = IdentityState::default();
        let guard = gate(&state).unwrap();
        let sender = session.dpop.public().unwrap();
        let instance = session.instance.public().unwrap();
        form(&mut session,&guard,&attestation,&trust,"par",None,|r| {
            let r=r.build().unwrap();
            jwt(r.headers()["dpop"].to_str().unwrap(),&sender);
            jwt(r.headers()["OAuth-Client-Attestation-PoP"].to_str().unwrap(),&instance);
            let fields:std::collections::BTreeMap<_,_>=url::form_urlencoded::parse(r.body().unwrap().as_bytes().unwrap()).into_owned().collect();
            assert_eq!(fields["scope"],"passport_dg1");assert_eq!(fields["issuer_state"],"t".repeat(43));
            assert_eq!(fields["dpop_jkt"],sender.thumbprint().unwrap());
            assert!(!fields.contains_key("passport_evidence"));assert!(!fields.contains_key("dg1"));assert!(!fields.contains_key("sod"));
            std::future::ready(Ok(response(201,json!({"request_uri":format!("urn:ietf:params:oauth:request_uri:{}","p".repeat(43)),"expires_in":90}),None)))
        }).await.unwrap();
    });
}
