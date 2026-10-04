use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD as B64},
};
use mikaki_identity::{
    client_attestation::AttesterTrust,
    issuance::{self, PublicJwk},
    key_attestation::Trust,
    wallet_authorization::{Authorization, Signer},
};
use p256::ecdsa::SigningKey;
use serde_json::{Value, json};
const NOW: u64 = 1791000000;
const ISSUER: &str = "https://issuer.example/identity/issuer";
const CALLBACK: &str = "https://wallet.example/callback?tenant=fixed%20tenant";
struct Key(SigningKey);
fn key(n: u8) -> Key {
    Key(SigningKey::from_slice(&[n; 32]).unwrap())
}
impl Signer for Key {
    fn public(&self) -> Result<PublicJwk, String> {
        Ok(PublicJwk::from_key(self.0.verifying_key()))
    }
    fn sign(&self, h: Value, c: Value) -> Result<String, String> {
        issuance::sign_jwt(&self.0, h, c).map_err(str::to_owned)
    }
}
fn session() -> Authorization {
    Authorization::new(
        ISSUER,
        "wallet",
        CALLBACK,
        "linked_document",
        [1; 32],
        [2; 32],
        key(6).public().unwrap(),
        key(7).public().unwrap(),
        key(8).public().unwrap(),
        NOW,
    )
    .unwrap()
}
fn pushed(a: &mut Authorization) {
    a.accept_par(&json!({"request_uri":format!("urn:ietf:params:oauth:request_uri:{}",B64.encode([3;32])),"expires_in":90}),NOW).unwrap();
}
fn callback() -> String {
    format!(
        "{CALLBACK}&code={}&state={}&iss=https%3A%2F%2Fissuer.example%2Fidentity%2Fissuer",
        B64.encode([4; 32]),
        B64.encode([1; 32])
    )
}
fn token() -> Value {
    json!({"access_token":B64.encode([9;32]),"token_type":"DPoP","scope":"linked_document","expires_in":120})
}
fn cert(name: &str) -> String {
    STANDARD.encode(
        std::fs::read(format!(
            "{}/tests/fixtures/trust/{name}.der",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap(),
    )
}
fn chain(typ: &str) -> Value {
    json!({"typ":typ,"alg":"ES256","x5c":[cert("attester"),cert("intermediate")]})
}
#[test]
fn pkce_callback_is_exact_bound_and_one_use_without_consuming_on_bad_input() {
    let mut a = session();
    let par = a.par_parameters(NOW).unwrap();
    assert_eq!(par["code_challenge_method"], "S256");
    assert_eq!(
        par["dpop_jkt"],
        key(7).public().unwrap().thumbprint().unwrap()
    );
    assert!(a.token_parameters(NOW).is_err());
    pushed(&mut a);
    for input in [
        callback().replace("tenant=fixed%20tenant", "tenant=other"),
        callback().replace("wallet.example", "evil.example"),
        callback().replace("state=", "state=wrong"),
        callback().replace("issuer.example%2Fidentity", "evil.example%2Fidentity"),
        format!("{}&%63ode={}", callback(), B64.encode([4; 32])),
        format!("{}#ignored", callback()),
        format!("{}&error=access_denied", callback()),
        callback().replace("&code=", "&unknown="),
    ] {
        assert!(a.accept_callback(&input, NOW + 1).is_err(), "{input}");
    }
    assert_eq!(
        a.accept_callback(&format!("{}&issuer_extension=ignored", callback()), NOW + 1),
        Ok(true)
    );
    assert!(a.accept_callback(&callback(), NOW + 1).is_err());
    let params = a.token_parameters(NOW + 1).unwrap();
    assert_eq!(params["code_verifier"], B64.encode([2; 32]));
    assert!(a.par_parameters(NOW + 1).is_err());
}
#[test]
fn denial_expiry_cancellation_and_bad_par_close_or_preserve_as_expected() {
    let mut a = session();
    for v in [
        json!({"request_uri":"https://evil.example","expires_in":90}),
        json!({"request_uri":format!("urn:ietf:params:oauth:request_uri:{}",B64.encode([3;32])),"expires_in":91}),
    ] {
        assert!(a.accept_par(&v, NOW).is_err());
    }
    pushed(&mut a);
    assert_eq!(
        a.accept_callback(
            &callback().replace(
                &format!("code={}", B64.encode([4; 32])),
                "error=access_denied"
            ),
            NOW + 1
        ),
        Ok(false)
    );
    assert!(a.token_parameters(NOW + 1).is_err());
    let mut a = session();
    pushed(&mut a);
    assert!(a.accept_callback(&callback(), NOW + 90).is_err());
    assert!(a.accept_callback(&callback(), NOW + 1).is_err());
    let mut a = session();
    a.cancel();
    assert!(a.par_parameters(NOW).is_err());
    assert!(session().par_parameters(NOW + 180).is_err());
}
#[test]
fn rejects_bad_registration_or_role_collisions() {
    for callback in [
        "http://wallet.example/callback",
        "https://wallet.example/callback?%63ode=x",
        "https://wallet.example/callback?tenant=x&%74enant=y",
        "https://wallet.example/callback#x",
        "https://wallet.example/callback?",
    ] {
        assert!(
            Authorization::new(
                ISSUER,
                "wallet",
                callback,
                "linked_document",
                [1; 32],
                [2; 32],
                key(6).public().unwrap(),
                key(7).public().unwrap(),
                key(8).public().unwrap(),
                NOW
            )
            .is_err()
        );
    }
    assert!(
        Authorization::new(
            ISSUER,
            "wallet",
            CALLBACK,
            "linked_document",
            [1; 32],
            [2; 32],
            key(6).public().unwrap(),
            key(6).public().unwrap(),
            key(8).public().unwrap(),
            NOW
        )
        .is_err()
    );
}
#[test]
fn token_is_dpop_scope_bound_expires_and_cannot_be_replaced() {
    let mut a = session();
    pushed(&mut a);
    a.accept_callback(&callback(), NOW + 1).unwrap();
    for (field, value) in [
        ("token_type", json!("Bearer")),
        ("scope", json!("linked_document_mdoc")),
        ("expires_in", json!(121)),
        ("refresh_token", json!("secret")),
        ("access_token", json!("bad")),
    ] {
        let mut t = token();
        t[field] = value;
        assert!(a.accept_token(t, NOW + 2).is_err());
    }
    a.accept_token(token(), NOW + 2).unwrap();
    assert!(a.accept_token(token(), NOW + 2).is_err());
    assert!(a.token_parameters(NOW + 2).is_err());
    assert!(
        a.dpop("token", None, &key(7), &B64.encode([11; 32]), NOW + 2)
            .is_err()
    );
    assert!(a.authorization_header(NOW + 122).is_err());
    let jwt = a
        .dpop(
            "credential",
            Some("nonce"),
            &key(7),
            &B64.encode([11; 32]),
            NOW + 2,
        )
        .unwrap();
    let claims: Value =
        serde_json::from_slice(&B64.decode(jwt.split('.').nth(1).unwrap()).unwrap()).unwrap();
    assert_eq!(claims["htu"], format!("{ISSUER}/credential"));
    assert!(claims["ath"].as_str().unwrap().len() == 43);
    assert!(
        a.dpop("credential", None, &key(6), &B64.encode([11; 32]), NOW + 2)
            .is_err()
    );
}
#[test]
fn verifies_external_attester_instance_holder_and_nonce_before_using_them() {
    let mut a = session();
    let policies = vec![AttesterTrust {
        issuer: "https://attester.example".into(),
        trust_anchors: vec![cert("root")],
    }];
    let attestation=key(5).sign(chain("oauth-client-attestation+jwt"),json!({"iss":"https://attester.example","sub":"wallet","iat":NOW,"exp":NOW+300,"cnf":{"jwk":key(6).public().unwrap()}})).unwrap();
    assert!(
        a.client_headers(&attestation, &policies, &key(6), &B64.encode([10; 32]), NOW)
            .is_ok()
    );
    assert!(
        a.client_headers(&attestation, &[], &key(6), &B64.encode([10; 32]), NOW)
            .is_err()
    );
    assert!(
        a.client_headers(&attestation, &policies, &key(7), &B64.encode([10; 32]), NOW)
            .is_err()
    );
    pushed(&mut a);
    a.accept_callback(&callback(), NOW + 1).unwrap();
    a.accept_token(token(), NOW + 2).unwrap();
    let trust = Trust {
        trust_anchors: vec![cert("root")],
        key_storage: None,
        user_authentication: None,
    };
    let attested=key(5).sign(chain("key-attestation+jwt"),json!({"iat":NOW,"exp":NOW+300,"nonce":"credential-nonce","attested_keys":[key(8).public().unwrap()]})).unwrap();
    assert!(
        a.credential_request("wrong-nonce", &attested, &trust, &key(8), NOW + 2)
            .is_err()
    );
    assert!(
        a.credential_request("credential-nonce", &attested, &trust, &key(7), NOW + 2)
            .is_err()
    );
    let request = a
        .credential_request("credential-nonce", &attested, &trust, &key(8), NOW + 2)
        .unwrap();
    let oversized = key(5)
        .sign(
            chain("key-attestation+jwt"),
            json!({"iat":NOW,"exp":NOW+300,"nonce":"credential-nonce","attested_keys":[key(8).public().unwrap()],"extension":"x".repeat(9000)}),
        )
        .unwrap();
    assert!(oversized.len() <= 16384);
    assert!(
        a.credential_request("credential-nonce", &oversized, &trust, &key(8), NOW + 2)
            .is_err()
    );
    issuance::verify_attested_wallet_proof(
        request["proofs"]["jwt"][0].as_str().unwrap(),
        ISSUER,
        "credential-nonce",
        "wallet",
        &trust,
        NOW + 2,
    )
    .unwrap();
}

#[test]
fn pending_holder_binds_once_only_after_token_and_before_expiry() {
    let pending = || {
        Authorization::new_pending_holder(
            ISSUER,
            "wallet",
            CALLBACK,
            "linked_document",
            [1; 32],
            [2; 32],
            key(6).public().unwrap(),
            key(7).public().unwrap(),
            NOW,
        )
        .unwrap()
    };
    let mut a = pending();
    assert!(a.bind_holder(key(8).public().unwrap(), NOW).is_err());
    pushed(&mut a);
    a.accept_callback(&callback(), NOW).unwrap();
    assert!(a.bind_holder(key(8).public().unwrap(), NOW).is_err());
    a.accept_token(token(), NOW).unwrap();
    assert!(a.bind_holder(key(6).public().unwrap(), NOW).is_err());
    assert!(a.bind_holder(key(7).public().unwrap(), NOW).is_err());
    a.bind_holder(key(8).public().unwrap(), NOW).unwrap();
    assert!(a.bind_holder(key(9).public().unwrap(), NOW).is_err());
    let mut expired = pending();
    pushed(&mut expired);
    expired.accept_callback(&callback(), NOW).unwrap();
    expired.accept_token(token(), NOW).unwrap();
    assert!(
        expired
            .bind_holder(key(8).public().unwrap(), NOW + 120)
            .is_err()
    );
    let mut cancelled = pending();
    cancelled.cancel();
    assert!(
        cancelled
            .bind_holder(key(8).public().unwrap(), NOW)
            .is_err()
    );
}
