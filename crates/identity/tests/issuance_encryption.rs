use mikaki_identity::issuance_encryption::{RequestKey, ResponseEncryption, decrypt_request};
use serde_json::{Value, json};
fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/issuance-jwe.json")).unwrap()
}
#[test]
fn independent_jose_requests_decrypt_with_both_gcm_algorithms_and_party_info() {
    let f = fixture();
    let key = RequestKey::parse(&f["privateKey"].to_string()).unwrap();
    assert!(key.public().metadata().get("d").is_none());
    for v in f["vectors"].as_array().unwrap() {
        let plain = decrypt_request(v["jwe"].as_str().unwrap(), &key).unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&plain).unwrap(),
            f["payload"]
        );
    }
}
#[test]
fn wrong_key_kid_aad_ciphertext_and_tag_never_release_plaintext() {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
    let f = fixture();
    let key = RequestKey::parse(&f["privateKey"].to_string()).unwrap();
    let mut wrong = f["privateKey"].clone();
    wrong["kid"] = json!("other");
    let wrong = RequestKey::parse(&wrong.to_string()).unwrap();
    for v in f["vectors"].as_array().unwrap() {
        let jwt = v["jwe"].as_str().unwrap();
        assert!(decrypt_request(jwt, &wrong).is_err());
        for i in [0, 2, 3, 4] {
            let mut parts: Vec<String> = jwt.split('.').map(str::to_owned).collect();
            let mut bytes = B64.decode(&parts[i]).unwrap();
            bytes[0] ^= 1;
            parts[i] = B64.encode(bytes);
            assert!(decrypt_request(&parts.join("."), &key).is_err());
        }
    }
    assert!(decrypt_request(&"a".repeat(32769), &key).is_err());
}
#[test]
fn recipient_must_be_public_p256_and_supported_key_agreement_and_content_cipher() {
    let f = fixture();
    let mut pubkey = f["privateKey"].clone();
    pubkey.as_object_mut().unwrap().remove("d");
    let check = |value: Value| {
        serde_json::from_value::<ResponseEncryption>(value).is_ok_and(|v| v.validate().is_ok())
    };
    for enc in ["A128GCM", "A256GCM"] {
        assert!(check(json!({"jwk":pubkey,"enc":enc})));
    }
    assert!(!check(json!({"jwk":f["privateKey"],"enc":"A256GCM"})));
    for field in ["alg", "crv", "use"] {
        let mut k = pubkey.clone();
        k[field] = json!("unsupported");
        assert!(!check(json!({"jwk":k,"enc":"A256GCM"})));
    }
    assert!(!check(json!({"jwk":pubkey,"enc":"unsupported"})));
    assert!(check(json!({"jwk":pubkey,"enc":"A256GCM","zip":"DEF"})));
    assert!(!check(
        json!({"jwk":pubkey,"enc":"A256GCM","zip":"unsupported"})
    ));
    let mut bad = f["privateKey"].clone();
    bad["x"] = json!("invalid");
    assert!(RequestKey::parse(&bad.to_string()).is_err());
}
fn wallet_metadata(f: &Value, enc: &str, zip: bool) -> Value {
    json!({"credential_request_encryption":{"jwks":{"keys":[f["requestJwk"]]},"enc_values_supported":[enc],"encryption_required":false},
        "credential_response_encryption":{"alg_values_supported":["ECDH-ES"],"enc_values_supported":[enc],"encryption_required":false,"zip_values_supported":if zip {json!(["DEF"])} else {json!([])}}})
}
#[test]
fn wallet_decrypts_independent_jose_and_openssl_deflate_and_rejects_downgrades() {
    use mikaki_identity::issuance_encryption::WalletEncryption;
    let f: Value = serde_json::from_str(include_str!("fixtures/wallet-jwe.json")).unwrap();
    for v in f["vectors"].as_array().unwrap() {
        let metadata = wallet_metadata(&f, v["enc"].as_str().unwrap(), v["zip"] == true);
        let wallet = WalletEncryption::from_metadata(&metadata, [0x22; 32], "native-fixture")
            .unwrap()
            .unwrap();
        let wire = v["jwe"].as_str().unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&wallet.decrypt_response(wire).unwrap()).unwrap(),
            f["payload"]
        );
        assert!(wallet.decrypt_response(&f["payload"].to_string()).is_err());
        let wrong = WalletEncryption::from_metadata(&metadata, [0x23; 32], "native-fixture")
            .unwrap()
            .unwrap();
        assert!(wrong.decrypt_response(wire).is_err());
        let wrong = WalletEncryption::from_metadata(&metadata, [0x22; 32], "other")
            .unwrap()
            .unwrap();
        assert!(wrong.decrypt_response(wire).is_err());
        let mut parts: Vec<String> = wire.split('.').map(str::to_owned).collect();
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
        let mut tag = B64.decode(&parts[4]).unwrap();
        tag[0] ^= 1;
        parts[4] = B64.encode(tag);
        assert!(wallet.decrypt_response(&parts.join(".")).is_err());
    }
    let wallet = WalletEncryption::from_metadata(
        &wallet_metadata(&f, "A256GCM", true),
        [0x22; 32],
        "native-fixture",
    )
    .unwrap()
    .unwrap();
    for name in ["bomb", "trailing"] {
        assert!(wallet.decrypt_response(f[name].as_str().unwrap()).is_err());
    }
    let nozip = WalletEncryption::from_metadata(
        &wallet_metadata(&f, "A256GCM", false),
        [0x22; 32],
        "native-fixture",
    )
    .unwrap()
    .unwrap();
    assert!(
        nozip
            .decrypt_response(f["vectors"][2]["jwe"].as_str().unwrap())
            .is_err()
    );
    let a128 = WalletEncryption::from_metadata(
        &wallet_metadata(&f, "A128GCM", false),
        [0x22; 32],
        "native-fixture",
    )
    .unwrap()
    .unwrap();
    assert!(
        a128.decrypt_response(f["vectors"][1]["jwe"].as_str().unwrap())
            .is_err()
    );
}
#[test]
fn wallet_metadata_never_silently_downgrades_required_or_malformed_encryption() {
    use mikaki_identity::issuance_encryption::WalletEncryption;
    let f: Value = serde_json::from_str(include_str!("fixtures/wallet-jwe.json")).unwrap();
    assert!(
        WalletEncryption::from_metadata(&json!({}), [0x22; 32], "native-fixture")
            .unwrap()
            .is_none()
    );
    let metadata = wallet_metadata(&f, "A256GCM", true);
    for field in [
        "credential_request_encryption",
        "credential_response_encryption",
    ] {
        let mut bad = metadata.clone();
        bad.as_object_mut().unwrap().remove(field);
        assert!(WalletEncryption::from_metadata(&bad, [0x22; 32], "native-fixture").is_err());
        let mut bad = metadata.clone();
        bad[field]["encryption_required"] = json!("false");
        assert!(WalletEncryption::from_metadata(&bad, [0x22; 32], "native-fixture").is_err());
    }
    let mut bad = metadata.clone();
    bad["credential_request_encryption"]["jwks"]["keys"][0]["d"] = json!("private");
    assert!(WalletEncryption::from_metadata(&bad, [0x22; 32], "native-fixture").is_err());
    let mut bad = metadata;
    bad["credential_request_encryption"]["jwks"]["keys"] =
        json!([f["requestJwk"], f["requestJwk"]]);
    assert!(WalletEncryption::from_metadata(&bad, [0x22; 32], "native-fixture").is_err());
}
