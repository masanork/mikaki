use super::*;
use p256::ecdsa::{SigningKey, signature::Signer};

fn context() -> Context {
    Context {
        challenge: B64.encode([3; 32]),
        origin: "https://login.example".into(),
        rp_id: "login.example".into(),
        max_bytes: 65536,
        max_depth: 8,
        user_verification: Default::default(),
        authentication: Default::default(),
        algorithms: vec![-7],
        attestation: None,
        attestation_policy: Default::default(),
    }
}
fn key() -> SigningKey {
    SigningKey::from_slice(&[7; 32]).unwrap()
}
fn client(ctx: &Context, kind: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"type":kind,"challenge":ctx.challenge,"origin":ctx.origin,"crossOrigin":false})).unwrap()
}
fn header(ctx: &Context, flags: u8, counter: u32) -> Vec<u8> {
    let mut data = Sha256::digest(ctx.rp_id.as_bytes()).to_vec();
    data.push(flags);
    data.extend(counter.to_be_bytes());
    data
}
fn cbor_bytes(v: &Value) -> Vec<u8> {
    let mut out = vec![];
    ciborium::ser::into_writer(v, &mut out).unwrap();
    out
}
fn cose() -> Value {
    let point = key().verifying_key().to_sec1_point(false);
    let bytes = point.as_bytes();
    Value::Map(
        vec![
            (1, Value::Integer(2.into())),
            (3, Value::Integer((-7).into())),
            (-1, Value::Integer(1.into())),
            (-2, Value::Bytes(bytes[1..33].to_vec())),
            (-3, Value::Bytes(bytes[33..65].to_vec())),
        ]
        .into_iter()
        .map(|(k, v)| (Value::Integer(k.into()), v))
        .collect(),
    )
}
fn registration(ctx: &Context, mutate: impl FnOnce(&mut Value, &mut Vec<u8>)) -> Registration {
    let mut auth = header(ctx, 0x45, 0);
    auth.extend([0; 16]);
    auth.extend([0, 3]);
    auth.extend([1, 2, 3]);
    let mut key = cose();
    mutate(&mut key, &mut auth);
    auth.extend(cbor_bytes(&key));
    let object = Value::Map(vec![
        (Value::Text("fmt".into()), Value::Text("none".into())),
        (Value::Text("attStmt".into()), Value::Map(vec![])),
        (Value::Text("authData".into()), Value::Bytes(auth)),
    ]);
    Registration {
        id: B64.encode([1, 2, 3]),
        client_data: B64.encode(client(ctx, "webauthn.create")),
        attestation: B64.encode(cbor_bytes(&object)),
    }
}
fn stored(be: bool, counter: u32) -> StoredCredential {
    StoredCredential {
        id: B64.encode([1, 2, 3]),
        public_key: B64.encode(cbor_bytes(&cose())),
        user_handle: B64.encode(b"account"),
        counter,
        backup_eligible: be,
    }
}
fn assertion(ctx: &Context, flags: u8, counter: u32, tail: &[u8]) -> Assertion {
    let client = client(ctx, "webauthn.get");
    let mut auth = header(ctx, flags, counter);
    auth.extend(tail);
    let mut signed = auth.clone();
    signed.extend(Sha256::digest(&client));
    let sig: Signature = key().sign(&signed);
    Assertion {
        id: B64.encode([1, 2, 3]),
        client_data: B64.encode(client),
        authenticator_data: B64.encode(auth),
        signature: B64.encode(sig.to_der().as_bytes()),
        user_handle: Some(B64.encode(b"account")),
    }
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn none_registration_and_es256_assertion() {
    let ctx = context();
    let proof = register(&ctx, registration(&ctx, |_, _| {})).unwrap();
    assert_eq!(proof.id, B64.encode([1, 2, 3]));
    let result = authenticate(&ctx, &stored(false, 0), assertion(&ctx, 5, 1, &[])).unwrap();
    assert_eq!(result.counter, 1);
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn registration_rejects_wrong_cose_profile_duplicate_keys_and_coordinates() {
    let ctx = context();
    for (field, replacement) in [
        (1, Value::Integer(1.into())),
        (3, Value::Integer((-257).into())),
        (-1, Value::Integer(2.into())),
        (-2, Value::Bytes(vec![0; 31])),
        (-3, Value::Bytes(vec![0; 32])),
    ] {
        let response = registration(&ctx, |key, _| {
            key.as_map_mut()
                .unwrap()
                .iter_mut()
                .find(|(k, _)| k == &Value::Integer(field.into()))
                .unwrap()
                .1 = replacement;
        });
        assert!(register(&ctx, response).is_err());
    }
    let response = registration(&ctx, |key, _| {
        let map = key.as_map_mut().unwrap();
        map.push(map[0].clone());
    });
    assert!(register(&ctx, response).is_err());
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn registration_rejects_missing_up_uv_wrong_rp_and_at() {
    let ctx = context();
    for flags in [0x40, 0x41, 0x44, 5, 0x65, 0x55] {
        assert!(register(&ctx, registration(&ctx, |_, data| data[32] = flags)).is_err());
    }
    assert!(register(&ctx, registration(&ctx, |_, data| data[0] ^= 1)).is_err());
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn registration_rejects_wrong_format_nonempty_attestation_and_trailing_data() {
    let ctx = context();
    for field in ["fmt", "attStmt"] {
        let mut r = registration(&ctx, |_, _| {});
        let (mut v, _) = cbor(&decode(&r.attestation, 65536).unwrap(), 8).unwrap();
        let map = v.as_map_mut().unwrap();
        let value = &mut map
            .iter_mut()
            .find(|(k, _)| k == &Value::Text(field.into()))
            .unwrap()
            .1;
        *value = if field == "fmt" {
            Value::Text("packed".into())
        } else {
            Value::Map(vec![(Value::Text("sig".into()), Value::Bytes(vec![]))])
        };
        r.attestation = B64.encode(cbor_bytes(&v));
        assert!(register(&ctx, r).is_err());
    }
    let mut r = registration(&ctx, |_, _| {});
    let mut bytes = decode(&r.attestation, 65536).unwrap();
    bytes.push(0);
    r.attestation = B64.encode(bytes);
    assert!(register(&ctx, r).is_err());
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn assertion_rejects_signature_and_bound_identity_changes() {
    let ctx = context();
    for case in 0..5 {
        let mut a = assertion(&ctx, 5, 1, &[]);
        match case {
            0 => a.id = B64.encode([4]),
            1 => a.user_handle = Some(B64.encode(b"other")),
            2 => {
                let mut bytes = decode(&a.signature, 80).unwrap();
                bytes[10] ^= 1;
                a.signature = B64.encode(bytes);
            }
            3 => {
                let mut bytes = decode(&a.authenticator_data, 65536).unwrap();
                bytes[0] ^= 1;
                a.authenticator_data = B64.encode(bytes);
            }
            _ => a.signature = B64.encode([0; 64]),
        }
        assert!(authenticate(&ctx, &stored(false, 0), a).is_err());
    }
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn rejects_client_data_rebinding_cross_origin_and_duplicate_required_fields() {
    let ctx = context();
    for (name, value) in [
        ("type", serde_json::json!("webauthn.create")),
        ("challenge", serde_json::json!(B64.encode([4; 32]))),
        ("origin", serde_json::json!("https://evil.example")),
        ("crossOrigin", serde_json::json!(true)),
        ("topOrigin", serde_json::json!("https://frame.example")),
    ] {
        let mut a = assertion(&ctx, 5, 1, &[]);
        let mut data: serde_json::Value =
            serde_json::from_slice(&decode(&a.client_data, 65536).unwrap()).unwrap();
        data[name] = value;
        a.client_data = B64.encode(serde_json::to_vec(&data).unwrap());
        assert!(authenticate(&ctx, &stored(false, 0), a).is_err());
    }
    let mut a = assertion(&ctx, 5, 1, &[]);
    let original = String::from_utf8(decode(&a.client_data, 65536).unwrap()).unwrap();
    a.client_data = B64.encode(original.replacen('{', "{\"type\":\"webauthn.get\",", 1));
    assert!(authenticate(&ctx, &stored(false, 0), a).is_err());
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn backup_and_counter_policy() {
    let ctx = context();
    for (be, prior, flags, next, valid) in [
        (false, 0, 5, 0, true),
        (false, 2, 5, 2, false),
        (false, 2, 5, 1, false),
        (false, 2, 5, 3, true),
        (true, 5, 13, 0, true),
        (true, 5, 29, 0, true),
        (false, 0, 13, 1, false),
        (true, 0, 5, 1, false),
        (false, 0, 21, 1, false),
    ] {
        assert_eq!(
            authenticate(&ctx, &stored(be, prior), assertion(&ctx, flags, next, &[])).is_ok(),
            valid
        );
    }
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn assertion_structure_and_signed_extension_map() {
    let ctx = context();
    for flags in [0, 1, 4, 0x45, 0x27] {
        assert!(authenticate(&ctx, &stored(false, 0), assertion(&ctx, flags, 1, &[])).is_err());
    }
    assert!(authenticate(&ctx, &stored(false, 0), assertion(&ctx, 5, 1, &[0])).is_err());
    assert!(authenticate(&ctx, &stored(false, 0), assertion(&ctx, 0x85, 1, &[0xa0])).is_ok());
    for tail in [&[0x80][..], &[0xa0, 0][..], &[][..]] {
        assert!(authenticate(&ctx, &stored(false, 0), assertion(&ctx, 0x85, 1, tail)).is_err());
    }
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn rejects_noncanonical_base64_truncated_oversized_and_deep_inputs() {
    let ctx = context();
    let mut r = registration(&ctx, |_, _| {});
    r.id.push('=');
    assert!(register(&ctx, r).is_err());
    for len in [0, 1, 10, 36, 37, 54] {
        let mut r = registration(&ctx, |_, _| {});
        r.attestation = B64.encode(vec![0; len]);
        assert!(register(&ctx, r).is_err());
    }
    assert!(bounded_json(&"[".repeat(9), 65536, 8).is_err());
    assert!(bounded_json("{}", 1, 8).is_err());
    let mut nested = Value::Null;
    for _ in 0..10 {
        nested = Value::Array(vec![nested]);
    }
    assert!(cbor(&cbor_bytes(&nested), 8).is_err());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn strict_json_rejects_unknown_field_duplicates_and_unicode_aliases() {
    assert!(strict_json(r#"{"a":[1,null,true,"[]"],"b":{"c":2}}"#, 65536, 8).is_ok());
    for input in [
        r#"{"a":1,"a":2}"#,
        r#"{"a":1,"\u0061":2}"#,
        r#"{"a":{"unknown":1,"unknown":2}}"#,
        r#"{} trailing"#,
    ] {
        assert!(strict_json(input, 65536, 8).is_err());
    }
}

fn packed_registration(ctx: &Context, mutate: impl FnOnce(&mut Value)) -> Registration {
    let mut response = registration(ctx, |_, _| {});
    let (mut object, _) = cbor(&decode(&response.attestation, 65536).unwrap(), 8).unwrap();
    let mut signed = text_field(&object, "authData")
        .unwrap()
        .as_bytes()
        .unwrap()
        .clone();
    signed.extend(Sha256::digest(client(ctx, "webauthn.create")));
    let signature: Signature = key().sign(&signed);
    for (name, value) in object.as_map_mut().unwrap() {
        if name.as_text() == Some("fmt") {
            *value = Value::Text("packed".into());
        }
        if name.as_text() == Some("attStmt") {
            *value = Value::Map(vec![
                (Value::Text("alg".into()), Value::Integer((-7).into())),
                (
                    Value::Text("sig".into()),
                    Value::Bytes(signature.to_der().as_bytes().to_vec()),
                ),
            ]);
        }
    }
    mutate(&mut object);
    response.attestation = B64.encode(cbor_bytes(&object));
    response
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn packed_self_verifies_signature_and_rejects_full_attestation_fallback() {
    let ctx = context();
    assert!(register(&ctx, packed_registration(&ctx, |_| {})).is_ok());
    for case in 0..9 {
        let response = packed_registration(&ctx, |object| {
            let statement = &mut object
                .as_map_mut()
                .unwrap()
                .iter_mut()
                .find(|(k, _)| k.as_text() == Some("attStmt"))
                .unwrap()
                .1;
            let map = statement.as_map_mut().unwrap();
            match case {
                0 => map[0].1 = Value::Integer((-257).into()),
                1 => map[1].1 = Value::Bytes(vec![0; 64]), // raw R|S is not DER
                2 => map[1].1.as_bytes_mut().unwrap()[10] ^= 1,
                3 => {
                    map.pop();
                }
                4 => map.push((Value::Text("x5c".into()), Value::Array(vec![]))),
                5 => map.push((Value::Text("x5c".into()), Value::Null)),
                6 => map.push((Value::Text("ecdaaKeyId".into()), Value::Bytes(vec![]))),
                7 => map.push(map[0].clone()),
                _ => map[1].0 = Value::Text("x5c".into()),
            }
        });
        assert!(register(&ctx, response).is_err(), "case {case}");
    }
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn packed_self_binds_raw_authenticator_and_client_data() {
    let ctx = context();
    let response = packed_registration(&ctx, |object| {
        let data = &mut object
            .as_map_mut()
            .unwrap()
            .iter_mut()
            .find(|(k, _)| k.as_text() == Some("authData"))
            .unwrap()
            .1;
        data.as_bytes_mut().unwrap()[36] ^= 1; // valid counter structure, invalid signature
    });
    assert!(register(&ctx, response).is_err());
    let mut response = packed_registration(&ctx, |_| {});
    let mut client_bytes = decode(&response.client_data, 65536).unwrap();
    client_bytes.push(b' '); // semantically identical JSON, distinct signed hash
    response.client_data = B64.encode(client_bytes);
    assert!(register(&ctx, response).is_err());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn ceremony_policy_binds_uv_account_allow_list_and_optional_handle() {
    let mut ctx = context();
    let mut a = assertion(&ctx, 1, 1, &[]);
    a.user_handle = None;
    assert!(authenticate(&ctx, &stored(false, 0), a).is_err());
    ctx.user_verification = UserVerification::Preferred;
    for case in 0..5 {
        ctx.authentication = Authentication::Identified {
            user_handle: B64.encode(if case == 1 {
                &b"other"[..]
            } else {
                &b"account"[..]
            }),
            allowed_credentials: if case == 2 {
                vec![]
            } else {
                vec![B64.encode([1, 2, 3])]
            },
        };
        let mut a = assertion(&ctx, 1, 1, &[]);
        a.user_handle = match case {
            3 => Some(B64.encode(b"other")),
            4 => Some(B64.encode(b"account")),
            _ => None,
        };
        let result = authenticate(&ctx, &stored(false, 0), a);
        assert_eq!(result.is_ok(), case == 0 || case == 4);
        if let Ok(proof) = result {
            assert!(!proof.user_verified);
        }
    }
    ctx.authentication = Authentication::Discoverable;
    let mut a = assertion(&ctx, 1, 1, &[]);
    a.user_handle = None;
    assert!(authenticate(&ctx, &stored(false, 0), a).is_err());
    assert!(authenticate(&ctx, &stored(false, 0), assertion(&ctx, 1, 1, &[])).is_ok());
    ctx.user_verification = UserVerification::Required;
    assert!(authenticate(&ctx, &stored(false, 0), assertion(&ctx, 1, 1, &[])).is_err());
    ctx.user_verification = UserVerification::Discouraged;
    assert!(authenticate(&ctx, &stored(false, 0), assertion(&ctx, 0, 1, &[])).is_err());
    assert!(
        authenticate(&ctx, &stored(false, 0), assertion(&ctx, 5, 1, &[]))
            .unwrap()
            .user_verified
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn independent_openssl_rsa_and_ed25519_vectors() {
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("../testdata/signatures.json")).unwrap();
    for v in vectors.as_array().unwrap() {
        let alg = v["alg"].as_i64().unwrap();
        let jwk = &v["publicKey"];
        let bytes = |name: &str| Value::Bytes(B64.decode(jwk[name].as_str().unwrap()).unwrap());
        let fields = if alg == -8 {
            vec![
                (1, Value::Integer(1.into())),
                (3, Value::Integer(alg.into())),
                (-1, Value::Integer(6.into())),
                (-2, bytes("x")),
            ]
        } else {
            vec![
                (1, Value::Integer(3.into())),
                (3, Value::Integer(alg.into())),
                (-1, bytes("n")),
                (-2, bytes("e")),
            ]
        };
        let value = Value::Map(
            fields
                .into_iter()
                .map(|(k, v)| (Value::Integer(k.into()), v))
                .collect(),
        );
        let key = PublicKey::parse(&value).unwrap();
        let message = B64.decode(v["message"].as_str().unwrap()).unwrap();
        let mut signature = B64.decode(v["signature"].as_str().unwrap()).unwrap();
        key.verify(&message, &signature).unwrap();
        signature[0] ^= 1;
        assert!(key.verify(&message, &signature).is_err());
        let mut private = value.clone();
        private
            .as_map_mut()
            .unwrap()
            .push((Value::Integer((-4).into()), Value::Bytes(vec![1])));
        assert!(PublicKey::parse(&private).is_err());
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn independent_attestation_paths_and_tpm_bindings() {
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("../testdata/attestations.json")).unwrap();
    for case in vectors["registrations"].as_array().unwrap() {
        let ctx: Context = serde_json::from_value(case["context"].clone()).unwrap();
        let response = serde_json::from_value(case["response"].clone()).unwrap();
        assert_eq!(
            register(&ctx, response).is_ok(),
            case["ok"].as_bool().unwrap(),
            "{}",
            case["name"]
        );
    }
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn independent_mds_signatures_revocation_and_freshness() {
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("../testdata/attestations.json")).unwrap();
    for case in vectors["mds"].as_array().unwrap() {
        let input = serde_json::from_value(case["input"].clone()).unwrap();
        let result = metadata::verify_mds(input);
        assert_eq!(
            result.is_ok(),
            case["ok"].as_bool().unwrap(),
            "{}",
            case["name"]
        );
        if let Ok(verified) = result {
            assert_eq!(verified.number, 1);
            assert_eq!(verified.issued_at, case["input"]["now"].as_u64().unwrap());
            match (case["no_next_update"].as_bool(), verified.next_update) {
                (Some(true), None) => {}
                (Some(true), _) => panic!("nextUpdate should be absent"),
                (_, Some(next_update)) => assert!(next_update > 0),
                (_, None) => panic!("nextUpdate should be retained when present"),
            }
            if case["past_next_update"] == true {
                assert!(verified.next_update.unwrap() <= case["input"]["now"].as_u64().unwrap());
            }
            assert_eq!(verified.entries.len(), 1);
            assert_eq!(
                verified.entries[0].allowed,
                case["allowed"].as_bool().unwrap_or(true)
            );
            if let Some(key_id) = case["key_id"].as_str() {
                assert_eq!(verified.entries[0].aaguid, "");
                assert_eq!(verified.entries[0].key_ids, vec![key_id.to_owned()]);
            }
            if let Some(status) = case["status"].as_str() {
                assert_eq!(verified.entries[0].status_reports[0].status, status);
            }
            if case["name"] == "valid MDS" {
                assert_eq!(
                    verified.entries[0].status_reports[0].status,
                    "FIDO_CERTIFIED"
                );
                assert_eq!(
                    verified.entries[0].status_reports[0].details["authenticatorVersion"],
                    1
                );
                assert!(verified.entries[0].time_of_last_status_change.is_some());
            }
            if case["name"] == "valid U2F metadata" {
                let registration = vectors["registrations"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|v| v["name"] == "U2F")
                    .unwrap();
                let mut ctx: Context =
                    serde_json::from_value(registration["context"].clone()).unwrap();
                ctx.attestation = Some(Trust {
                    now: serde_json::from_value(case["input"]["now"].clone()).unwrap(),
                    entries: verified.entries,
                });
                ctx.attestation_policy = AttestationPolicy::RequiredTrusted;
                let proof = register(
                    &ctx,
                    serde_json::from_value(registration["response"].clone()).unwrap(),
                )
                .unwrap();
                assert_eq!(
                    proof.attestation().trust().unwrap().metadata_key(),
                    case["key_id"]
                );
            }
        }
    }
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn legacy_token_binding_structure() {
    let ctx = context();
    for value in [
        serde_json::json!(null),
        serde_json::json!(false),
        serde_json::json!([]),
        serde_json::json!({}),
        serde_json::json!({"status":"unknown"}),
        serde_json::json!({"status":"present"}),
    ] {
        let mut client: serde_json::Value =
            serde_json::from_slice(&client(&ctx, "webauthn.create")).unwrap();
        client["tokenBinding"] = value;
        assert!(
            client_data(
                &ctx,
                &B64.encode(serde_json::to_vec(&client).unwrap()),
                "webauthn.create"
            )
            .is_err()
        );
    }
}

fn registration_with_extensions(ctx: &Context, tail: &[u8]) -> Registration {
    let mut response = registration(ctx, |_, _| {});
    let (mut object, _) = cbor(&decode(&response.attestation, 65536).unwrap(), 8).unwrap();
    let data = object
        .as_map_mut()
        .unwrap()
        .iter_mut()
        .find(|(key, _)| key.as_text() == Some("authData"))
        .unwrap()
        .1
        .as_bytes_mut()
        .unwrap();
    data[32] |= 0x80;
    data.extend(tail);
    response.attestation = B64.encode(cbor_bytes(&object));
    response
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn extension_identifiers_must_be_text_for_registration_and_authentication() {
    let ctx = context();
    for identifier in [
        Value::Integer(1.into()),
        Value::Bytes(vec![1]),
        Value::Null,
        Value::Bool(true),
    ] {
        let tail = cbor_bytes(&Value::Map(vec![(identifier, Value::Bool(true))]));
        assert!(register(&ctx, registration_with_extensions(&ctx, &tail)).is_err());
        assert!(authenticate(&ctx, &stored(false, 0), assertion(&ctx, 0x85, 1, &tail)).is_err());
    }
    let duplicate = cbor_bytes(&Value::Map(vec![
        (Value::Text("unknown".into()), Value::Bool(true)),
        (Value::Text("unknown".into()), Value::Bool(false)),
    ]));
    assert!(register(&ctx, registration_with_extensions(&ctx, &duplicate)).is_err());
    assert!(
        authenticate(
            &ctx,
            &stored(false, 0),
            assertion(&ctx, 0x85, 1, &duplicate)
        )
        .is_err()
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn unknown_extension_structure_is_accepted_but_assertion_bytes_are_signature_bound() {
    let ctx = context();
    let tail = cbor_bytes(&Value::Map(vec![(
        Value::Text("futureExtension".into()),
        Value::Bool(true),
    )]));
    let proof = register(&ctx, registration_with_extensions(&ctx, &tail)).unwrap();
    assert!(
        serde_json::to_value(proof)
            .unwrap()
            .get("extensions")
            .is_none()
    );
    let a = assertion(&ctx, 0x85, 1, &tail);
    let proof = authenticate(&ctx, &stored(false, 0), a).unwrap();
    assert!(
        serde_json::to_value(proof)
            .unwrap()
            .get("extensions")
            .is_none()
    );
    let mut changed = assertion(&ctx, 0x85, 1, &tail);
    let mut bytes = decode(&changed.authenticator_data, 65536).unwrap();
    // CBOR true -> false preserves structure, but must fail signature validation.
    *bytes.last_mut().unwrap() = 0xf4;
    changed.authenticator_data = B64.encode(bytes);
    assert!(authenticate(&ctx, &stored(false, 0), changed).is_err());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn diagnostic_codes_distinguish_bindings_flags_and_signatures_without_payloads() {
    let ctx = context();
    for (field, value, expected) in [
        (
            "type",
            "webauthn.create".to_owned(),
            Invalid::ClientDataType,
        ),
        ("challenge", B64.encode([9; 32]), Invalid::Challenge),
        (
            "origin",
            "https://untrusted.example".to_owned(),
            Invalid::Origin,
        ),
    ] {
        let mut a = assertion(&ctx, 5, 1, &[]);
        let mut data: serde_json::Value =
            serde_json::from_slice(&client(&ctx, "webauthn.get")).unwrap();
        data[field] = value.into();
        a.client_data = B64.encode(serde_json::to_vec(&data).unwrap());
        let error = authenticate(&ctx, &stored(false, 0), a).err().unwrap();
        assert_eq!(error, expected);
        assert_eq!(Invalid::from_code(error.code()), Some(error));
        assert_eq!(error.to_string(), error.code());
    }
    for (flags, counter, expected) in [
        (4, 1, Invalid::UserPresence),
        (1, 1, Invalid::UserVerification),
        (21, 1, Invalid::Backup),
        (5, 0, Invalid::Counter),
    ] {
        assert_eq!(
            authenticate(
                &ctx,
                &stored(false, 1),
                assertion(&ctx, flags, counter, &[])
            )
            .err(),
            Some(expected)
        );
    }
    let mut a = assertion(&ctx, 5, 1, &[]);
    a.user_handle = None;
    assert_eq!(
        authenticate(&ctx, &stored(false, 0), a).err(),
        Some(Invalid::UserHandle)
    );
    let mut a = assertion(&ctx, 5, 1, &[]);
    let mut raw = decode(&a.authenticator_data, 65536).unwrap();
    raw[0] ^= 1;
    a.authenticator_data = B64.encode(raw);
    assert_eq!(
        authenticate(&ctx, &stored(false, 0), a).err(),
        Some(Invalid::RpId)
    );
    let mut a = assertion(&ctx, 5, 1, &[]);
    a.signature = B64.encode([0; 64]);
    assert_eq!(
        authenticate(&ctx, &stored(false, 0), a).err(),
        Some(Invalid::Signature)
    );
    assert_eq!(strict_json("{}", 1, 8), Err(Invalid::Limit));
    assert_eq!(strict_json("invalid", 100, 8), Err(Invalid::Input));
    assert_eq!(Invalid::from_code("credential secret response"), None);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn independent_trust_fixtures_have_stable_diagnostic_codes() {
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("../testdata/attestations.json")).unwrap();
    for (name, expected) in [
        ("untrusted root", Invalid::CertificatePath),
        ("expired certificate", Invalid::CertificateTime),
        ("revoked metadata", Invalid::Revoked),
        ("wrong AAGUID", Invalid::Trust),
        ("reordered chain", Invalid::Certificate),
        ("duplicate chain", Invalid::CertificatePath),
        ("TPM magic", Invalid::Tpm),
        ("TPM extraData", Invalid::Tpm),
    ] {
        let case = vectors["registrations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["name"] == name)
            .unwrap();
        let ctx = serde_json::from_value(case["context"].clone()).unwrap();
        let response = serde_json::from_value(case["response"].clone()).unwrap();
        assert_eq!(register(&ctx, response).err(), Some(expected), "{name}");
    }
    for (name, expected) in [
        ("revoked signer", Invalid::Revoked),
        ("missing CRLs", Invalid::Crl),
        // This fixture advances time past both certificate and CRL validity.
        ("expired CRL", Invalid::CertificateTime),
        ("bad JWT signature", Invalid::Signature),
        ("missing BLOB number", Invalid::Metadata),
        ("missing issued-at", Invalid::Metadata),
        ("x5u transport is unsupported", Invalid::Metadata),
    ] {
        let case = vectors["mds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["name"] == name)
            .unwrap();
        assert_eq!(
            metadata::verify_mds(serde_json::from_value(case["input"].clone()).unwrap()).err(),
            Some(expected),
            "{name}"
        );
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn invalid_trusted_configuration_is_rejected_at_both_verification_entries() {
    let mutations: &[fn(&mut Context)] = &[
        |c| c.challenge.clear(),
        |c| c.challenge.push('='),
        |c| c.origin.clear(),
        |c| c.rp_id.clear(),
        |c| c.origin.push(' '),
        |c| c.max_bytes = 0,
        |c| c.max_depth = 0,
        |c| c.algorithms.clear(),
        |c| c.algorithms = vec![-7, -7],
        |c| c.algorithms = vec![-999],
        |c| {
            c.authentication = Authentication::Identified {
                user_handle: B64.encode([1]),
                allowed_credentials: vec![],
            }
        },
        |c| {
            c.authentication = Authentication::Identified {
                user_handle: String::new(),
                allowed_credentials: vec![B64.encode([1])],
            }
        },
        |c| {
            c.authentication = Authentication::Identified {
                user_handle: B64.encode([1]),
                allowed_credentials: vec!["invalid=".into()],
            }
        },
    ];
    for mutate in mutations {
        let mut ctx = context();
        mutate(&mut ctx);
        assert_eq!(ctx.validate(), Err(Invalid::Configuration));
        assert_eq!(
            register(&ctx, registration(&ctx, |_, _| {})).err(),
            Some(Invalid::Configuration)
        );
        assert_eq!(
            authenticate(&ctx, &stored(false, 0), assertion(&ctx, 5, 1, &[])).err(),
            Some(Invalid::Configuration)
        );
    }
    let mut ctx = context();
    ctx.algorithms = vec![-7, -8, -257, -65535];
    assert_eq!(ctx.validate(), Ok(()));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn required_attestation_rejects_none_and_self_even_with_trust_material() {
    let mut ctx = context();
    // Supplying trust material does not implicitly require attestation.
    ctx.attestation = Some(Trust {
        now: 1,
        entries: vec![],
    });
    for self_signed in [false, true] {
        let response = |ctx: &Context| {
            if self_signed {
                packed_registration(ctx, |_| {})
            } else {
                registration(ctx, |_, _| {})
            }
        };
        let proof = register(&ctx, response(&ctx)).unwrap();
        assert_eq!(
            proof.attestation().kind(),
            if self_signed { "self" } else { "none" }
        );
        assert!(proof.attestation().trust().is_none());
        assert_eq!(proof.attestation().aaguid(), B64.encode([0; 16]));
        ctx.attestation_policy = AttestationPolicy::RequiredTrusted;
        assert_eq!(
            register(&ctx, response(&ctx)).err(),
            Some(Invalid::AttestationPolicy)
        );
        ctx.attestation_policy = AttestationPolicy::Optional;
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn required_attestation_preserves_fixture_rejections_and_returns_trust_evidence() {
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("../testdata/attestations.json")).unwrap();
    for case in vectors["registrations"].as_array().unwrap() {
        let mut ctx: Context = serde_json::from_value(case["context"].clone()).unwrap();
        ctx.attestation_policy = AttestationPolicy::RequiredTrusted;
        let result = register(
            &ctx,
            serde_json::from_value(case["response"].clone()).unwrap(),
        );
        assert_eq!(
            result.is_ok(),
            case["ok"].as_bool().unwrap(),
            "{}",
            case["name"]
        );
        if let Ok(proof) = result {
            let evidence = proof.attestation();
            assert_eq!(evidence.kind(), "trusted");
            let expected_format = match case["name"].as_str().unwrap() {
                "packed chain" => "packed",
                "U2F" => "fido-u2f",
                "TPM RSA" => "tpm",
                _ => unreachable!(),
            };
            assert_eq!(evidence.format(), expected_format);
            let trust = evidence.trust().unwrap();
            let configured = ctx.attestation.as_ref().unwrap();
            let entry = &configured.entries[0];
            assert_eq!(
                trust.metadata_key(),
                if expected_format == "fido-u2f" {
                    &entry.key_ids[0]
                } else {
                    &entry.aaguid
                }
            );
            assert_eq!(
                trust.anchor_sha256(),
                B64.encode(Sha256::digest(decode(&entry.roots[0], 16384).unwrap()))
            );
            assert_eq!(trust.verified_at(), configured.now);
            ctx.attestation = None;
            assert_eq!(
                register(
                    &ctx,
                    serde_json::from_value(case["response"].clone()).unwrap()
                )
                .err(),
                Some(Invalid::Trust)
            );
        }
    }
    // Directly trusted batch certificates report that exact certificate as anchor.
    let case = &vectors["registrations"][0];
    let mut ctx: Context = serde_json::from_value(case["context"].clone()).unwrap();
    let mut response: Registration = serde_json::from_value(case["response"].clone()).unwrap();
    let (mut object, _) = cbor(&decode(&response.attestation, 65536).unwrap(), 8).unwrap();
    let statement = object
        .as_map_mut()
        .unwrap()
        .iter_mut()
        .find(|(k, _)| k.as_text() == Some("attStmt"))
        .unwrap();
    let chain = statement
        .1
        .as_map_mut()
        .unwrap()
        .iter_mut()
        .find(|(k, _)| k.as_text() == Some("x5c"))
        .unwrap()
        .1
        .as_array_mut()
        .unwrap();
    chain.truncate(1);
    let anchor = chain[0].as_bytes().unwrap().clone();
    ctx.attestation.as_mut().unwrap().entries[0].roots = vec![B64.encode(&anchor)];
    ctx.attestation_policy = AttestationPolicy::RequiredTrusted;
    response.attestation = B64.encode(cbor_bytes(&object));
    let proof = register(&ctx, response).unwrap();
    assert_eq!(
        proof.attestation().trust().unwrap().anchor_sha256(),
        B64.encode(Sha256::digest(anchor))
    );
}
