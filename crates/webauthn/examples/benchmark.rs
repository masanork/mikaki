//! Offline microbenchmark: public fixtures, identical checks, no transport or DB.
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use mikaki_webauthn::{Assertion, Context, Registration, StoredCredential};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{hint::black_box, time::Instant};

fn cases() -> Vec<Value> {
    let fixtures: Value =
        serde_json::from_str(include_str!("../testdata/attestations.json")).unwrap();
    let mut cases = fixtures["registrations"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["ok"] == true)
        .cloned()
        .collect::<Vec<_>>();
    let mut none = cases[0].clone();
    let att = B64
        .decode(none["response"]["attestation"].as_str().unwrap())
        .unwrap();
    let mut object: ciborium::Value = ciborium::from_reader(att.as_slice()).unwrap();
    let map = object.as_map_mut().unwrap();
    let mut auth = vec![];
    for (name, value) in map {
        match name.as_text() {
            Some("fmt") => *value = ciborium::Value::Text("none".into()),
            Some("attStmt") => *value = ciborium::Value::Map(vec![]),
            Some("authData") => auth = value.as_bytes().unwrap().clone(),
            _ => (),
        }
    }
    let mut bytes = vec![];
    ciborium::into_writer(&object, &mut bytes).unwrap();
    none["name"] = json!("none ES256");
    none["response"]["attestation"] = json!(B64.encode(bytes));
    none["context"]["attestation"] = Value::Null;
    cases.push(none.clone());
    let mut context = none["context"].clone();
    context["authentication"] = json!({"mode":"discoverable"});
    let client = serde_json::to_vec(&json!({"type":"webauthn.get","challenge":context["challenge"],"origin":context["origin"],"crossOrigin":false})).unwrap();
    let id_len = usize::from(u16::from_be_bytes([auth[53], auth[54]]));
    let public_key = B64.encode(&auth[55 + id_len..]);
    auth.truncate(37);
    auth[32] = 5;
    auth[36] = 1;
    let mut message = auth.clone();
    message.extend(Sha256::digest(&client));
    // Public test key shared with the independent fixture generator; never a product key.
    let key = SigningKey::from_slice(&[7; 32]).unwrap();
    let signature: Signature = key.sign(&message);
    let id = none["response"]["id"].clone();
    let handle = B64.encode([1; 32]);
    let mut assertion = json!({"name":"assertion ES256","ok":true,"context":context,
        "credential":{"id":id,"public_key":public_key,"user_handle":handle,"counter":0,"backup_eligible":false},
        "response":{"id":id,"client_data":B64.encode(client),"authenticator_data":B64.encode(auth),"signature":B64.encode(signature.to_der().as_bytes()),"user_handle":handle}});
    cases.push(assertion.clone());
    let mut invalid = signature.to_der().as_bytes().to_vec();
    *invalid.last_mut().unwrap() ^= 1;
    assertion["name"] = json!("assertion invalid signature");
    assertion["ok"] = json!(false);
    assertion["response"]["signature"] = json!(B64.encode(invalid));
    cases.push(assertion);
    cases
}
fn run(case: &Value, iterations: usize) -> Value {
    let context: Context = serde_json::from_value(case["context"].clone()).unwrap();
    let registration = case.get("credential").is_none();
    let expected = case["ok"].as_bool().unwrap();
    let mut operation: Box<dyn FnMut()> = if registration {
        let response: Registration = serde_json::from_value(case["response"].clone()).unwrap();
        Box::new(move || {
            let response = Registration {
                id: response.id.clone(),
                client_data: response.client_data.clone(),
                attestation: response.attestation.clone(),
            };
            assert_eq!(
                black_box(mikaki_webauthn::register(&context, response)).is_ok(),
                expected
            );
        })
    } else {
        let response: Assertion = serde_json::from_value(case["response"].clone()).unwrap();
        let credential: StoredCredential =
            serde_json::from_value(case["credential"].clone()).unwrap();
        Box::new(move || {
            let response = Assertion {
                id: response.id.clone(),
                client_data: response.client_data.clone(),
                authenticator_data: response.authenticator_data.clone(),
                signature: response.signature.clone(),
                user_handle: response.user_handle.clone(),
            };
            assert_eq!(
                black_box(mikaki_webauthn::authenticate(
                    &context,
                    &credential,
                    response
                ))
                .is_ok(),
                expected
            );
        })
    };
    for _ in 0..5 {
        operation();
    }
    let mut samples = vec![];
    for _ in 0..7 {
        let start = Instant::now();
        for _ in 0..iterations {
            operation();
        }
        samples.push(start.elapsed().as_secs_f64() * 1e6 / iterations as f64);
    }
    samples.sort_by(f64::total_cmp);
    json!({"name":case["name"],"iterations_per_sample":iterations,"samples":7,"median_us":samples[3],"min_us":samples[0],"max_us":samples[6]})
}
fn main() {
    let arg = std::env::args().nth(1).unwrap_or_else(|| "100".into());
    let cases = cases();
    if arg == "--export" {
        println!("{}", json!(cases));
        return;
    }
    let iterations: usize = arg.parse().expect("iterations or --export");
    assert!((1..=100_000).contains(&iterations));
    println!(
        "{}",
        json!({"boundary":"native core, including owned-response copies; excludes JSON/HTTP/DB","debug_assertions":cfg!(debug_assertions),"cases":cases.iter().map(|case|run(case,iterations)).collect::<Vec<_>>()})
    );
}
