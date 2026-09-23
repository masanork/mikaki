use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use mikaki_webauthn::{self as webauthn, Assertion, Context, Registration, StoredCredential};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

pub fn fixtures() -> &'static Value {
    static FIXTURES: OnceLock<Value> = OnceLock::new();
    FIXTURES.get_or_init(|| {
        serde_json::from_str(include_str!(
            "../../crates/webauthn/testdata/attestations.json"
        ))
        .unwrap()
    })
}
pub fn decode(value: &Value) -> Vec<u8> {
    B64.decode(value.as_str().unwrap()).unwrap()
}

// Two framing bytes select fixture and raw field. Remaining bytes are untrusted.
pub fn registration(data: &[u8]) -> bool {
    if data.len() < 2 || data.len() > 65_538 {
        return false;
    }
    let cases = fixtures()["registrations"].as_array().unwrap();
    let case = &cases[data[0] as usize % cases.len()];
    let ctx: Context = serde_json::from_value(case["context"].clone()).unwrap();
    let mut response: Registration = serde_json::from_value(case["response"].clone()).unwrap();
    if data[1].is_multiple_of(2) {
        response.attestation = B64.encode(&data[2..]);
    } else {
        response.client_data = B64.encode(&data[2..]);
    }
    let _ = webauthn::attestation_hint(&response.attestation);
    let accepted = webauthn::register(&ctx, response).is_ok();
    if let Ok(text) = std::str::from_utf8(&data[2..]) {
        let _ = webauthn::strict_json(text, 65_536, 8);
    }
    accepted
}

pub fn assertion_seed() -> &'static Value {
    static SEED: OnceLock<Value> = OnceLock::new();
    SEED.get_or_init(|| {
        let case = &fixtures()["registrations"][0];
        let ctx: Context = serde_json::from_value(case["context"].clone()).unwrap();
        let proof = webauthn::register(
            &ctx,
            serde_json::from_value(case["response"].clone()).unwrap(),
        )
        .unwrap();
        let proof = serde_json::to_value(proof).unwrap();
        let mut auth = Sha256::digest(ctx.rp_id.as_bytes()).to_vec();
        auth.extend([5, 0, 0, 0, 1]);
        let client = serde_json::to_vec(
            &json!({"type":"webauthn.get", "challenge":ctx.challenge,"origin":ctx.origin}),
        )
        .unwrap();
        let mut signed = auth.clone();
        signed.extend(Sha256::digest(&client));
        // Public test fixture key, matching generate_attestations.py; never a deployment key.
        let signature: Signature = SigningKey::from_slice(&[7; 32]).unwrap().sign(&signed);
        let seed = json!({
            "id": proof["id"], "public_key": proof["public_key"],
            "user_handle": B64.encode(b"account"), "counter": 0, "backup_eligible": false,
            "client_data": B64.encode(client),
            "authenticator_data": B64.encode(auth),
            "signature": B64.encode(signature.to_der().as_bytes()),
        });
        webauthn::authenticate(
            &ctx,
            &serde_json::from_value(seed.clone()).unwrap(),
            serde_json::from_value(seed.clone()).unwrap(),
        )
        .unwrap();
        seed
    })
}
pub fn assertion(data: &[u8]) {
    if data.is_empty() || data.len() > 65_537 {
        return;
    }
    let ctx: Context =
        serde_json::from_value(fixtures()["registrations"][0]["context"].clone()).unwrap();
    let mut stored: StoredCredential = serde_json::from_value(assertion_seed().clone()).unwrap();
    let mut response: Assertion = serde_json::from_value(assertion_seed().clone()).unwrap();
    let value = B64.encode(&data[1..]);
    match data[0] % 4 {
        0 => response.authenticator_data = value,
        1 => stored.public_key = value,
        2 => response.signature = value,
        _ => response.client_data = value,
    }
    let _ = webauthn::authenticate(&ctx, &stored, response);
}

pub fn metadata(data: &[u8]) -> bool {
    if data.len() < 2 || data.len() > 131_074 {
        return false;
    }
    if data[1] % 4 == 2 {
        let Ok(input) = serde_json::from_slice::<webauthn::metadata::MdsInput>(&data[2..]) else {
            return false;
        };
        let _ = webauthn::metadata::mds_crl_urls(&input.jwt);
        return webauthn::metadata::verify_mds(input).is_ok();
    }
    let cases = fixtures()["mds"].as_array().unwrap();
    let mut input: webauthn::metadata::MdsInput =
        serde_json::from_value(cases[data[0] as usize % cases.len()]["input"].clone()).unwrap();
    match data[1] % 4 {
        0 => {
            let Ok(text) = std::str::from_utf8(&data[2..]) else {
                return false;
            };
            input.jwt = text.to_owned();
        }
        1 => {
            if input.crls.is_empty() {
                input.crls.push(B64.encode(&data[2..]));
            } else {
                input.crls[0] = B64.encode(&data[2..]);
            }
        }
        _ => {
            let (_, tail) = input.jwt.split_once('.').unwrap();
            input.jwt = format!("{}.{}", B64.encode(&data[2..]), tail);
        }
    }
    let _ = webauthn::metadata::mds_crl_urls(&input.jwt);
    webauthn::metadata::verify_mds(input).is_ok()
}
