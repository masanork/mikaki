use super::*;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use serde_json::{Value, json};

fn key(seed: u8) -> SigningKey {
    SigningKey::from_slice(&[seed; 32]).unwrap()
}

fn header(key: &SigningKey) -> Value {
    let point = key.verifying_key().to_sec1_point(false);
    json!({
        "alg": "ES256",
        "typ": "dbsc+jwt",
        "unused": {
            "kty": "EC",
            "crv": "P-256",
            "x": B64.encode(point.x().unwrap()),
            "y": B64.encode(point.y().unwrap()),
            "use": "sig"
        }
    })
}

fn claims(challenge: &str, now: Option<u64>) -> Value {
    let mut v = json!({
        "jti": challenge, "aud": "https://example.test/dbsc"
    });
    if let Some(t) = now {
        v["iat"] = json!(t);
    }
    v
}

fn sign(h: &Value, c: &Value, key: &SigningKey) -> String {
    let input = format!(
        "{}.{}",
        B64.encode(serde_json::to_vec(h).unwrap()),
        B64.encode(serde_json::to_vec(c).unwrap())
    );
    let signature: Signature = key.sign(input.as_bytes());
    format!("{input}.{}", B64.encode(signature.to_bytes()))
}

#[test]
fn test_dbsc_registration_success() {
    let signing_key = key(1);
    let now = 1730000000;
    let challenge = "test_challenge_1234567890abcdef";

    let h = header(&signing_key);
    let mut c = claims(challenge, Some(now));
    c["key"] = header(&signing_key)["unused"].clone();
    let jwt = sign(&h, &c, &signing_key);

    let verified = verify_dbsc_registration(&jwt, challenge, "https://example.test/dbsc", now)
        .expect("verification failed");
    assert_eq!(verified.challenge, challenge);
    assert_eq!(verified.issued_at, Some(now));
    assert!(!verified.thumbprint.is_empty());
}

#[test]
fn test_dbsc_registration_rejects_wrong_challenge_or_expiry() {
    let signing_key = key(1);
    let now = 1730000000;
    let challenge = "test_challenge_1234567890abcdef";
    let h = header(&signing_key);

    // Wrong challenge
    let mut c_wrong = claims("different_challenge", Some(now));
    c_wrong["key"] = header(&signing_key)["unused"].clone();
    let jwt = sign(&h, &c_wrong, &signing_key);
    assert_eq!(
        verify_dbsc_registration(&jwt, challenge, "https://example.test/dbsc", now),
        Err(InvalidDbscProof)
    );

    // Expired iat (too old)
    let mut c_old = claims(challenge, Some(now - 150));
    c_old["key"] = header(&signing_key)["unused"].clone();
    let jwt = sign(&h, &c_old, &signing_key);
    assert_eq!(
        verify_dbsc_registration(&jwt, challenge, "https://example.test/dbsc", now),
        Err(InvalidDbscProof)
    );

    // Future iat (too far ahead)
    let mut c_future = claims(challenge, Some(now + 70));
    c_future["key"] = header(&signing_key)["unused"].clone();
    let jwt = sign(&h, &c_future, &signing_key);
    assert_eq!(
        verify_dbsc_registration(&jwt, challenge, "https://example.test/dbsc", now),
        Err(InvalidDbscProof)
    );
}

#[test]
fn test_dbsc_registration_rejects_invalid_type_or_alg() {
    let signing_key = key(1);
    let now = 1730000000;
    let challenge = "test_challenge_1234567890abcdef";
    let mut c = claims(challenge, Some(now));
    c["key"] = header(&signing_key)["unused"].clone();

    // Invalid typ
    let mut h = header(&signing_key);
    h["typ"] = json!("dpop+jwt");
    let jwt = sign(&h, &c, &signing_key);
    assert_eq!(
        verify_dbsc_registration(&jwt, challenge, "https://example.test/dbsc", now),
        Err(InvalidDbscProof)
    );

    // Invalid alg
    let mut h = header(&signing_key);
    h["alg"] = json!("RS256");
    let jwt = sign(&h, &c, &signing_key);
    assert_eq!(
        verify_dbsc_registration(&jwt, challenge, "https://example.test/dbsc", now),
        Err(InvalidDbscProof)
    );
}

#[test]
fn test_dbsc_refresh_success_and_tampering() {
    let signing_key = key(1);
    let now = 1730000000;
    let challenge = "refresh_challenge_987654321";

    let h = json!({
        "alg": "ES256",
        "typ": "dbsc+jwt"
    });
    let c = json!({
        "jti": challenge,
        "sub": "session-123",
        "iat": now, "aud":"https://example.test/dbsc"
    });

    let jwt = sign(&h, &c, &signing_key);
    let sec1 = signing_key
        .verifying_key()
        .to_sec1_point(false)
        .as_bytes()
        .to_vec();

    let verified = verify_dbsc_refresh(
        &jwt,
        challenge,
        &sec1,
        "https://example.test/dbsc",
        "session-123",
        now,
    )
    .expect("refresh failed");
    assert_eq!(verified.challenge, challenge);
    assert_eq!(verified.session_id, Some("session-123".into()));

    // Tampered signature or different key fails
    let other_key = key(2);
    let tampered_jwt = sign(&h, &c, &other_key);
    assert_eq!(
        verify_dbsc_refresh(
            &tampered_jwt,
            challenge,
            &sec1,
            "https://example.test/dbsc",
            "session-123",
            now
        ),
        Err(InvalidDbscProof)
    );
}

#[test]
fn rejects_wrong_audience_and_wrong_refresh_session() {
    let signing_key = key(3);
    let now = 1_730_000_000;
    let challenge = "challenge_1234567890123456";
    let mut c = claims(challenge, Some(now));
    c["key"] = header(&signing_key)["unused"].clone();
    let h = header(&signing_key);
    let jwt = sign(&h, &c, &signing_key);
    assert_eq!(
        verify_dbsc_registration(&jwt, challenge, "https://other.test/dbsc", now),
        Err(InvalidDbscProof)
    );
    let refresh =
        json!({"jti": challenge, "sub": "other", "iat": now, "aud": "https://example.test/dbsc"});
    let jwt = sign(
        &json!({"alg":"ES256", "typ":"dbsc+jwt"}),
        &refresh,
        &signing_key,
    );
    let sec1 = signing_key.verifying_key().to_sec1_point(false);
    assert_eq!(
        verify_dbsc_refresh(
            &jwt,
            challenge,
            sec1.as_bytes(),
            "https://example.test/dbsc",
            "expected",
            now
        ),
        Err(InvalidDbscProof)
    );
}

#[test]
fn asynchronous_registration_and_refresh_verify_and_reject_forged_proofs() {
    let signer = key(4);
    let other = key(5);
    let now = 1_730_000_000;
    let challenge = "challenge_1234567890123456";
    let audience = "https://example.test/dbsc";
    let mut h = header(&signer);
    h["jwk"] = h.as_object_mut().unwrap().remove("unused").unwrap();
    let c = claims(challenge, Some(now));
    let valid = sign(&h, &c, &signer);
    assert!(
        crate::es256::ready(verify_dbsc_registration_async(
            &valid, challenge, audience, now
        ))
        .is_ok()
    );
    let forged = sign(&h, &c, &other);
    assert_eq!(
        crate::es256::ready(verify_dbsc_registration_async(
            &forged, challenge, audience, now
        )),
        Err(InvalidDbscProof)
    );
    let refresh = json!({"jti":challenge,"aud":audience,"sub":"session-123","iat":now});
    let h = json!({"alg":"ES256", "typ":"dbsc+jwt"});
    let point = signer.verifying_key().to_sec1_point(false);
    let valid = sign(&h, &refresh, &signer);
    assert!(
        crate::es256::ready(verify_dbsc_refresh_async(
            &valid,
            challenge,
            point.as_bytes(),
            audience,
            "session-123",
            now
        ))
        .is_ok()
    );
    let forged = sign(&h, &refresh, &other);
    assert_eq!(
        crate::es256::ready(verify_dbsc_refresh_async(
            &forged,
            challenge,
            point.as_bytes(),
            audience,
            "session-123",
            now
        )),
        Err(InvalidDbscProof)
    );
}

#[test]
fn registration_rejects_missing_ambiguous_and_invalid_keys() {
    let signer = key(6);
    let now = 1_730_000_000;
    let challenge = "challenge_1234567890123456";
    let audience = "https://example.test/dbsc";
    let mut h = header(&signer);
    let jwk = h.as_object_mut().unwrap().remove("unused").unwrap();
    let mut c = claims(challenge, Some(now));
    let check = |header: &Value, claims: &Value| {
        assert_eq!(
            verify_dbsc_registration(&sign(header, claims, &signer), challenge, audience, now),
            Err(InvalidDbscProof)
        );
    };
    check(&h, &c);
    h["jwk"] = jwk.clone();
    c["key"] = jwk.clone();
    check(&h, &c);
    h.as_object_mut().unwrap().remove("jwk");
    c["key"]["crv"] = json!("wrong");
    check(&h, &c);
    c["key"] = jwk;
    c["key"]["x"] = json!(B64.encode([1u8; 31]));
    check(&h, &c);
}
