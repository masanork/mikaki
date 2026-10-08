use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use mikaki_identity::{
    card::DocumentType,
    evidence::{Evidence, TrustedKey, VerificationError, verify},
    issuance::{self, PublicJwk},
};
use p256::ecdsa::SigningKey;
use rsa::{Pkcs1v15Sign, RsaPrivateKey, traits::PublicKeyParts};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;
const NOW: u64 = 1_790_812_800;
fn key() -> &'static RsaPrivateKey {
    static KEY: OnceLock<RsaPrivateKey> = OnceLock::new();
    KEY.get_or_init(|| {
        RsaPrivateKey::new(&mut rand_core::UnwrapErr(getrandom::SysRng), 2048).unwrap()
    })
}
fn trust(kind: DocumentType) -> TrustedKey {
    TrustedKey {
        id: "fixture-only".into(),
        document_type: kind,
        n: B64.encode(key().n().to_be_bytes_trimmed_vartime()),
        e: B64.encode(key().e().to_be_bytes_trimmed_vartime()),
        subject_key_identifier: Some(B64.encode([42; 32])),
        not_before: NOW - 100,
        not_after: NOW + 10000,
    }
}
fn tlv(tag: u8, v: &[u8], out: &mut Vec<u8>) {
    out.push(tag);
    if v.len() < 128 {
        out.push(v.len() as u8);
    } else {
        out.extend([0x82, (v.len() >> 8) as u8, v.len() as u8]);
    }
    out.extend(v);
}
fn dl() -> Evidence {
    let mut e = Evidence::new(DocumentType::DrivingLicense);
    for (t, v) in [
        (0x12, &[0x30, 0x22][..]),
        (0x17, &[0x30, 0x22][..]),
        (0x16, &b"4020228"[..]),
        (0x1b, &b"5120101"[..]),
    ] {
        tlv(t, v, &mut e.attributes);
    }
    e.attributes.resize(880, 255);
    e.domicile = vec![255; 82];
    e.photo = vec![0; 2005];
    let hash = Sha256::digest([e.attributes.as_slice(), &e.domicile, &e.photo].concat());
    let sig = key().sign(Pkcs1v15Sign::new_unprefixed(), &hash).unwrap();
    tlv(0xb1, &sig, &mut e.signature);
    tlv(0xb6, &[42; 32], &mut e.signature);
    e.signature.resize(578, 255);
    e
}
fn mnc() -> Evidence {
    let mut e = Evidence::new(DocumentType::MyNumberCard);
    for (tag, v) in [
        (0x22, "試験 太郎"),
        (0x23, "東京都"),
        (0x24, "19900228"),
        (0x25, "1"),
    ] {
        e.attributes.extend([0xdf, tag, v.len() as u8]);
        e.attributes.extend(v.as_bytes());
    }
    let mut message = vec![0xdf, 0x31, 32];
    message.extend([11; 32]);
    message.extend([0xdf, 0x32, 32]);
    message.extend(Sha256::digest(&e.attributes));
    let sig = key()
        .sign(Pkcs1v15Sign::new::<Sha256>(), &Sha256::digest(&message))
        .unwrap();
    let mut body = message;
    body.extend([0xdf, 0x33, 0x82, 1, 0]);
    body.extend(sig);
    e.signature
        .extend([0xff, 0x30, 0x82, (body.len() >> 8) as u8, body.len() as u8]);
    e.signature.extend(body);
    e
}
#[test]
fn both_document_signatures_require_explicit_trusted_issuer() {
    for e in [dl(), mnc()] {
        let t = trust(e.document_type);
        let d = verify(&e, std::slice::from_ref(&t), NOW).unwrap();
        assert_eq!(d.assurance, "issuer_signed_static_data");
        assert_eq!(
            verify(&e, &[], NOW).unwrap_err(),
            VerificationError::UntrustedIssuer
        );
        assert_eq!(
            verify(&e, &[t], NOW + 10001).unwrap_err(),
            VerificationError::UntrustedIssuer
        );
    }
}
#[test]
fn dl_checks_full_photo_domicile_padding_key_identifier_and_expiry() {
    let mut e = dl();
    let t = trust(e.document_type);
    for section in [0, 1, 2] {
        let v = match section {
            0 => &mut e.attributes,
            1 => &mut e.domicile,
            _ => &mut e.photo,
        };
        let old = v[v.len() - 1];
        let n = v.len() - 1;
        v[n] ^= 1;
        assert!(verify(&e, std::slice::from_ref(&t), NOW).is_err());
        let v = match section {
            0 => &mut e.attributes,
            1 => &mut e.domicile,
            _ => &mut e.photo,
        };
        v[n] = old;
    }
    let mut wrong = t.clone();
    wrong.subject_key_identifier = Some(B64.encode([43; 32]));
    assert_eq!(
        verify(&e, &[wrong], NOW).unwrap_err(),
        VerificationError::UntrustedIssuer
    );
    e.photo.clear();
    assert_eq!(
        verify(&e, std::slice::from_ref(&t), NOW).unwrap_err(),
        VerificationError::InvalidEvidence
    );
    let e = dl();
    let mut future = t;
    future.not_after = u64::MAX;
    assert_eq!(
        verify(&e, &[future], 2_000_000_000).unwrap_err(),
        VerificationError::ExpiredDocument
    );
}
#[test]
fn mnc_rejects_unsigned_duplicate_prefix_and_tampered_signature() {
    let mut e = mnc();
    let t = trust(e.document_type);
    e.attributes[4] ^= 1;
    assert!(verify(&e, std::slice::from_ref(&t), NOW).is_err());
    let mut e = mnc();
    let mut pref = vec![0xdf, 0x22, 1, b'X'];
    pref.extend(&e.attributes);
    e.attributes = pref;
    assert!(verify(&e, std::slice::from_ref(&t), NOW).is_err());
    let mut e = mnc();
    let n = e.signature.len() - 1;
    e.signature[n] ^= 1;
    assert_eq!(
        verify(&e, &[t], NOW).unwrap_err(),
        VerificationError::SignatureInvalid
    );
}
#[test]
fn oid4vci_proof_and_receipt_bind_issuer_holder_nonce_and_disclosures() {
    let holder = SigningKey::from_slice(&[2; 32]).unwrap();
    let other = SigningKey::from_slice(&[3; 32]).unwrap();
    let issuerkey = SigningKey::from_slice(&[4; 32]).unwrap();
    let jwk = PublicJwk::from_key(holder.verifying_key());
    let nonce = "N".repeat(43);
    let issuer = "https://issuer.example/identity/issuer";
    let proof = issuance::create_proof(&holder, issuer, &nonce, NOW, &"j".repeat(32)).unwrap();
    assert!(issuance::verify_proof(&proof, &jwk, issuer, &nonce, NOW).is_ok());
    for (k, a, n, time) in [
        (
            PublicJwk::from_key(other.verifying_key()),
            issuer,
            nonce.as_str(),
            NOW,
        ),
        (jwk.clone(), "https://evil.example", nonce.as_str(), NOW),
        (jwk.clone(), issuer, "other", NOW),
        (jwk.clone(), issuer, nonce.as_str(), NOW + 91),
    ] {
        assert!(issuance::verify_proof(&proof, &k, a, n, time).is_err());
    }
    let e = mnc();
    let document = verify(&e, &[trust(e.document_type)], NOW).unwrap();
    let token = issuance::issue(
        &issuerkey,
        "issuer",
        issuer,
        &jwk,
        &document,
        NOW,
        &[[1; 16]; 4],
    )
    .unwrap();
    let public = PublicJwk::from_key(issuerkey.verifying_key());
    let claims = issuance::verify_receipt(&token, &public, "issuer", &jwk, issuer, NOW).unwrap();
    assert_eq!(claims["name"], "試験 太郎");
    assert!(issuance::verify_receipt(&token, &public, "issuer", &jwk, issuer, NOW + 299).is_ok());
    assert_eq!(claims["evidence"]["live_possession_verified"], false);
    assert!(issuance::verify_receipt(&token, &public, "issuer", &jwk, issuer, NOW + 301).is_err());
    assert!(
        issuance::verify_receipt(
            &token,
            &public,
            "issuer",
            &PublicJwk::from_key(other.verifying_key()),
            issuer,
            NOW
        )
        .is_err()
    );
    let jwt = token.split('~').next().unwrap();
    assert!(
        !String::from_utf8(B64.decode(jwt.split('.').nth(1).unwrap()).unwrap())
            .unwrap()
            .contains("試験")
    );
    let mutated = token.replacen("~", "~AAAA~", 1);
    assert!(issuance::verify_receipt(&mutated, &public, "issuer", &jwk, issuer, NOW).is_err());
}

#[test]
fn independent_wallet_proof_uses_its_own_key_and_optional_client_claim() {
    let key = SigningKey::from_slice(&[6; 32]).unwrap();
    let wrong = SigningKey::from_slice(&[7; 32]).unwrap();
    let jwk = PublicJwk::from_key(key.verifying_key());
    let issuer = "https://issuer.example/identity/issuer";
    let nonce = "N".repeat(43);
    for client in [None, Some("wallet")] {
        let mut claims = serde_json::json!({"aud":issuer,"nonce":nonce,"iat":NOW});
        if let Some(client) = client {
            claims["iss"] = serde_json::json!(client);
        }
        let header = serde_json::json!({"typ":"openid4vci-proof+jwt","alg":"ES256","jwk":jwk});
        let proof = issuance::sign_jwt(&key, header.clone(), claims.clone()).unwrap();
        assert_eq!(
            issuance::verify_wallet_proof(&proof, issuer, &nonce, "wallet", NOW).unwrap(),
            jwk
        );
        assert!(
            issuance::verify_wallet_proof(&proof, issuer, "wrong-nonce", "wallet", NOW).is_err()
        );
        let forged = issuance::sign_jwt(&wrong, header.clone(), claims.clone()).unwrap();
        assert!(issuance::verify_wallet_proof(&forged, issuer, &nonce, "wallet", NOW).is_err());
        claims["iss"] = serde_json::json!("different-wallet");
        let wrong_client = issuance::sign_jwt(&key, header, claims).unwrap();
        assert!(
            issuance::verify_wallet_proof(&wrong_client, issuer, &nonce, "wallet", NOW).is_err()
        );
    }
}

#[test]
fn proof_jwk_metadata_is_normalized_without_accepting_private_or_wrong_use_keys() {
    use serde_json::json;
    let key = SigningKey::from_slice(&[6; 32]).unwrap();
    let jwk = PublicJwk::from_key(key.verifying_key());
    let issuer = "https://issuer.example/identity/issuer";
    let nonce = "N".repeat(43);
    let claims = json!({"aud":issuer,"nonce":nonce,"iat":NOW,"iss":"wallet"});
    let mut header = json!({"typ":"openid4vci-proof+jwt","alg":"ES256","jwk":jwk});
    header["jwk"]["kid"] = json!("wallet-key");
    header["jwk"]["alg"] = json!("ES256");
    header["jwk"]["use"] = json!("sig");
    header["jwk"]["key_ops"] = json!(["verify"]);
    let proof = issuance::sign_jwt(&key, header.clone(), claims.clone()).unwrap();
    assert_eq!(
        issuance::verify_wallet_proof(&proof, issuer, &nonce, "wallet", NOW).unwrap(),
        jwk
    );
    for (field, value) in [
        ("d", json!(B64.encode([6; 32]))),
        ("alg", json!("ES384")),
        ("use", json!("enc")),
        ("key_ops", json!(["sign"])),
        ("crv", json!("P-384")),
    ] {
        let mut wrong = header.clone();
        wrong["jwk"][field] = value;
        let proof = issuance::sign_jwt(&key, wrong, claims.clone()).unwrap();
        assert!(
            issuance::verify_wallet_proof(&proof, issuer, &nonce, "wallet", NOW).is_err(),
            "{field}"
        );
    }
}
