#[path = "support/certificate.rs"]
mod mutable_certificate;
use mutable_certificate::Certificate;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use der::{
    Decode, Encode,
    asn1::{ObjectIdentifier, OctetString},
};
use mikaki_identity::{
    android_attestation_evidence::UntrustedAndroidEvidence, issuance::PublicJwk,
};
use p256::ecdsa::SigningKey;
use serde_json::Value;
use x509_cert::ext::Extension;
const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.11129.2.1.17");
fn certificate(name: &str) -> Certificate {
    Certificate::from_der(
        &std::fs::read(format!(
            "{}/tests/fixtures/trust/{name}.der",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap(),
    )
    .unwrap()
}
fn key(n: u8) -> PublicJwk {
    PublicJwk::from_key(SigningKey::from_slice(&[n; 32]).unwrap().verifying_key())
}
fn tlv(tag: u8, bytes: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if bytes.len() < 128 {
        out.push(bytes.len() as u8);
    } else {
        out.extend([0x82, (bytes.len() >> 8) as u8, bytes.len() as u8]);
    }
    out.extend(bytes);
    out
}
fn description(challenge: &[u8], unique_id: &[u8]) -> Vec<u8> {
    let mut fields = vec![2, 1, 4, 10, 1, 1, 2, 1, 4, 10, 1, 1];
    fields.extend(tlv(4, challenge));
    fields.extend(tlv(4, unique_id));
    fields.extend([0x30, 0, 0x30, 0]);
    tlv(0x30, &fields)
}
fn extension(bytes: &[u8]) -> Extension {
    Extension {
        extn_id: OID,
        critical: false,
        extn_value: OctetString::new(bytes).unwrap(),
    }
}
fn chain_with(description: &[u8]) -> Vec<String> {
    let mut leaf = certificate("attester");
    leaf.tbs_certificate
        .extensions
        .as_mut()
        .unwrap()
        .push(extension(description));
    vec![
        STANDARD.encode(leaf.to_der().unwrap()),
        STANDARD.encode(certificate("intermediate").to_der().unwrap()),
        STANDARD.encode(certificate("root").to_der().unwrap()),
    ]
}
#[test]
fn collects_untrusted_evidence_with_bound_challenge_key_and_no_assurance_claim() {
    // Intentionally modified without re-signing: this API is a transport sanity
    // boundary, not a certificate trust/signature/hardware verifier.
    let chain = chain_with(&description(&[7; 32], &[]));
    let evidence = UntrustedAndroidEvidence::collect(&[7; 32], key(5), chain.clone()).unwrap();
    let json = serde_json::to_value(evidence).unwrap();
    assert_eq!(json["certificate_chain"], serde_json::json!(chain));
    assert_eq!(json["public_key"], serde_json::to_value(key(5)).unwrap());
    assert_eq!(json.as_object().unwrap().len(), 3);
    assert!(json.get("hardware_backed").is_none());
}
#[test]
fn rejects_wrong_challenge_key_and_unrequested_unique_id() {
    let chain = chain_with(&description(&[7; 32], &[]));
    assert!(UntrustedAndroidEvidence::collect(&[8; 32], key(5), chain.clone()).is_err());
    assert!(UntrustedAndroidEvidence::collect(&[7; 32], key(6), chain).is_err());
    assert!(
        UntrustedAndroidEvidence::collect(
            &[7; 32],
            key(5),
            chain_with(&description(&[7; 32], b"device-identifier"))
        )
        .is_err()
    );
}
#[test]
fn rejects_extension_ambiguity_nonleaf_extension_and_malformed_schema() {
    let mut chain = chain_with(&description(&[7; 32], &[]));
    let mut leaf = Certificate::from_der(&STANDARD.decode(&chain[0]).unwrap()).unwrap();
    leaf.tbs_certificate
        .extensions
        .as_mut()
        .unwrap()
        .push(extension(&description(&[7; 32], &[])));
    chain[0] = STANDARD.encode(leaf.to_der().unwrap());
    assert!(UntrustedAndroidEvidence::collect(&[7; 32], key(5), chain).is_err());
    let mut chain = chain_with(&description(&[7; 32], &[]));
    let mut parent = certificate("intermediate");
    parent
        .tbs_certificate
        .extensions
        .as_mut()
        .unwrap()
        .push(extension(&description(&[7; 32], &[])));
    chain[1] = STANDARD.encode(parent.to_der().unwrap());
    assert!(UntrustedAndroidEvidence::collect(&[7; 32], key(5), chain).is_err());
    for bytes in [
        vec![0x30, 0],
        vec![0x30, 0x80, 0, 0],
        vec![0x30, 1, 0xff],
        {
            let mut bytes = description(&[7; 32], &[]);
            bytes.push(0);
            bytes
        },
        description(&[7; 31], &[]),
        {
            let mut bytes = description(&[7; 32], &[]);
            bytes[5] = 2;
            bytes
        },
        {
            let mut bytes = description(&[7; 32], &[]);
            bytes[4] = 0xff;
            bytes
        },
        {
            let mut bytes = description(&[7; 32], &[]);
            bytes[7] = 3;
            bytes
        },
    ] {
        assert!(UntrustedAndroidEvidence::collect(&[7; 32], key(5), chain_with(&bytes)).is_err());
    }
}
#[test]
fn bounds_chain_count_sizes_encoding_and_rejects_duplicate_or_noncertificate_members() {
    let chain = chain_with(&description(&[7; 32], &[]));
    for mut bad in [
        vec![],
        vec![chain[0].clone()],
        vec![chain[0].clone(); 9],
        vec![chain[0].clone(); 2],
    ] {
        assert!(
            UntrustedAndroidEvidence::collect(&[7; 32], key(5), std::mem::take(&mut bad)).is_err()
        );
    }
    for invalid in [
        STANDARD.encode([0xff; 8193]),
        "not-base64".into(),
        "AA==".into(),
        format!("{}\n", chain[0]),
    ] {
        let mut bad = chain.clone();
        bad[0] = invalid;
        assert!(UntrustedAndroidEvidence::collect(&[7; 32], key(5), bad).is_err());
    }
    let json: Value =
        serde_json::to_value(UntrustedAndroidEvidence::collect(&[7; 32], key(5), chain).unwrap())
            .unwrap();
    assert_eq!(json["challenge"].as_str().unwrap().len(), 43);
    let mut large_chain = Vec::new();
    let mut total = 0;
    for i in 0..5 {
        let mut certificate = certificate("attester");
        certificate
            .tbs_certificate
            .extensions
            .as_mut()
            .unwrap()
            .push(Extension {
                extn_id: ObjectIdentifier::new_unwrap("1.2.3.4"),
                critical: false,
                extn_value: OctetString::new(vec![i; 7000]).unwrap(),
            });
        let bytes = certificate.to_der().unwrap();
        assert!(bytes.len() < 8192);
        total += bytes.len();
        large_chain.push(STANDARD.encode(bytes));
    }
    assert!(total > 32768);
    assert!(UntrustedAndroidEvidence::collect(&[7; 32], key(5), large_chain).is_err());
}
