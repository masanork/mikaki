use crate::identity_wallet::{HolderKey, Receipt};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use mikaki_identity::{
    certificate::CrlPolicy, credential_certificate::SigningTrust,
    credential_receipt::CredentialTrust, issuance::PublicJwk, mdoc,
};
use mikaki_identity::{
    evidence::VerifiedDocument,
    issuance::{self, Validity},
};
use p256::ecdsa::SigningKey;
use serde_json::{json, Value};
use zeroize::Zeroizing;
const NOW: u64 = 1791000000;
const ISSUER: &str = "https://issuer.example/identity/issuer";
#[test]
fn persisted_profile_cannot_silently_downgrade_haip_or_ambiguous_legacy_records() {
    use crate::identity_wallet::restoration_profile as profile;
    assert!(!profile(1, None, false).unwrap());
    assert!(profile(1, None, true).is_err());
    assert!(profile(2, Some(true), false).is_err());
    assert!(profile(2, Some(true), true).unwrap());
    assert!(!profile(2, Some(false), true).unwrap());
    for (version, marker) in [
        (0, None),
        (3, Some(true)),
        (1, Some(false)),
        (1, Some(true)),
        (2, None),
    ] {
        assert!(profile(version, marker, true).is_err());
    }
}
fn bytes(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/../../../crates/identity/tests/fixtures/credential/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}
fn policy() -> CredentialTrust {
    serde_json::from_value(json!({"sd_jwt":{"trust_anchors":[STANDARD.encode(bytes("sd-ca.der"))]},"mdoc":{"trust_anchors":[STANDARD.encode(bytes("mdoc-ca.der"))]}})).unwrap()
}
fn receipt(format: &str) -> Receipt {
    receipt_with(format, 3, ISSUER)
}
pub(crate) fn receipt_with(format: &str, seed: u8, issuer_url: &str) -> Receipt {
    let issuer = SigningKey::from_slice(&[4; 32]).unwrap();
    let holder = HolderKey::Memory(SigningKey::from_slice(&[seed; 32]).unwrap());
    let document: VerifiedDocument = serde_json::from_value(json!({"attributes":{"name":"Fixture","address":"Private","birth_date":"1990-02-28","gender":"1","verification":"issuer_signed_static_data","document_type":"my_number_card","expiry_date":null,"backend_verifiable":true},"trusted_key_id":"fixture","verified_at":NOW,"assurance":"issuer_signed_static_data","attributes_source":"input_support_ef"})).unwrap();
    let credential = if format == "dc+sd-jwt" {
        issuance::issue_with_certificate_trust(
            &issuer,
            "issuer",
            issuer_url,
            &holder.public().unwrap(),
            &document,
            Validity::new(&document, NOW, NOW + 300).unwrap(),
            &[[1; 16], [2; 16], [3; 16], [4; 16]],
            &SigningTrust {
                chain: vec![STANDARD.encode(bytes("sd-signer.der"))],
                trust_anchors: policy().sd_jwt.trust_anchors,
                revocation: None,
            },
        )
        .unwrap()
    } else {
        mdoc::issue(
            &issuer,
            &bytes("mdoc-signer.der"),
            &holder.public().unwrap(),
            &document,
            NOW,
            &[[1; 16], [2; 16], [3; 16], [4; 16]],
        )
        .unwrap()
    };
    Receipt {
        credential: Zeroizing::new(credential),
        format: format.into(),
        key: holder,
        expires_at: NOW + 300,
        issuer_key: PublicJwk::from_key(issuer.verifying_key()),
        issuer_kid: "issuer".into(),
        credential_trust: Some(policy()),
    }
}
// Resign the JWT so negative tests target certificate trust rather than JWT signatures.
fn edit_header(r: &mut Receipt, edit: impl FnOnce(&mut Value)) {
    let (jwt, tail) = r.credential.split_once('~').unwrap();
    let parts: Vec<_> = jwt.split('.').collect();
    let mut header: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
    let claims = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
    edit(&mut header);
    let compact =
        issuance::sign_jwt(&SigningKey::from_slice(&[4; 32]).unwrap(), header, claims).unwrap();
    r.credential = Zeroizing::new(format!("{compact}~{tail}"));
}
#[test]
fn native_receipts_recheck_current_roots_and_signed_expiry() {
    policy().validate(NOW).unwrap();
    for format in ["dc+sd-jwt", "mso_mdoc"] {
        let mut r = receipt(format);
        assert_eq!(r.validate(ISSUER, NOW).unwrap(), NOW + 300);
        let mut changed = policy();
        changed.sd_jwt.trust_anchors = vec![STANDARD.encode(bytes("mdoc-ca.der"))];
        changed.mdoc.trust_anchors = vec![STANDARD.encode(bytes("sd-ca.der"))];
        r.credential_trust = Some(changed);
        assert!(r.validate(ISSUER, NOW + 1).is_err());
        r.credential_trust = Some(policy());
        assert!(r.validate(ISSUER, NOW + 300).is_err());
        assert!(policy()
            .verify(&r.credential, format, &r.issuer_key, NOW, u64::MAX)
            .is_err());
    }
    let mut bad = policy();
    bad.sd_jwt.trust_anchors.clear();
    assert!(bad.validate(NOW).is_err());
    let mut bad = policy();
    bad.mdoc.trust_anchors = bad.sd_jwt.trust_anchors.clone();
    assert!(bad.validate(NOW).is_err());
}
#[test]
fn validly_signed_sd_jwt_cannot_omit_include_root_or_tamper_its_chain() {
    for mode in ["missing", "root", "tampered"] {
        let mut r = receipt("dc+sd-jwt");
        edit_header(&mut r, |h| match mode {
            "missing" => {
                h.as_object_mut().unwrap().remove("x5c");
            }
            "root" => {
                h["x5c"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!(STANDARD.encode(bytes("sd-ca.der"))));
            }
            _ => {
                let mut b = bytes("sd-signer.der");
                *b.last_mut().unwrap() ^= 1;
                h["x5c"][0] = json!(STANDARD.encode(b));
            }
        });
        assert!(r.validate(ISSUER, NOW).is_err(), "{mode}");
    }
}
#[test]
fn native_mdoc_receipts_enforce_configured_complete_crl_status() {
    let mut r = receipt("mso_mdoc");
    r.credential_trust.as_mut().unwrap().mdoc.revocation = Some(CrlPolicy {
        crls: vec![STANDARD.encode(bytes("mdoc-clean.crl"))],
        max_age_seconds: 604800,
    });
    assert_eq!(r.validate(ISSUER, NOW).unwrap(), NOW + 300);
    r.credential_trust
        .as_mut()
        .unwrap()
        .mdoc
        .revocation
        .as_mut()
        .unwrap()
        .crls = vec![STANDARD.encode(bytes("mdoc-revoked.crl"))];
    assert!(r.validate(ISSUER, NOW).is_err());
    r.credential_trust
        .as_mut()
        .unwrap()
        .mdoc
        .revocation
        .as_mut()
        .unwrap()
        .crls
        .clear();
    assert!(r.validate(ISSUER, NOW).is_err());
    assert!(r.credential_trust.as_ref().unwrap().validate(NOW).is_err());
}
