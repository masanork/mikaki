//! Validate operator-provisioned development PKI with the actual Issuer/Wallet validators.
//! Input is a public bundle only; private application and CA keys are never read.
use base64::{Engine as _, engine::general_purpose::STANDARD};
use der::Decode;
use mikaki_identity::{
    certificate,
    credential_certificate::{Purpose, SigningTrust, verify},
    issuance::PublicJwk,
    wallet_profile::Configuration,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::time::{SystemTime, UNIX_EPOCH};
use x509_cert::{Certificate, crl::CertificateList};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Certificates {
    sd_jwt: SigningTrust,
    mdoc: SigningTrust,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Attester {
    chain: Vec<String>,
    trust_anchors: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bundle {
    format: String,
    issuer_jwk: PublicJwk,
    attester_jwk: PublicJwk,
    credential_certificates: Certificates,
    attester: Attester,
    wallet_configuration: Value,
    revoked_sd_jwt: SigningTrust,
}

// Time-bound diagnostics are not certificate/path/signature validation. In
// particular, an expired or forged input must never become a successful check.
fn public_time_bound(
    chain: &[String],
    roots: &[String],
    revocation: Option<&certificate::CrlPolicy>,
) -> Result<u64, Box<dyn std::error::Error>> {
    let mut deadline = u64::MAX;
    for value in chain.iter().chain(roots) {
        let bytes = certificate::decode_certificate(value)?;
        let cert = Certificate::from_der(&bytes)?;
        deadline = deadline.min(
            cert.tbs_certificate()
                .validity()
                .not_after
                .to_unix_duration()
                .as_secs(),
        );
    }
    if let Some(policy) = revocation {
        policy.validate()?;
        for value in &policy.crls {
            let crl: CertificateList = CertificateList::from_der(&STANDARD.decode(value)?)?;
            let list = &crl.tbs_cert_list;
            let next = list.next_update.ok_or("missing CRL nextUpdate")?;
            deadline = deadline.min(next.to_unix_duration().as_secs()).min(
                list.this_update
                    .to_unix_duration()
                    .as_secs()
                    .saturating_add(policy.max_age_seconds),
            );
        }
    }
    if deadline == u64::MAX {
        return Err("missing public time bounds".into());
    }
    Ok(deadline)
}

fn expired_diagnostics(
    b: &Bundle,
    now: u64,
    digest: &str,
) -> Result<Option<Value>, Box<dyn std::error::Error>> {
    // Deserialize the public shape without treating its dates or roots as
    // authenticated. Configuration::parse and the actual validators below are
    // still required for every successful check.
    let wallet: Configuration = serde_json::from_value(b.wallet_configuration.clone())?;
    let c = &b.credential_certificates;
    let bounds = [
        (
            "sd_jwt_valid_until",
            public_time_bound(
                &c.sd_jwt.chain,
                &c.sd_jwt.trust_anchors,
                c.sd_jwt.revocation.as_ref(),
            )?,
        ),
        (
            "mdoc_valid_until",
            public_time_bound(
                &c.mdoc.chain,
                &c.mdoc.trust_anchors,
                c.mdoc.revocation.as_ref(),
            )?,
        ),
        (
            "attester_valid_until",
            public_time_bound(&b.attester.chain, &b.attester.trust_anchors, None)?,
        ),
        (
            "wallet_sd_jwt_valid_until",
            public_time_bound(
                &c.sd_jwt.chain,
                &wallet.credential_trust.sd_jwt.trust_anchors,
                wallet.credential_trust.sd_jwt.revocation.as_ref(),
            )?,
        ),
        (
            "wallet_mdoc_valid_until",
            public_time_bound(
                &c.mdoc.chain,
                &wallet.credential_trust.mdoc.trust_anchors,
                wallet.credential_trust.mdoc.revocation.as_ref(),
            )?,
        ),
    ];
    if !bounds.iter().any(|(_, deadline)| now >= *deadline) {
        return Ok(None);
    }
    let mut report = json!({
        "format":"mikaki-haip-labpki-expired-v1", "checked_at":now,
        "public_bundle_sha256":digest, "qualification":"unverified-public-time-bounds-only"
    });
    for (name, deadline) in bounds {
        report[name] = json!(deadline);
    }
    Ok(Some(report))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .ok_or("expected a public PKI bundle path")?;
    let bytes = std::fs::read(path)?;
    let mut public_bundle_sha256 = String::with_capacity(64);
    for byte in Sha256::digest(&bytes) {
        write!(public_bundle_sha256, "{byte:02x}")?;
    }
    let b: Bundle = serde_json::from_value(mikaki_identity::wallet_profile::strict_json(&bytes)?)?;
    if b.format != "mikaki-haip-labpki-v1" || b.issuer_jwk == b.attester_jwk {
        return Err("invalid development PKI bundle".into());
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    if let Some(report) = expired_diagnostics(&b, now, &public_bundle_sha256)? {
        println!("{report}");
        return Err("expired public PKI time bound; diagnostics do not establish signature or trust validity".into());
    }
    let c = &b.credential_certificates;
    let sd_until = verify(&c.sd_jwt, &b.issuer_jwk, Purpose::SdJwt, now)?.1;
    let mdoc_until = verify(&c.mdoc, &b.issuer_jwk, Purpose::Mdoc, now)?.1;
    certificate::validate_attester_roots(&b.attester.trust_anchors)?;
    let chain: Vec<_> = b
        .attester
        .chain
        .iter()
        .map(|s| STANDARD.decode(s))
        .collect::<Result<_, _>>()?;
    let (key, attester_until) =
        certificate::verify_attester_chain(&chain, &b.attester.trust_anchors, now)?;
    if PublicJwk::from_key(&key) != b.attester_jwk {
        return Err("attester key mismatch".into());
    }
    let wallet = Configuration::parse(&b.wallet_configuration.to_string(), now)?;
    // Wallets receive the Issuer chain in the credential, but apply their own
    // separately compiled roots and revocation snapshots to it.
    let wallet_sd = SigningTrust {
        chain: c.sd_jwt.chain.clone(),
        trust_anchors: wallet.credential_trust.sd_jwt.trust_anchors.clone(),
        revocation: wallet.credential_trust.sd_jwt.revocation.clone(),
    };
    let wallet_mdoc = SigningTrust {
        chain: c.mdoc.chain.clone(),
        trust_anchors: wallet.credential_trust.mdoc.trust_anchors.clone(),
        revocation: wallet.credential_trust.mdoc.revocation.clone(),
    };
    let wallet_sd_until = verify(&wallet_sd, &b.issuer_jwk, Purpose::SdJwt, now)?.1;
    let wallet_mdoc_until = verify(&wallet_mdoc, &b.issuer_jwk, Purpose::Mdoc, now)?.1;
    if wallet.client_trust[0].trust_anchors != b.attester.trust_anchors
        || wallet.key_trust.trust_anchors != b.attester.trust_anchors
        || wallet.credential_trust.sd_jwt.trust_anchors != c.sd_jwt.trust_anchors
        || wallet.credential_trust.mdoc.trust_anchors != c.mdoc.trust_anchors
    {
        return Err("issuer/wallet trust mismatch".into());
    }
    // Independent implementations must agree on rejection as well as acceptance.
    let mut wrong_root = c.sd_jwt.clone();
    wrong_root.trust_anchors = c.mdoc.trust_anchors.clone();
    let mut included_root = c.sd_jwt.clone();
    included_root.chain.extend(c.sd_jwt.trust_anchors.clone());
    let checks = [
        (
            "revoked_signing_certificate",
            verify(&b.revoked_sd_jwt, &b.issuer_jwk, Purpose::SdJwt, now).is_err(),
        ),
        (
            "wrong_trust_anchor",
            verify(&wrong_root, &b.issuer_jwk, Purpose::SdJwt, now).is_err(),
        ),
        (
            "root_in_x5c",
            verify(&included_root, &b.issuer_jwk, Purpose::SdJwt, now).is_err(),
        ),
        (
            "wrong_signing_key",
            verify(&c.sd_jwt, &b.attester_jwk, Purpose::SdJwt, now).is_err(),
        ),
        (
            "wrong_certificate_purpose",
            verify(&c.mdoc, &b.issuer_jwk, Purpose::SdJwt, now).is_err(),
        ),
        (
            "expired_attester",
            certificate::verify_attester_chain(&chain, &b.attester.trust_anchors, attester_until)
                .is_err(),
        ),
        (
            "expired_credential_crl",
            verify(&c.sd_jwt, &b.issuer_jwk, Purpose::SdJwt, sd_until).is_err(),
        ),
    ];
    if checks.iter().any(|(_, rejected)| !rejected) {
        return Err("development PKI negative check failed".into());
    }
    println!(
        "{}",
        json!({
            "format":"mikaki-haip-labpki-check-v1", "checked_at":now,
            "public_bundle_sha256":public_bundle_sha256,
            "issuer_thumbprint":b.issuer_jwk.thumbprint()?, "attester_thumbprint":b.attester_jwk.thumbprint()?,
            "sd_jwt_valid_until":sd_until, "mdoc_valid_until":mdoc_until,
            "attester_valid_until":attester_until, "wallet_configuration_valid":true,
            "wallet_sd_jwt_valid_until":wallet_sd_until, "wallet_mdoc_valid_until":wallet_mdoc_until,
            "negative_checks":checks.into_iter().map(|(name, _)| name).collect::<Vec<_>>(),
            "qualification":"development-pki-validation-only"
        })
    );
    Ok(())
}
