//! Explicit, bounded P-256 reader PKI. No system roots or network chain building.
use crate::issuance::PublicJwk;
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use der::{Decode, Encode, asn1::ObjectIdentifier};
use p256::{
    ecdsa::{Signature, VerifyingKey, signature::Verifier},
    pkcs8::DecodePublicKey,
};
use rustls_pki_types::{
    AlgorithmIdentifier, CertificateDer, InvalidSignature, SignatureVerificationAlgorithm,
    UnixTime, alg_id,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, time::Duration};
use x509_cert::{
    Certificate,
    ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAltName, name::GeneralName},
};

pub use crate::certificate_revocation::CrlPolicy;

static READER_EKU: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.0.18013.5.1.6");

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReaderTrust {
    /// Standard padded base64 DER CA certificates, provisioned out of band.
    pub trust_anchors: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation: Option<CrlPolicy>,
}
#[derive(Debug)]
pub(crate) struct P256Sha256;
impl SignatureVerificationAlgorithm for P256Sha256 {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ECDSA_P256
    }
    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ECDSA_SHA256
    }
    fn verify_signature(
        &self,
        key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        VerifyingKey::from_sec1_bytes(key)
            .map_err(|_| InvalidSignature)?
            .verify(
                message,
                &Signature::from_der(signature).map_err(|_| InvalidSignature)?,
            )
            .map_err(|_| InvalidSignature)
    }
}
pub fn decode_certificate(value: &str) -> Result<Vec<u8>, &'static str> {
    if value.len() > 5464 {
        return Err("invalid_certificate_chain");
    }
    let bytes = B64.decode(value).map_err(|_| "invalid_certificate_chain")?;
    if bytes.is_empty() || bytes.len() > 4096 || B64.encode(&bytes) != value {
        return Err("invalid_certificate_chain");
    }
    Ok(bytes)
}
impl ReaderTrust {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.trust_anchors.is_empty() || self.trust_anchors.len() > 8 {
            return Err("invalid_certificate_policy");
        }
        let mut seen = HashSet::new();
        for root in &self.trust_anchors {
            let bytes = decode_certificate(root)?;
            if !seen.insert(bytes.clone()) {
                return Err("invalid_certificate_policy");
            }
            check_certificate(&bytes, None, true)?;
        }
        if let Some(name) = &self.dns_name
            && (name.parse::<std::net::IpAddr>().is_ok()
                || name.len() > 253
                || !name.contains('.')
                || name.ends_with('.')
                || name != &name.to_ascii_lowercase()
                || rustls_pki_types::DnsName::try_from(name.as_str()).is_err())
        {
            return Err("invalid_certificate_policy");
        }
        if let Some(policy) = &self.revocation {
            policy.decode()?;
        }
        Ok(())
    }
}
fn check_certificate(
    bytes: &[u8],
    now: Option<u64>,
    ca: bool,
) -> Result<Certificate, &'static str> {
    check_certificate_for_purpose(bytes, now, ca, true)
}
fn check_certificate_for_purpose(
    bytes: &[u8],
    now: Option<u64>,
    ca: bool,
    reader: bool,
) -> Result<Certificate, &'static str> {
    if bytes.is_empty() || bytes.len() > 4096 {
        return Err("invalid_certificate_chain");
    }
    let cert = Certificate::from_der(bytes).map_err(|_| "invalid_certificate_chain")?;
    let t = cert.tbs_certificate();
    if now.is_some_and(|now| {
        now < t.validity().not_before.to_unix_duration().as_secs()
            || now >= t.validity().not_after.to_unix_duration().as_secs()
    }) {
        return Err("invalid_certificate_chain");
    }
    let extensions = t.extensions().ok_or("invalid_certificate_chain")?;
    let mut seen = HashSet::new();
    for e in extensions {
        if !seen.insert(e.extn_id)
            || (e.critical
                && !matches!(
                    e.extn_id.to_string().as_str(),
                    "2.5.29.15" | "2.5.29.19" | "2.5.29.30" | "2.5.29.17" | "2.5.29.37"
                ))
        {
            return Err("invalid_certificate_chain");
        }
    }
    let ext = |oid| {
        extensions
            .iter()
            .find(|e| e.extn_id == ObjectIdentifier::new_unwrap(oid))
            .ok_or("invalid_certificate_chain")
    };
    let ku_ext = ext("2.5.29.15")?;
    let bc_ext = ext("2.5.29.19")?;
    let ku = KeyUsage::from_der(ku_ext.extn_value.as_bytes())
        .map_err(|_| "invalid_certificate_chain")?;
    let bc = BasicConstraints::from_der(bc_ext.extn_value.as_bytes())
        .map_err(|_| "invalid_certificate_chain")?;
    if !ku_ext.critical
        || !bc_ext.critical
        || bc.ca != ca
        || (ca && !ku.key_cert_sign())
        || (!ca && (!ku.digital_signature() || ku.key_cert_sign()))
    {
        return Err("invalid_certificate_chain");
    }
    if reader
        && ca
        && let Some(eku_ext) = extensions
            .iter()
            .find(|e| e.extn_id == ObjectIdentifier::new_unwrap("2.5.29.37"))
    {
        let eku = ExtendedKeyUsage::from_der(eku_ext.extn_value.as_bytes())
            .map_err(|_| "invalid_certificate_chain")?;
        if !eku.0.contains(&READER_EKU) {
            return Err("invalid_certificate_chain");
        }
    }
    if reader && !ca {
        let eku_ext = ext("2.5.29.37")?;
        let eku = ExtendedKeyUsage::from_der(eku_ext.extn_value.as_bytes())
            .map_err(|_| "invalid_certificate_chain")?;
        if !eku_ext.critical
            || !eku
                .0
                .contains(&ObjectIdentifier::new_unwrap("1.0.18013.5.1.6"))
        {
            return Err("invalid_certificate_chain");
        }
    }
    Ok(cert)
}
/// Adds certificate authentication to the registered key. Certificate subject/CN
/// never supplies an application display name or expands attribute authorization.
pub fn verify_reader_chain(
    chain: &[Vec<u8>],
    policy: &ReaderTrust,
    expected: &PublicJwk,
    now: u64,
) -> Result<u64, &'static str> {
    policy.validate()?;
    if chain.is_empty() || chain.len() > 4 {
        return Err("invalid_certificate_chain");
    }
    let leaf = check_certificate(&chain[0], Some(now), false)?;
    let mut deadline = leaf
        .tbs_certificate()
        .validity()
        .not_after
        .to_unix_duration()
        .as_secs();
    for cert in &chain[1..] {
        deadline = deadline.min(
            check_certificate(cert, Some(now), true)?
                .tbs_certificate()
                .validity()
                .not_after
                .to_unix_duration()
                .as_secs(),
        );
    }
    let key = VerifyingKey::from_public_key_der(
        &leaf
            .tbs_certificate()
            .subject_public_key_info()
            .to_der()
            .map_err(|_| "invalid_certificate_chain")?,
    )
    .map_err(|_| "invalid_certificate_chain")?;
    if &PublicJwk::from_key(&key) != expected {
        return Err("certificate_key_mismatch");
    }
    let roots = policy
        .trust_anchors
        .iter()
        .map(|s| decode_certificate(s))
        .collect::<Result<Vec<_>, _>>()?;
    for cert in &roots {
        let root = check_certificate(cert, Some(now), true)?;
        deadline = deadline.min(
            root.tbs_certificate()
                .validity()
                .not_after
                .to_unix_duration()
                .as_secs(),
        );
        if policy.revocation.is_some() {
            let ku = root
                .tbs_certificate()
                .extensions()
                .and_then(|es| es.iter().find(|e| e.extn_id.to_string() == "2.5.29.15"))
                .ok_or("invalid_crl_policy")?;
            if !KeyUsage::from_der(ku.extn_value.as_bytes())
                .map_err(|_| "invalid_crl_policy")?
                .crl_sign()
            {
                return Err("invalid_crl_policy");
            }
        }
    }
    let roots: Vec<_> = roots
        .iter()
        .map(|c| CertificateDer::from(c.as_slice()))
        .collect();
    let anchors = roots
        .iter()
        .map(webpki::anchor_from_trusted_cert)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "invalid_certificate_policy")?;
    let der = CertificateDer::from(chain[0].as_slice());
    let cert = webpki::EndEntityCert::try_from(&der).map_err(|_| "invalid_certificate_chain")?;
    let intermediates: Vec<_> = chain[1..]
        .iter()
        .map(|c| CertificateDer::from(c.as_slice()))
        .collect();
    let crl_bytes = policy
        .revocation
        .as_ref()
        .map(|p| p.decode())
        .transpose()?
        .unwrap_or_default();
    if let Some(policy) = &policy.revocation {
        deadline = deadline.min(policy.deadline(&crl_bytes, now)?);
    }
    let crls = crl_bytes
        .iter()
        .map(|bytes| {
            webpki::BorrowedCertRevocationList::from_der(bytes)
                .map(webpki::CertRevocationList::from)
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "invalid_crl")?;
    let refs = crls.iter().collect::<Vec<_>>();
    let revocation = if policy.revocation.is_some() {
        Some(
            webpki::RevocationOptionsBuilder::new(&refs)
                .map_err(|_| "invalid_crl_policy")?
                .with_depth(webpki::RevocationCheckDepth::Chain)
                .with_status_policy(webpki::UnknownStatusPolicy::Deny)
                .with_expiration_policy(webpki::ExpirationPolicy::Enforce)
                .build(),
        )
    } else {
        None
    };
    cert.verify_for_usage(
        &[&P256Sha256],
        &anchors,
        &intermediates,
        UnixTime::since_unix_epoch(Duration::from_secs(now)),
        webpki::KeyUsage::required_if_present(READER_EKU.as_bytes()),
        revocation,
        None,
    )
    .map_err(|error| match error {
        webpki::Error::CertRevoked => "certificate_revoked",
        webpki::Error::UnknownRevocationStatus => "certificate_status_unknown",
        webpki::Error::CrlExpired { .. } => "crl_expired",
        webpki::Error::InvalidCrlSignatureForPublicKey | webpki::Error::IssuerNotCrlSigner => {
            "invalid_crl"
        }
        _ => "untrusted_certificate_chain",
    })?;
    if let Some(name) = &policy.dns_name {
        let san = leaf
            .tbs_certificate()
            .extensions()
            .and_then(|es| {
                es.iter()
                    .find(|e| e.extn_id == ObjectIdentifier::new_unwrap("2.5.29.17"))
            })
            .ok_or("certificate_name_mismatch")?;
        let names = SubjectAltName::from_der(san.extn_value.as_bytes())
            .map_err(|_| "certificate_name_mismatch")?;
        if !names.0.iter().any(
            |n| matches!(n, GeneralName::DnsName(dns) if dns.as_str().eq_ignore_ascii_case(name)),
        ) {
            return Err("certificate_name_mismatch");
        }
    }
    Ok(deadline)
}

/// Validate configured attester CA material independently of an incoming JWT.
pub fn validate_attester_roots(roots: &[String]) -> Result<(), &'static str> {
    if roots.is_empty() || roots.len() > 8 {
        return Err("invalid_certificate_policy");
    }
    let mut seen = HashSet::new();
    for root in roots {
        let bytes = decode_certificate(root)?;
        if !seen.insert(bytes.clone()) {
            return Err("invalid_certificate_policy");
        }
        let cert = check_certificate_for_purpose(&bytes, None, true, false)?;
        if cert
            .tbs_certificate()
            .extensions()
            .is_some_and(|es| es.iter().any(|e| e.extn_id.to_string() == "2.5.29.37"))
        {
            return Err("unsupported_attester_eku");
        }
        webpki::anchor_from_trusted_cert(&CertificateDer::from(bytes.as_slice()))
            .map_err(|_| "invalid_certificate_policy")?;
    }
    Ok(())
}
/// Attester ecosystem policy: digital-signature leaf, CA chain, no EKU restriction.
/// Certificates with EKUs are unsupported here (reader/TLS purposes cannot be reused).
pub fn verify_attester_chain(
    chain: &[Vec<u8>],
    roots: &[String],
    now: u64,
) -> Result<(VerifyingKey, u64), &'static str> {
    if chain.is_empty() || chain.len() > 4 || roots.is_empty() || roots.len() > 8 {
        return Err("invalid_certificate_chain");
    }
    let roots = roots
        .iter()
        .map(|s| decode_certificate(s))
        .collect::<Result<Vec<_>, _>>()?;
    let mut seen = HashSet::new();
    let mut deadline = u64::MAX;
    for (index, bytes) in chain.iter().chain(roots.iter()).enumerate() {
        if !seen.insert(bytes) {
            return Err("invalid_certificate_chain");
        }
        let cert = check_certificate_for_purpose(bytes, Some(now), index != 0, false)?;
        if cert
            .tbs_certificate()
            .extensions()
            .is_some_and(|es| es.iter().any(|e| e.extn_id.to_string() == "2.5.29.37"))
        {
            return Err("unsupported_attester_eku");
        }
        deadline = deadline.min(
            cert.tbs_certificate()
                .validity()
                .not_after
                .to_unix_duration()
                .as_secs(),
        );
    }
    let leaf = check_certificate_for_purpose(&chain[0], Some(now), false, false)?;
    if leaf.tbs_certificate().issuer() == leaf.tbs_certificate().subject() {
        return Err("invalid_certificate_chain");
    }
    let key = VerifyingKey::from_public_key_der(
        &leaf
            .tbs_certificate()
            .subject_public_key_info()
            .to_der()
            .map_err(|_| "invalid_certificate_chain")?,
    )
    .map_err(|_| "invalid_certificate_chain")?;
    let roots: Vec<_> = roots
        .iter()
        .map(|c| CertificateDer::from(c.as_slice()))
        .collect();
    let anchors = roots
        .iter()
        .map(webpki::anchor_from_trusted_cert)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "invalid_certificate_policy")?;
    let der = CertificateDer::from(chain[0].as_slice());
    let cert = webpki::EndEntityCert::try_from(&der).map_err(|_| "invalid_certificate_chain")?;
    let intermediates: Vec<_> = chain[1..]
        .iter()
        .map(|c| CertificateDer::from(c.as_slice()))
        .collect();
    cert.verify_for_usage(
        &[&P256Sha256],
        &anchors,
        &intermediates,
        UnixTime::since_unix_epoch(Duration::from_secs(now)),
        webpki::KeyUsage::client_auth(),
        None,
        None,
    )
    .map_err(|_| "untrusted_certificate_chain")?;
    Ok((key, deadline))
}

/// HAIP x509_hash authentication with an operator-provisioned reader ecosystem.
/// Exact leaf hash and key pin are additional to path/purpose/status validation.
pub fn verify_x509_hash_reader_chain(
    chain: &[Vec<u8>],
    policy: &ReaderTrust,
    expected: &PublicJwk,
    client_id: &str,
    now: u64,
) -> Result<u64, &'static str> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use sha2::{Digest, Sha256};
    policy.validate()?;
    if chain.is_empty() || chain.len() > 4 {
        return Err("invalid_certificate_chain");
    }
    let leaf = chain.first().ok_or("invalid_certificate_chain")?;
    if client_id != format!("x509_hash:{}", URL_SAFE_NO_PAD.encode(Sha256::digest(leaf))) {
        return Err("certificate_hash_mismatch");
    }
    let cert = check_certificate(leaf, Some(now), false)?;
    if cert.tbs_certificate().issuer() == cert.tbs_certificate().subject() {
        return Err("invalid_certificate_chain");
    }
    let roots = policy
        .trust_anchors
        .iter()
        .map(|r| decode_certificate(r))
        .collect::<Result<Vec<_>, _>>()?;
    let mut seen = HashSet::new();
    for cert in chain {
        if !seen.insert(cert) || roots.contains(cert) {
            return Err("invalid_certificate_chain");
        }
    }
    verify_reader_chain(chain, policy, expected, now)
}
