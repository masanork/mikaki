//! Explicit credential signing trust. P-256 only; mdoc uses direct IACA -> DS.
//! Certificate URLs are never fetched. Optional offline CRLs fail closed.
use crate::{
    certificate::{CrlPolicy, P256Sha256, decode_certificate},
    issuance::PublicJwk,
};
use der::{Decode, Encode, Tag, Tagged};
use p256::{
    ecdsa::{Signature, VerifyingKey, signature::Verifier},
    pkcs8::DecodePublicKey,
};
use rustls_pki_types::{CertificateDer, UnixTime};
use serde::Deserialize;
use sha1::{Digest, Sha1};
use std::{collections::HashSet, time::Duration};
use x509_cert::{
    Certificate, Version,
    ext::Extension,
    ext::pkix::{
        AuthorityKeyIdentifier, BasicConstraints, CrlDistributionPoints, ExtendedKeyUsage,
        IssuerAltName, KeyUsage, SubjectKeyIdentifier,
        name::{DistributionPointName, GeneralName},
    },
};

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningTrust {
    /// Leaf first, standard base64 DER; root MUST be omitted.
    pub chain: Vec<String>,
    pub trust_anchors: Vec<String>,
    pub revocation: Option<CrlPolicy>,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    SdJwt,
    Mdoc,
}
/// Validate separately provisioned roots before starting a wallet transaction.
pub fn validate_roots(roots: &[String], purpose: Purpose, now: u64) -> Result<(), &'static str> {
    if roots.is_empty() || roots.len() > 8 {
        return Err(ERR);
    }
    let mut seen = HashSet::new();
    for root in roots {
        let bytes = decode_certificate(root)?;
        if !seen.insert(bytes.clone()) {
            return Err(ERR);
        }
        parse(&bytes, true, purpose, now)?;
        webpki::anchor_from_trusted_cert(&CertificateDer::from(bytes.as_slice()))
            .map_err(|_| ERR)?;
    }
    Ok(())
}
const ERR: &str = "invalid_credential_certificate";
fn ext<'a>(c: &'a Certificate, oid: &str) -> Result<&'a Extension, &'static str> {
    c.tbs_certificate
        .extensions
        .as_ref()
        .and_then(|es| es.iter().find(|e| e.extn_id.to_string() == oid))
        .ok_or(ERR)
}
fn public(c: &Certificate) -> Result<VerifyingKey, &'static str> {
    VerifyingKey::from_public_key_der(
        &c.tbs_certificate
            .subject_public_key_info
            .to_der()
            .map_err(|_| ERR)?,
    )
    .map_err(|_| ERR)
}
fn parse(bytes: &[u8], ca: bool, purpose: Purpose, now: u64) -> Result<Certificate, &'static str> {
    if bytes.is_empty() || bytes.len() > 4096 {
        return Err(ERR);
    }
    let c = Certificate::from_der(bytes).map_err(|_| ERR)?;
    let t = &c.tbs_certificate;
    let start = t.validity.not_before.to_unix_duration().as_secs();
    let end = t.validity.not_after.to_unix_duration().as_secs();
    if t.version != Version::V3
        || t.serial_number.as_bytes().len() > 20
        || t.serial_number.as_bytes().iter().all(|b| *b == 0)
        || now < start
        || now >= end
        || t.signature != c.signature_algorithm
        || c.signature_algorithm.oid.to_string() != "1.2.840.10045.4.3.2"
        || c.signature_algorithm.parameters.is_some()
    {
        return Err(ERR);
    }
    public(&c)?;
    let mut ids = HashSet::new();
    for e in t.extensions.as_ref().ok_or(ERR)? {
        if !ids.insert(e.extn_id)
            || (e.critical
                && !(e.extn_id.to_string() == "2.5.29.15"
                    || ((ca || purpose == Purpose::SdJwt) && e.extn_id.to_string() == "2.5.29.19")
                    || (!ca && purpose == Purpose::Mdoc && e.extn_id.to_string() == "2.5.29.37")))
        {
            return Err(ERR);
        }
    }
    let ku_ext = ext(&c, "2.5.29.15")?;
    let ku = KeyUsage::from_der(ku_ext.extn_value.as_bytes()).map_err(|_| ERR)?;
    if !ku_ext.critical
        || (!ca && ku.0.bits() != 1)
        || (ca && (!ku.key_cert_sign() || ku.digital_signature()))
    {
        return Err(ERR);
    }
    // This ecosystem uses unrestricted credential certificates for SD-JWT only.
    if purpose == Purpose::SdJwt && ext(&c, "2.5.29.37").is_ok() {
        return Err("unsupported_credential_eku");
    }
    if ca {
        let e = ext(&c, "2.5.29.19")?;
        let bc = BasicConstraints::from_der(e.extn_value.as_bytes()).map_err(|_| ERR)?;
        if !e.critical
            || !bc.ca
            || (purpose == Purpose::Mdoc
                && (bc.path_len_constraint != Some(0) || ku.0.bits() != 96))
        {
            return Err(ERR);
        }
    } else if let Ok(e) = ext(&c, "2.5.29.19")
        && BasicConstraints::from_der(e.extn_value.as_bytes())
            .map_err(|_| ERR)?
            .ca
    {
        return Err(ERR);
    }
    if purpose == Purpose::Mdoc {
        if end.saturating_sub(start) > if ca { 7305 * 86400 } else { 457 * 86400 } {
            return Err(ERR);
        }
        for oid in [
            "2.5.29.33",
            "2.5.29.30",
            "2.5.29.36",
            "2.5.29.54",
            "2.5.29.46",
        ] {
            if ext(&c, oid).is_ok() {
                return Err(ERR);
            }
        }
        let mut country = false;
        let mut cn = false;
        for rdn in &t.subject.0 {
            for at in rdn.0.iter() {
                let oid = at.oid.to_string();
                if oid == "2.5.4.6" {
                    let b = at.value.value();
                    if country
                        || at.value.tag() != Tag::PrintableString
                        || b.len() != 2
                        || !b.iter().all(u8::is_ascii_uppercase)
                    {
                        return Err(ERR);
                    }
                    country = true;
                }
                if oid == "2.5.4.3" {
                    cn = true;
                    if at.value.value().is_empty() {
                        return Err(ERR);
                    }
                }
                if ["2.5.4.3", "2.5.4.7", "2.5.4.8", "2.5.4.10", "2.5.4.11"].contains(&oid.as_str())
                    && !matches!(at.value.tag(), Tag::PrintableString | Tag::Utf8String)
                {
                    return Err(ERR);
                }
            }
        }
        if !country || !cn {
            return Err(ERR);
        }
        let ski = SubjectKeyIdentifier::from_der(ext(&c, "2.5.29.14")?.extn_value.as_bytes())
            .map_err(|_| ERR)?;
        let bits = t
            .subject_public_key_info
            .subject_public_key
            .as_bytes()
            .ok_or(ERR)?;
        if bits.first() != Some(&4) || ski.0.as_bytes() != &Sha1::digest(bits)[..] {
            return Err(ERR);
        }
        let contact = IssuerAltName::from_der(ext(&c, "2.5.29.18")?.extn_value.as_bytes())
            .map_err(|_| ERR)?;
        if !contact.0.iter().any(|n| matches!(n,GeneralName::Rfc822Name(s)|GeneralName::UniformResourceIdentifier(s) if !s.as_str().is_empty())) { return Err(ERR); }
        if !ca {
            let e = ext(&c, "2.5.29.37")?;
            let eku = ExtendedKeyUsage::from_der(e.extn_value.as_bytes()).map_err(|_| ERR)?;
            if !e.critical || eku.0.len() != 1 || eku.0[0].to_string() != "1.0.18013.5.1.2" {
                return Err(ERR);
            }
            AuthorityKeyIdentifier::from_der(ext(&c, "2.5.29.35")?.extn_value.as_bytes())
                .map_err(|_| ERR)?
                .key_identifier
                .ok_or(ERR)?;
        }
        if !ca || ext(&c, "2.5.29.31").is_ok() {
            let points =
                CrlDistributionPoints::from_der(ext(&c, "2.5.29.31")?.extn_value.as_bytes())
                    .map_err(|_| ERR)?;
            if points.0.is_empty() || points.0.iter().any(|p| p.reasons.is_some() || p.crl_issuer.is_some())
                || !points.0.iter().any(|p|matches!(&p.distribution_point,Some(DistributionPointName::FullName(names)) if names.iter().any(|n|matches!(n,GeneralName::UniformResourceIdentifier(s) if !s.as_str().is_empty())))) { return Err(ERR); }
        }
    }
    Ok(c)
}
/// Pinned-key receipt compatibility: validates the presented leaf and signed expiry.
/// It does not infer trust from x5c; the caller's independently pinned key supplies trust.
pub fn pinned_leaf(
    bytes: &[u8],
    expected: &PublicJwk,
    purpose: Purpose,
    now: u64,
) -> Result<u64, &'static str> {
    let c = parse(bytes, false, purpose, now)?;
    if c.tbs_certificate.issuer == c.tbs_certificate.subject
        || &PublicJwk::from_key(&public(&c)?) != expected
    {
        return Err(ERR);
    }
    Ok(c.tbs_certificate
        .validity
        .not_after
        .to_unix_duration()
        .as_secs())
}
/// Lower timestamp bound of a certificate already validated for issuance.
/// This parses a bound only; it does not establish certificate trust.
pub fn not_before(bytes: &[u8]) -> Result<u64, &'static str> {
    Ok(Certificate::from_der(bytes)
        .map_err(|_| ERR)?
        .tbs_certificate
        .validity
        .not_before
        .to_unix_duration()
        .as_secs())
}
pub fn verify(
    trust: &SigningTrust,
    expected: &PublicJwk,
    purpose: Purpose,
    now: u64,
) -> Result<(Vec<Vec<u8>>, u64), &'static str> {
    if trust.chain.is_empty()
        || trust.chain.len() > 4
        || trust.trust_anchors.is_empty()
        || trust.trust_anchors.len() > 8
        || (purpose == Purpose::Mdoc && trust.chain.len() != 1)
    {
        return Err(ERR);
    }
    let chain = trust
        .chain
        .iter()
        .map(|s| decode_certificate(s))
        .collect::<Result<Vec<_>, _>>()?;
    let roots = trust
        .trust_anchors
        .iter()
        .map(|s| decode_certificate(s))
        .collect::<Result<Vec<_>, _>>()?;
    let mut seen = HashSet::new();
    let mut deadline = u64::MAX;
    let leaf = parse(&chain[0], false, purpose, now)?;
    deadline = deadline.min(pinned_leaf(&chain[0], expected, purpose, now)?);
    for (i, b) in chain.iter().chain(roots.iter()).enumerate() {
        if !seen.insert(b) {
            return Err(ERR);
        }
        let c = parse(b, i != 0, purpose, now)?;
        deadline = deadline.min(
            c.tbs_certificate
                .validity
                .not_after
                .to_unix_duration()
                .as_secs(),
        );
    }
    // Validate the supplied order, not only some path that webpki can build.
    // Extra unrelated intermediates and self-issued CA certificates cannot ride in x5c.
    for b in &chain[1..] {
        let c = parse(b, true, purpose, now)?;
        if c.tbs_certificate.issuer == c.tbs_certificate.subject {
            return Err(ERR);
        }
    }
    for (index, pair) in chain.windows(2).enumerate() {
        let child = parse(&pair[0], index != 0, purpose, now)?;
        let parent = parse(&pair[1], true, purpose, now)?;
        if child.tbs_certificate.issuer != parent.tbs_certificate.subject {
            return Err(ERR);
        }
        public(&parent)?
            .verify(
                &child.tbs_certificate.to_der().map_err(|_| ERR)?,
                &Signature::from_der(child.signature.as_bytes().ok_or(ERR)?).map_err(|_| ERR)?,
            )
            .map_err(|_| ERR)?;
    }
    if purpose == Purpose::Mdoc {
        let mut matched = false;
        let aki = AuthorityKeyIdentifier::from_der(ext(&leaf, "2.5.29.35")?.extn_value.as_bytes())
            .map_err(|_| ERR)?
            .key_identifier
            .ok_or(ERR)?;
        for b in &roots {
            let root = parse(b, true, purpose, now)?;
            let t = &root.tbs_certificate;
            if t.issuer != t.subject {
                return Err(ERR);
            }
            public(&root)?
                .verify(
                    &t.to_der().map_err(|_| ERR)?,
                    &Signature::from_der(root.signature.as_bytes().ok_or(ERR)?).map_err(|_| ERR)?,
                )
                .map_err(|_| ERR)?;
            let ski =
                SubjectKeyIdentifier::from_der(ext(&root, "2.5.29.14")?.extn_value.as_bytes())
                    .map_err(|_| ERR)?;
            let state = |c: &Certificate| {
                c.tbs_certificate
                    .subject
                    .0
                    .iter()
                    .flat_map(|r| r.0.iter())
                    .find(|a| a.oid.to_string() == "2.5.4.8")
                    .map(|a| a.value.clone())
            };
            if leaf.tbs_certificate.issuer == t.subject
                && aki == ski.0
                && state(&root).is_none_or(|s| state(&leaf) == Some(s))
            {
                matched = true;
            }
        }
        if !matched {
            return Err(ERR);
        }
    }
    let root_der: Vec<_> = roots
        .iter()
        .map(|b| CertificateDer::from(b.as_slice()))
        .collect();
    let anchors = root_der
        .iter()
        .map(webpki::anchor_from_trusted_cert)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ERR)?;
    let leaf_der = CertificateDer::from(chain[0].as_slice());
    let cert = webpki::EndEntityCert::try_from(&leaf_der).map_err(|_| ERR)?;
    let intermediates: Vec<_> = chain[1..]
        .iter()
        .map(|b| CertificateDer::from(b.as_slice()))
        .collect();
    let crl_bytes = trust
        .revocation
        .as_ref()
        .map(|p| p.decode())
        .transpose()?
        .unwrap_or_default();
    if let Some(p) = &trust.revocation {
        deadline = deadline.min(p.deadline(&crl_bytes, now)?);
    }
    let crls = crl_bytes
        .iter()
        .map(|b| {
            webpki::BorrowedCertRevocationList::from_der(b).map(webpki::CertRevocationList::from)
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ERR)?;
    let refs = crls.iter().collect::<Vec<_>>();
    let revocation = if trust.revocation.is_some() {
        Some(
            webpki::RevocationOptionsBuilder::new(&refs)
                .map_err(|_| ERR)?
                .with_depth(webpki::RevocationCheckDepth::Chain)
                .with_status_policy(webpki::UnknownStatusPolicy::Deny)
                .with_expiration_policy(webpki::ExpirationPolicy::Enforce)
                .build(),
        )
    } else {
        None
    };
    static MDOC_EKU: der::asn1::ObjectIdentifier =
        der::asn1::ObjectIdentifier::new_unwrap("1.0.18013.5.1.2");
    static SD_EKU: der::asn1::ObjectIdentifier =
        der::asn1::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.3");
    let usage = webpki::KeyUsage::required_if_present(if purpose == Purpose::Mdoc {
        MDOC_EKU.as_bytes()
    } else {
        SD_EKU.as_bytes()
    });
    cert.verify_for_usage(
        &[&P256Sha256],
        &anchors,
        &intermediates,
        UnixTime::since_unix_epoch(Duration::from_secs(now)),
        usage,
        revocation,
        None,
    )
    .map_err(|_| "untrusted_credential_chain")?;
    Ok((chain, deadline))
}
