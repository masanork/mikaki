//! Offline, direct CSCA -> DSC subset. Trust anchors are application-owned,
//! fingerprint-pinned independently of the SOD. No CDP/AIA network requests.
use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use std::collections::HashSet;
use x509_cert::{
    Version,
    crl::CertificateList,
    ext::pkix::{AuthorityKeyIdentifier, CrlNumber},
};

const MAX_AGE: u64 = 90 * 86400;
struct Anchor {
    issuer: &'static [u8; 3],
    der: &'static [u8],
    sha256: &'static str,
}
const ANCHORS: &[Anchor] = &[
    Anchor {
        issuer: b"JPN",
        der: include_bytes!("../trust/jpn-2013.der"),
        sha256: "764b5259b64dc7d34d7695080f8d9d523acdb45e8436d32e3019033955066b4c",
    },
    Anchor {
        issuer: b"JPN",
        der: include_bytes!("../trust/jpn-2015.der"),
        sha256: "5434b41ed095630d193572ff0fe821a1382fbc35051fd696ae66a00738145d8b",
    },
    Anchor {
        issuer: b"JPN",
        der: include_bytes!("../trust/jpn-2019.der"),
        sha256: "493260e5d98322b0cf61eabcaf5fe34e182a9b82f862f8555e431a8268f984f1",
    },
    Anchor {
        issuer: b"JPN",
        der: include_bytes!("../trust/jpn-2024.der"),
        sha256: "fafc46eb6f3c31767f70a65295cf8c6073ba2a46ce7ee60538342a0ed53007be",
    },
];
type TrustResult<T> = std::result::Result<T, &'static str>;
fn check_true(value: bool) -> TrustResult<()> {
    if value {
        Ok(())
    } else {
        Err("invalid_certificate")
    }
}
fn map_crypto(state: State) -> &'static str {
    if state == State::Unsupported {
        "unsupported_certificate"
    } else {
        "invalid_certificate"
    }
}
fn parse_certificate(bytes: &[u8]) -> TrustResult<Certificate> {
    check_true(!bytes.is_empty() && bytes.len() <= 4096)?;
    let cert = Certificate::from_der(bytes).map_err(|_| "invalid_certificate")?;
    check_true(cert.to_der().map_err(|_| "invalid_certificate")? == bytes)?;
    Ok(cert)
}
fn deadline(cert: &Certificate, now: u64) -> TrustResult<u64> {
    let validity = cert.tbs_certificate().validity();
    let start = validity.not_before.to_unix_duration().as_secs();
    let end = validity.not_after.to_unix_duration().as_secs();
    check_true(start < end)?;
    if now < start {
        return Err("certificate_not_yet_valid");
    }
    if now >= end {
        return Err("certificate_expired");
    }
    Ok(end)
}
fn identifier(bytes: &[u8]) -> TrustResult<Vec<u8>> {
    let id = OctetString::from_der(bytes).map_err(|_| "invalid_certificate")?;
    check_true((1..=64).contains(&id.as_bytes().len()))?;
    Ok(id.as_bytes().to_vec())
}
fn authority(bytes: &[u8]) -> TrustResult<Vec<u8>> {
    let a = AuthorityKeyIdentifier::from_der(bytes).map_err(|_| "invalid_certificate")?;
    check_true(a.authority_cert_issuer.is_none() && a.authority_cert_serial_number.is_none())?;
    let id = a.key_identifier.ok_or("invalid_certificate")?;
    check_true((1..=64).contains(&id.as_bytes().len()))?;
    Ok(id.as_bytes().to_vec())
}
struct Profile {
    ski: Option<Vec<u8>>,
    aki: Option<Vec<u8>>,
}
fn profile(cert: &Certificate, ca: bool) -> TrustResult<Profile> {
    let t = cert.tbs_certificate();
    check_true(t.version() == Version::V3 && t.signature() == cert.signature_algorithm())?;
    let mut ids = HashSet::new();
    let (mut ski, mut aki, mut usage, mut basic) = (None, None, false, false);
    for e in t
        .extensions()
        .as_ref()
        .map(|v| v.as_slice())
        .unwrap_or_default()
    {
        check_true(ids.insert(e.extn_id))?;
        match e.extn_id.to_string().as_str() {
            "2.5.29.14" => ski = Some(identifier(e.extn_value.as_bytes())?),
            "2.5.29.35" => aki = Some(authority(e.extn_value.as_bytes())?),
            "2.5.29.19" => {
                let b = BasicConstraints::from_der(e.extn_value.as_bytes())
                    .map_err(|_| "invalid_certificate")?;
                check_true(b.ca == ca && (ca || b.path_len_constraint.is_none()))?;
                basic = true;
            }
            "2.5.29.15" => {
                let k = KeyUsage::from_der(e.extn_value.as_bytes())
                    .map_err(|_| "invalid_certificate")?;
                check_true(if ca {
                    k.key_cert_sign() && k.crl_sign()
                } else {
                    k.digital_signature() && !k.key_cert_sign() && !k.crl_sign()
                })?;
                usage = true;
            }
            // Purpose/path constraints are not silently ignored, even noncritical.
            "2.5.29.30" | "2.5.29.33" | "2.5.29.36" | "2.5.29.37" | "2.5.29.54" => {
                return Err("unsupported_certificate");
            }
            _ if e.critical => return Err("unsupported_certificate"),
            _ => (),
        }
    }
    check_true(usage && (!ca || (basic && ski.is_some())))?;
    Ok(Profile { ski, aki })
}

fn anchors() -> TrustResult<Vec<Certificate>> {
    ANCHORS
        .iter()
        .map(|a| {
            let actual = Sha256::digest(a.der)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            if actual != a.sha256 {
                return Err("policy_invalid");
            }
            let cert = parse_certificate(a.der)?;
            let p = profile(&cert, true)?;
            check_true(cert.tbs_certificate().issuer() == cert.tbs_certificate().subject())?;
            check_true(p.aki.is_none() || p.aki == p.ski)?;
            // Self-signature is a consistency check; only the independent pin grants trust.
            verify_signed(
                &cert,
                cert.signature_algorithm(),
                cert.signature().as_bytes().ok_or("invalid_certificate")?,
                &cert
                    .tbs_certificate()
                    .to_der()
                    .map_err(|_| "invalid_certificate")?,
            )
            .map_err(map_crypto)?;
            Ok(cert)
        })
        .collect()
}
pub(in crate::passport) fn decode_crls(json: &str) -> TrustResult<Vec<Vec<u8>>> {
    if json.len() > 350000 {
        return Err("policy_invalid");
    }
    let values: Vec<String> = serde_json::from_str(json).map_err(|_| "policy_invalid")?;
    if values.len() > 8 {
        return Err("policy_invalid");
    }
    let mut total = 0;
    values
        .into_iter()
        .map(|v| {
            if v.len() > 87384 {
                return Err("policy_invalid");
            }
            let bytes = B64.decode(&v).map_err(|_| "policy_invalid")?;
            total += bytes.len();
            if bytes.is_empty() || bytes.len() > 65536 || total > 262144 || B64.encode(&bytes) != v
            {
                return Err("policy_invalid");
            }
            Ok(bytes)
        })
        .collect()
}
pub(super) fn check(
    cert: &Certificate,
    issuer: &[u8],
    crls: &[Vec<u8>],
    now: u64,
    report: &mut Report,
) {
    report.checked_at = Some(now);
    let result = (|| {
        let roots = anchors()?;
        let candidates = ANCHORS
            .iter()
            .zip(&roots)
            .filter(|(a, _)| a.issuer.as_slice() == issuer)
            .map(|(_, c)| c.clone())
            .collect::<Vec<_>>();
        evaluate(cert, &candidates, crls, now)
    })();
    match result {
        Ok((revocation, end)) => {
            report.issuer_trust = "csca_verified";
            report.revocation = revocation;
            report.valid_until = Some(end);
        }
        Err(reason) => report.issuer_trust = reason,
    }
}
/// Direct paths only. A CRL signed by a newer pinned key for the same CSCA name
/// covers older keys too (ICAO key rollover); embedded certificates cannot supply it.
fn evaluate(
    cert: &Certificate,
    roots: &[Certificate],
    crls: &[Vec<u8>],
    now: u64,
) -> TrustResult<(&'static str, u64)> {
    if roots.is_empty() {
        return Err("unknown_issuer");
    }
    let p = profile(cert, false)?;
    let aki = p.aki.ok_or("invalid_certificate")?;
    let mut selected = None;
    for root in roots {
        let r = profile(root, true)?;
        if cert.tbs_certificate().issuer() == root.tbs_certificate().subject()
            && r.ski.as_ref() == Some(&aki)
        {
            if selected.is_some() {
                return Err("policy_invalid");
            }
            selected = Some(root);
        }
    }
    let root = selected.ok_or("unknown_issuer")?;
    let end = deadline(root, now)?.min(deadline(cert, now)?);
    verify_signed(
        root,
        cert.signature_algorithm(),
        cert.signature().as_bytes().ok_or("invalid_certificate")?,
        &cert
            .tbs_certificate()
            .to_der()
            .map_err(|_| "invalid_certificate")?,
    )
    .map_err(map_crypto)?;
    match revocation(cert, root, roots, crls, now) {
        Ok((state, crl_end)) => Ok((state, end.min(crl_end))),
        Err(reason) => Ok((reason, end)),
    }
}

fn revocation(
    cert: &Certificate,
    root: &Certificate,
    roots: &[Certificate],
    bytes: &[Vec<u8>],
    now: u64,
) -> TrustResult<(&'static str, u64)> {
    if bytes.len() > 8 || bytes.iter().map(Vec::len).sum::<usize>() > 262144 {
        return Err("invalid");
    }
    let mut selected = None;
    for b in bytes {
        if b.is_empty() || b.len() > 65536 {
            return Err("invalid");
        }
        let crl = CertificateList::from_der(b).map_err(|_| "invalid")?;
        if crl.to_der().map_err(|_| "invalid")? != *b {
            return Err("invalid");
        }
        if &crl.tbs_cert_list.issuer == cert.tbs_certificate().issuer() {
            if selected.is_some() {
                return Err("invalid");
            }
            selected = Some(crl);
        }
    }
    let crl = selected.ok_or("missing")?;
    let t = &crl.tbs_cert_list;
    if t.version != Version::V2 || t.signature != crl.signature_algorithm {
        return Err("invalid");
    }
    let mut ids = HashSet::new();
    let mut aki = None;
    let mut number = false;
    for e in t.crl_extensions.as_deref().unwrap_or_default() {
        if !ids.insert(e.extn_id) || e.critical {
            return Err("invalid");
        }
        match e.extn_id.to_string().as_str() {
            "2.5.29.35" => aki = Some(authority(e.extn_value.as_bytes()).map_err(|_| "invalid")?),
            "2.5.29.20" => {
                let n = CrlNumber::from_der(e.extn_value.as_bytes()).map_err(|_| "invalid")?;
                if n.0.as_bytes().len() > 20 {
                    return Err("invalid");
                }
                number = true;
            }
            "2.5.29.27" | "2.5.29.28" | "2.5.29.46" => return Err("unsupported"),
            _ => (),
        }
    }
    let aki = aki.ok_or("invalid")?;
    if !number {
        return Err("invalid");
    }
    let mut signer = None;
    for ca in roots {
        if ca.tbs_certificate().subject() == &t.issuer
            && profile(ca, true).map_err(|_| "invalid")?.ski.as_ref() == Some(&aki)
        {
            if signer.is_some() {
                return Err("invalid");
            }
            signer = Some(ca);
        }
    }
    let signer = signer.ok_or("invalid")?;
    let signer_end = deadline(signer, now).map_err(|_| "invalid")?;
    verify_signed(
        signer,
        &crl.signature_algorithm,
        crl.signature.as_bytes().ok_or("invalid")?,
        &t.to_der().map_err(|_| "invalid")?,
    )
    .map_err(|s| {
        if s == State::Unsupported {
            "unsupported"
        } else {
            "invalid"
        }
    })?;
    let start = t.this_update.to_unix_duration().as_secs();
    let end = t.next_update.ok_or("invalid")?.to_unix_duration().as_secs();
    if end <= start {
        return Err("invalid");
    }
    if start > now {
        return Err("not_yet_valid");
    }
    if now >= end || now >= start.saturating_add(MAX_AGE) {
        return Err("stale");
    }
    let entries = t.revoked_certificates.as_deref().unwrap_or_default();
    if entries.len() > 2048 {
        return Err("unsupported");
    }
    let mut serials = HashSet::new();
    let mut revoked = false;
    for entry in entries {
        if !serials.insert(entry.serial_number.as_bytes())
            || entry.revocation_date.to_unix_duration().as_secs() > start
        {
            return Err("invalid");
        }
        let mut ids = HashSet::new();
        for e in entry.crl_entry_extensions.as_deref().unwrap_or_default() {
            if !ids.insert(e.extn_id) || e.critical || oid(e.extn_id, "2.5.29.29") {
                return Err("unsupported");
            }
            if oid(e.extn_id, "2.5.29.21") {
                let reason = Any::from_der(e.extn_value.as_bytes()).map_err(|_| "invalid")?;
                if reason.tag() != Tag::Enumerated
                    || reason.value().len() != 1
                    || !matches!(reason.value()[0], 0..=6 | 9..=10)
                {
                    return Err("unsupported");
                }
            }
        }
        revoked |= &entry.serial_number == cert.tbs_certificate().serial_number()
            || &entry.serial_number == root.tbs_certificate().serial_number();
    }
    Ok((
        if revoked { "revoked" } else { "good" },
        end.min(start.saturating_add(MAX_AGE)).min(signer_end),
    ))
}

#[cfg(test)]
mod tests;

pub(in crate::passport) fn policy_fingerprint(crls: &[Vec<u8>]) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let mut digest = Sha256::new();
    digest.update(b"mikaki-passport-dg1-policy-v1\0");
    for a in ANCHORS {
        digest.update((a.der.len() as u64).to_be_bytes());
        digest.update(a.der);
    }
    for crl in crls {
        digest.update((crl.len() as u64).to_be_bytes());
        digest.update(crl);
    }
    URL_SAFE_NO_PAD.encode(digest.finalize())
}
pub(in crate::passport) fn policy_valid_until(crls: &[Vec<u8>], now: u64) -> TrustResult<u64> {
    let roots = anchors()?;
    let mut until = None;
    for root in &roots {
        let Ok(end) = deadline(root, now) else {
            continue;
        };
        let (state, crl_end) = revocation(root, root, &roots, crls, now)?;
        if state != "good" {
            return Err("revoked");
        }
        let end = end.min(crl_end);
        until = Some(until.map_or(end, |previous: u64| previous.min(end)));
    }
    until.ok_or("certificate_unavailable")
}

#[cfg(test)]
pub(in crate::passport) fn test_verified_fixture() -> crate::passport::VerifiedDg1 {
    let dg1 = include_bytes!("../fixtures/dg1.bin");
    let sod = include_bytes!("../fixtures/trust-rsa.sod");
    let root = parse_certificate(include_bytes!("../fixtures/trust-rsa-root.der")).unwrap();
    let crl = include_bytes!("../fixtures/trust-rsa-good.crl").to_vec();
    let time = CertificateList::from_der(&crl)
        .map(|c: CertificateList| c.tbs_cert_list.this_update.to_unix_duration().as_secs() + 1)
        .unwrap();
    let cert = verify_inner(sod, dg1).unwrap();
    let (revocation, end) = evaluate(&cert, &[root], &[crl], time).unwrap();
    let mut report = Report::new(State::Consistent);
    report.issuer_trust = "csca_verified";
    report.revocation = revocation;
    report.checked_at = Some(time);
    report.valid_until = Some(end);
    crate::passport::authorize(
        report,
        Some(crate::passport::mrz::claims(dg1).unwrap()),
        time,
    )
    .unwrap()
}
