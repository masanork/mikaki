//! Explicit offline complete-CRL policy; never fetches attacker-supplied CDP URLs.
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use der::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use x509_cert::{
    crl::CertificateList,
    ext::pkix::{AuthorityKeyIdentifier, CrlNumber},
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrlPolicy {
    pub crls: Vec<String>,
    /// 1 minute to 7 days; enforced in addition to nextUpdate.
    pub max_age_seconds: u64,
}
impl CrlPolicy {
    pub fn validate(&self) -> Result<(), &'static str> {
        self.decode().map(|_| ())
    }
    pub(crate) fn decode(&self) -> Result<Vec<Vec<u8>>, &'static str> {
        if self.crls.is_empty()
            || self.crls.len() > 8
            || !(60..=604800).contains(&self.max_age_seconds)
        {
            return Err("invalid_crl_policy");
        }
        let mut total = 0;
        let mut issuers = HashSet::new();
        self.crls
            .iter()
            .map(|value| {
                if value.len() > 43692 {
                    return Err("invalid_crl");
                }
                let bytes = B64.decode(value).map_err(|_| "invalid_crl")?;
                total += bytes.len();
                if bytes.is_empty()
                    || bytes.len() > 32768
                    || total > 131072
                    || B64.encode(&bytes) != *value
                {
                    return Err("invalid_crl");
                }
                let crl = structural(&bytes)?;
                if !issuers.insert(
                    crl.tbs_cert_list
                        .issuer
                        .to_der()
                        .map_err(|_| "invalid_crl")?,
                ) {
                    return Err("ambiguous_crl_issuer");
                }
                Ok(bytes)
            })
            .collect()
    }
    pub(crate) fn deadline(&self, bytes: &[Vec<u8>], now: u64) -> Result<u64, &'static str> {
        let mut deadline = u64::MAX;
        for bytes in bytes {
            let crl = structural(bytes)?;
            let start = crl.tbs_cert_list.this_update.to_unix_duration().as_secs();
            let end = crl
                .tbs_cert_list
                .next_update
                .ok_or("invalid_crl")?
                .to_unix_duration()
                .as_secs();
            if start > now {
                return Err("crl_not_yet_valid");
            }
            if now >= end {
                return Err("crl_expired");
            }
            let fresh_until = start.saturating_add(self.max_age_seconds);
            if now >= fresh_until {
                return Err("crl_stale");
            }
            deadline = deadline.min(end).min(fresh_until);
        }
        Ok(deadline)
    }
}
fn structural(bytes: &[u8]) -> Result<CertificateList, &'static str> {
    let crl = CertificateList::from_der(bytes).map_err(|_| "invalid_crl")?;
    let t = &crl.tbs_cert_list;
    if t.version != x509_cert::Version::V2
        || t.signature != crl.signature_algorithm
        || crl.signature_algorithm.oid.to_string() != "1.2.840.10045.4.3.2"
        || crl.signature_algorithm.parameters.is_some()
        || crl.signature.as_bytes().is_none()
        || t.next_update
            .is_none_or(|end| end.to_unix_duration() <= t.this_update.to_unix_duration())
    {
        return Err("invalid_crl");
    }
    let mut ids = HashSet::new();
    for e in t.crl_extensions.as_deref().unwrap_or_default() {
        let oid = e.extn_id.to_string();
        if oid == "2.5.29.35" {
            let aki = AuthorityKeyIdentifier::from_der(e.extn_value.as_bytes())
                .map_err(|_| "invalid_crl")?;
            if aki
                .key_identifier
                .is_none_or(|id| id.as_bytes().is_empty() || id.as_bytes().len() > 64)
                || aki.authority_cert_issuer.is_some()
                || aki.authority_cert_serial_number.is_some()
            {
                return Err("unsupported_crl");
            }
        }
        if oid == "2.5.29.20"
            && CrlNumber::from_der(e.extn_value.as_bytes())
                .map_err(|_| "invalid_crl")?
                .0
                .as_bytes()
                .len()
                > 20
        {
            return Err("unsupported_crl");
        }

        if !ids.insert(e.extn_id) || e.critical || matches!(oid.as_str(), "2.5.29.27" | "2.5.29.28")
        {
            return Err("unsupported_crl");
        }
    }
    // This subset requires a complete, direct v2 CRL with AKI and CRLNumber.
    if !ids.iter().any(|id| id.to_string() == "2.5.29.35")
        || !ids.iter().any(|id| id.to_string() == "2.5.29.20")
    {
        return Err("unsupported_crl");
    }
    let mut serials = HashSet::new();
    let entries = t.revoked_certificates.as_deref().unwrap_or_default();
    if entries.len() > 1024 {
        return Err("invalid_crl");
    }
    for entry in entries {
        if !serials.insert(entry.serial_number.as_bytes().to_vec())
            || entry.revocation_date.to_unix_duration() > t.this_update.to_unix_duration()
        {
            return Err("invalid_crl");
        }
        let mut ids = HashSet::new();
        for e in entry.crl_entry_extensions.as_deref().unwrap_or_default() {
            if !ids.insert(e.extn_id) || e.critical || e.extn_id.to_string() == "2.5.29.29" {
                return Err("unsupported_crl");
            }
            // Complete CRLs cannot remove entries from a previous CRL.
            if e.extn_id.to_string() == "2.5.29.21" && e.extn_value.as_bytes() == [0x0a, 0x01, 0x08]
            {
                return Err("unsupported_crl");
            }
        }
    }
    webpki::BorrowedCertRevocationList::from_der(bytes).map_err(|_| "invalid_crl")?;
    Ok(crl)
}
