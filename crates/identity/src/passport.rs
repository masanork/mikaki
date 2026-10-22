//! Portable verification of signed TD3 DG1 evidence. Does not attest a live chip,
//! holder identity, full birth year, travel validity or presentation authority.
mod authentication;
pub mod credential;
mod encoding;
mod mrz;
pub use authentication::{Report, State};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use serde::{Deserialize, Serialize, ser::SerializeStruct};
use zeroize::{Zeroize, Zeroizing};

pub const MAX_SOD: usize = authentication::MAX_SOD;

/// Only original chip evidence. No caller-supplied attributes, success flags,
/// dates with inferred centuries, keys or trust anchors are accepted.
#[derive(Clone, Deserialize)]
#[serde(try_from = "WireEvidence")]
pub struct Evidence {
    dg1: Zeroizing<Vec<u8>>,
    sod: Zeroizing<Vec<u8>>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireEvidence {
    dg1: String,
    sod: String,
}
impl Drop for WireEvidence {
    fn drop(&mut self) {
        self.dg1.zeroize();
        self.sod.zeroize();
    }
}
impl TryFrom<WireEvidence> for Evidence {
    type Error = &'static str;
    fn try_from(wire: WireEvidence) -> Result<Self, Self::Error> {
        fn decode(value: &str, max: usize) -> Result<Zeroizing<Vec<u8>>, &'static str> {
            if value.len() > max {
                return Err("invalid_passport_evidence");
            }
            let bytes = Zeroizing::new(B64.decode(value).map_err(|_| "invalid_passport_evidence")?);
            let canonical = Zeroizing::new(B64.encode(&*bytes));
            if canonical.as_str() != value {
                return Err("invalid_passport_evidence");
            }
            Ok(bytes)
        }
        let evidence = Self {
            dg1: decode(&wire.dg1, 124)?,
            sod: decode(&wire.sod, 10923)?,
        };
        evidence.bounded()?;
        Ok(evidence)
    }
}
impl Serialize for Evidence {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let dg1 = Zeroizing::new(B64.encode(&*self.dg1));
        let sod = Zeroizing::new(B64.encode(&*self.sod));
        let mut out = serializer.serialize_struct("PassportEvidence", 2)?;
        out.serialize_field("dg1", dg1.as_str())?;
        out.serialize_field("sod", sod.as_str())?;
        out.end()
    }
}
impl Evidence {
    pub fn from_bytes(dg1: Vec<u8>, sod: Vec<u8>) -> Result<Self, &'static str> {
        let evidence = Self {
            dg1: Zeroizing::new(dg1),
            sod: Zeroizing::new(sod),
        };
        evidence.bounded()?;
        Ok(evidence)
    }
    fn bounded(&self) -> Result<(), &'static str> {
        if self.dg1.len() != 93 || self.sod.is_empty() || self.sod.len() > MAX_SOD {
            Err("invalid_passport_evidence")
        } else {
            Ok(())
        }
    }
    /// Diagnostic report only. A report supplied by a client is never evidence.
    pub fn inspect(&self, policy: &Policy, now: u64) -> Report {
        authentication::inspect(&self.sod, &self.dg1, policy, now)
    }
    /// Requires signature, pinned country chain and fresh complete CRL together.
    /// The result cannot be deserialized or constructed from a diagnostic report.
    pub fn verify(&self, policy: &Policy, now: u64) -> Result<VerifiedDg1, VerificationError> {
        let report = self.inspect(policy, now);
        authorize(report, mrz::claims(&self.dg1).ok(), now)
    }
}

/// Application-owned Japanese anchors are fixed in code. A policy can replace
/// revocation evidence, never enroll a SOD-embedded or caller-provided root.
pub struct Policy {
    crls: Vec<Vec<u8>>,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            crls: vec![include_bytes!("passport/trust/jpn-20260914.crl").to_vec()],
        }
    }
}
impl Policy {
    /// Operational readiness without accepting a document or granting identity authority.
    /// Requires current pinned anchors and authenticated complete CRLs.
    pub fn valid_until(&self, now: u64) -> Result<u64, &'static str> {
        authentication::policy_valid_until(&self.crls, now)
    }
    pub fn fingerprint(&self) -> String {
        authentication::policy_fingerprint(&self.crls)
    }
    pub fn from_json(json: &str) -> Result<Self, &'static str> {
        Ok(Self {
            crls: authentication::policy_crls(json)?,
        })
    }
}

/// Exact signed MRZ semantics. `*_mrz` dates remain YYMMDD; no address,
/// document number, personal number, portrait or complete MRZ is projected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Dg1Claims {
    pub name_mrz: String,
    pub issuing_state: String,
    pub nationality: String,
    pub birth_date_mrz: String,
    pub expiry_date_mrz: String,
    pub sex_mrz: String,
}
impl Drop for Dg1Claims {
    fn drop(&mut self) {
        self.name_mrz.zeroize();
        self.issuing_state.zeroize();
        self.nationality.zeroize();
        self.birth_date_mrz.zeroize();
        self.expiry_date_mrz.zeroize();
        self.sex_mrz.zeroize();
    }
}
/// Issuer-authenticated DG1 projection. Deliberately not `Deserialize`: client
/// reports cannot manufacture this result.
///
/// ```compile_fail
/// use mikaki_identity::passport::VerifiedDg1;
/// let forged: VerifiedDg1 = serde_json::from_str("{}").unwrap();
/// ```
pub struct VerifiedDg1 {
    claims: Dg1Claims,
    report: Report,
}
impl VerifiedDg1 {
    pub fn claims(&self) -> &Dg1Claims {
        &self.claims
    }
    pub fn report(&self) -> &Report {
        &self.report
    }
    /// Upper bound for the evidence's certificate/CRL checks, not passport expiry.
    pub fn evidence_valid_until(&self) -> u64 {
        self.report.valid_until.expect("verified deadline")
    }
}
#[derive(Debug, PartialEq, Eq)]
pub enum VerificationError {
    InvalidEvidence,
    UnsupportedEvidence,
    UntrustedIssuer,
    InvalidCertificate,
    RevocationUnknown,
    Revoked,
    InvalidTime,
}
impl std::fmt::Display for VerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::InvalidEvidence => "invalid_passport_evidence",
                Self::UnsupportedEvidence => "unsupported_passport_evidence",
                Self::UntrustedIssuer => "untrusted_passport_issuer",
                Self::InvalidCertificate => "invalid_passport_certificate",
                Self::RevocationUnknown => "passport_revocation_unknown",
                Self::Revoked => "passport_certificate_revoked",
                Self::InvalidTime => "invalid_passport_verification_time",
            }
        )
    }
}
impl std::error::Error for VerificationError {}
fn authorize(
    report: Report,
    claims: Option<Dg1Claims>,
    now: u64,
) -> Result<VerifiedDg1, VerificationError> {
    match report.state {
        State::Unsupported => return Err(VerificationError::UnsupportedEvidence),
        State::Consistent => (),
        _ => return Err(VerificationError::InvalidEvidence),
    }
    if report.checked_data_groups != [1] {
        return Err(VerificationError::InvalidEvidence);
    }
    match report.issuer_trust {
        "csca_verified" => (),
        "unknown_issuer" | "not_configured" => return Err(VerificationError::UntrustedIssuer),
        _ => return Err(VerificationError::InvalidCertificate),
    }
    if report.checked_at != Some(now) || report.valid_until.is_none_or(|end| end <= now) {
        return Err(VerificationError::InvalidTime);
    }
    match report.revocation {
        "good" => (),
        "revoked" => return Err(VerificationError::Revoked),
        _ => return Err(VerificationError::RevocationUnknown),
    }
    Ok(VerifiedDg1 {
        claims: claims.ok_or(VerificationError::InvalidEvidence)?,
        report,
    })
}

#[cfg(test)]
mod tests;
