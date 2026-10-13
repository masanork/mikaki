//! Issuer-selected attributes. Omitted attributes never enter a credential.
use crate::evidence::VerifiedDocument;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Claim {
    Name,
    Address,
    Birthdate,
    Gender,
    DocumentExpiryDate,
    #[serde(rename = "age_over_18")]
    AgeOver18,
    #[serde(rename = "age_over_20")]
    AgeOver20,
}
impl Claim {
    pub fn name(self) -> &'static str {
        match self {
            Self::Name => "name",
            Self::Address => "address",
            Self::Birthdate => "birthdate",
            Self::Gender => "gender",
            Self::DocumentExpiryDate => "document_expiry_date",
            Self::AgeOver18 => "age_over_18",
            Self::AgeOver20 => "age_over_20",
        }
    }
    fn label(self) -> &'static str {
        match self {
            Self::Name => "氏名",
            Self::Address => "住所",
            Self::Birthdate => "生年月日",
            Self::Gender => "性別（カード上の符号）",
            Self::DocumentExpiryDate => "身分証の有効期限",
            Self::AgeOver18 => "18歳以上である",
            Self::AgeOver20 => "20歳以上である",
        }
    }
}

#[derive(Clone, Debug)]
pub struct ClaimProfile(Vec<Claim>);
impl Default for ClaimProfile {
    fn default() -> Self {
        Self(vec![
            Claim::Name,
            Claim::Address,
            Claim::Birthdate,
            Claim::Gender,
            Claim::DocumentExpiryDate,
        ])
    }
}
impl ClaimProfile {
    pub fn new(claims: Vec<Claim>) -> Result<Self, &'static str> {
        if claims.is_empty()
            || claims.len() > 7
            || claims
                .iter()
                .enumerate()
                .any(|(i, c)| claims[..i].contains(c))
        {
            return Err("invalid_claim_profile");
        }
        Ok(Self(claims))
    }
    pub fn from_json(raw: &str) -> Result<Self, &'static str> {
        if raw.len() > 512 {
            return Err("invalid_claim_profile");
        }
        Self::new(serde_json::from_str(raw).map_err(|_| "invalid_claim_profile")?)
    }
    pub fn age_only() -> Self {
        Self(vec![Claim::AgeOver18, Claim::AgeOver20])
    }
    pub fn all() -> Self {
        Self(vec![
            Claim::Name,
            Claim::Address,
            Claim::Birthdate,
            Claim::Gender,
            Claim::DocumentExpiryDate,
            Claim::AgeOver18,
            Claim::AgeOver20,
        ])
    }
    /// Each result becomes one independently selectable disclosure/item.
    pub fn values(&self, document: &VerifiedDocument, at: u64) -> Vec<(&'static str, Value)> {
        let a = &document.attributes;
        self.0
            .iter()
            .filter_map(|claim| {
                let value = match claim {
                    Claim::Name => json!(a.name),
                    Claim::Address => json!({"formatted":a.address}),
                    Claim::Birthdate => json!(a.birth_date),
                    Claim::Gender if !a.gender.is_empty() => json!(a.gender),
                    Claim::DocumentExpiryDate => json!(a.expiry_date.as_ref()?),
                    Claim::AgeOver18 => json!(age_over(&a.birth_date, at, 18)?),
                    Claim::AgeOver20 => json!(age_over(&a.birth_date, at, 20)?),
                    _ => return None,
                };
                Some((claim.name(), value))
            })
            .collect()
    }
    /// OID4VCI Final credential_metadata.claims and SD-JWT type metadata paths.
    pub fn metadata(&self, namespace: Option<&str>) -> Value {
        json!(
            self.0
                .iter()
                .map(|c| {
                    let path = match namespace {
                        Some(ns) => vec![ns, c.name()],
                        None => vec![c.name()],
                    };
                    json!({"path":path,"display":[{"name":c.label(),"locale":"ja"}]})
                })
                .collect::<Vec<_>>()
        )
    }
}

pub fn is_age_claim(name: &str) -> bool {
    matches!(name, "age_over_18" | "age_over_20")
}
pub fn supported(name: &str) -> bool {
    matches!(
        name,
        "name"
            | "address"
            | "birthdate"
            | "gender"
            | "document_expiry_date"
            | "age_over_18"
            | "age_over_20"
    )
}

/// Calendar age on the UTC issuance date, inclusive of the Nth birthday.
/// A Feb 29 birthday reaches the threshold on March 1 in a non-leap year.
/// Invalid, uncertain, future dates and unrepresentable clocks yield no predicate.
pub fn age_over(birthdate: &str, at: u64, threshold: u16) -> Option<bool> {
    if !crate::card::valid_date(birthdate) {
        return None;
    }
    let birth = (
        birthdate[..4].parse::<u16>().ok()?,
        birthdate[5..7].parse::<u8>().ok()?,
        birthdate[8..].parse::<u8>().ok()?,
    );
    let time = der::DateTime::from_unix_duration(std::time::Duration::from_secs(at)).ok()?;
    let today = (time.year(), time.month(), time.day());
    if birth > today {
        return None;
    }
    Some(today >= (birth.0.checked_add(threshold)?, birth.1, birth.2))
}

pub fn evidence_metadata(document: &VerifiedDocument, predicate_at: Option<u64>) -> Value {
    let mut evidence = json!({"assurance":document.assurance,"verified_at":document.verified_at,
        "trusted_key_id":document.trusted_key_id,"attributes_source":document.attributes_source,
        "live_possession_verified":false,"government_credential":false});
    if let Some(at) = predicate_at {
        evidence["verified_at"] = json!(at);
        evidence["source_verified_at"] = json!(document.verified_at);
        evidence["predicate_source"] = json!("birthdate");
    }
    evidence
}
