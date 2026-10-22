//! Bounded ASC Draft 02 projection for internal and custom-claim UserInfo adapters.
//! This module does not assert account/person binding or enable verified_claims.
use crate::{claim_profile::age_over, evidence::VerifiedDocument};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub const TRUST_FRAMEWORK_CANDIDATE: &str = "jp_mikaki_card_static";
pub const FUNCTIONS: [&str; 2] = ["years_ago", "gte"];
pub const MAX_COUNT: usize = 2;
pub const MAX_DEPTH: usize = 2;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    InvalidRequest,
    ConsentRequired,
    ClaimUnavailable,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Claims {
    userinfo: UserInfo,
    #[serde(rename = "_asc")]
    asc: Asc,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UserInfo {
    verified_claims: VerifiedClaims,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LinkedClaims {
    userinfo: LinkedUserInfo,
    #[serde(rename = "_asc")]
    asc: Asc,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LinkedUserInfo {
    mikaki_linked_document: LinkedDocument,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LinkedDocument {
    attributes: BTreeMap<String, Option<Constraint>>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifiedClaims {
    verification: Verification,
    claims: BTreeMap<String, Option<Constraint>>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Verification {
    trust_framework: Value,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Asc {
    transformed_claims: BTreeMap<String, Definition>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Definition {
    claim: String,
    r#fn: Vec<Value>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Constraint {
    #[serde(rename = "essential", default, deserialize_with = "boolean_option")]
    _essential: Option<bool>,
    #[serde(default, deserialize_with = "boolean_option")]
    value: Option<bool>,
}
fn boolean_option<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<bool>, D::Error> {
    bool::deserialize(d).map(Some)
}

/// Validated definitions. No raw birthdate request, arbitrary alias/function,
/// caller-selected reference date, ID Token delivery or selective-abort program.
pub struct AgeRequest {
    claims: Vec<(String, u16, Option<bool>)>,
}
impl AgeRequest {
    /// The eventual wire adapter must authenticate/integrity-protect this at PAR.
    pub fn parse(raw: &[u8]) -> Result<Self, Error> {
        let invalid = || Error::InvalidRequest;
        if raw.len() > 4096 {
            return Err(invalid());
        }
        let value = crate::wallet_profile::strict_json(raw).map_err(|_| invalid())?;
        let request: Claims = serde_json::from_value(value).map_err(|_| invalid())?;
        let claims = request.userinfo.verified_claims;
        if !matches!(claims.verification.trust_framework, Value::Null)
            && claims.verification.trust_framework != json!({"value":TRUST_FRAMEWORK_CANDIDATE})
        {
            return Err(invalid());
        }
        Self::validate(claims.claims, request.asc)
    }
    /// Experimental custom-claim delivery. This carries static source assurance,
    /// never verified person/account binding. Accept only authenticated PAR input.
    pub fn parse_linked(raw: &[u8]) -> Result<Self, Error> {
        if raw.len() > 4096 {
            return Err(Error::InvalidRequest);
        }
        let value = crate::wallet_profile::strict_json(raw).map_err(|_| Error::InvalidRequest)?;
        let request: LinkedClaims =
            serde_json::from_value(value).map_err(|_| Error::InvalidRequest)?;
        Self::validate(
            request.userinfo.mikaki_linked_document.attributes,
            request.asc,
        )
    }
    fn validate(claims: BTreeMap<String, Option<Constraint>>, asc: Asc) -> Result<Self, Error> {
        let invalid = || Error::InvalidRequest;
        if asc.transformed_claims.is_empty()
            || asc.transformed_claims.len() > MAX_COUNT
            || claims.is_empty()
            || claims.len() > MAX_COUNT
        {
            return Err(invalid());
        }
        let mut definitions = BTreeMap::new();
        for (alias, definition) in asc.transformed_claims {
            let threshold = match alias.as_str() {
                "age_over_18" => 18,
                "age_over_20" => 20,
                _ => return Err(invalid()),
            };
            if definition.claim != "birthdate"
                || definition.r#fn != vec![json!("years_ago"), json!(["gte", threshold])]
            {
                return Err(invalid());
            }
            definitions.insert(alias, threshold);
        }
        let mut selected = Vec::new();
        for (name, constraint) in claims {
            let alias = name.strip_prefix(':').ok_or_else(invalid)?;
            let threshold = *definitions.get(alias).ok_or_else(invalid)?;
            let expected = constraint.and_then(|c| c.value);
            selected.push((name, threshold, expected));
        }
        Ok(Self { claims: selected })
    }
    pub fn consent_fields(&self) -> Vec<&str> {
        self.claims.iter().map(|(name, _, _)| &name[1..]).collect()
    }
    /// Use only independently verified/revalidated document data and live RP-specific consent.
    /// A predicate's consent is distinct from permission to disclose the birthdate value.
    pub fn project(
        &self,
        document: &VerifiedDocument,
        consent: &[String],
        at: u64,
    ) -> Result<Value, Error> {
        if document.assurance != "issuer_signed_static_data" || document.verified_at > at {
            return Err(Error::ClaimUnavailable);
        }
        let mut result = serde_json::Map::new();
        for (name, threshold, expected) in &self.claims {
            if !consent.iter().any(|field| field == &name[1..]) {
                return Err(Error::ConsentRequired);
            }
            let value = age_over(&document.attributes.birth_date, at, *threshold)
                .ok_or(Error::ClaimUnavailable)?;
            if expected.is_some_and(|expected| value != expected) {
                return Err(Error::ClaimUnavailable);
            }
            result.insert(name.clone(), json!(value));
        }
        Ok(Value::Object(result))
    }
}

/// Consumer-authored metadata from an independently verified linkage, never civ's advisory record.
/// No raw attributes, document identifier, source signature, DF31/32/33, reader ID or PIN.
pub fn consumer_evidence(document: &VerifiedDocument, at: u64) -> Result<Value, Error> {
    if document.assurance != "issuer_signed_static_data"
        || document.verified_at > at
        || document.trusted_key_id.is_empty()
        || document.trusted_key_id.len() > 128
    {
        return Err(Error::ClaimUnavailable);
    }
    fn timestamp(at: u64) -> Result<String, Error> {
        let t = der::DateTime::from_unix_duration(std::time::Duration::from_secs(at))
            .map_err(|_| Error::ClaimUnavailable)?;
        Ok(format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            t.year(),
            t.month(),
            t.day(),
            t.hour(),
            t.minutes(),
            t.seconds()
        ))
    }
    let source_type = match document.attributes.document_type {
        crate::card::DocumentType::MyNumberCard => "jp_mnc_input_support_static",
        crate::card::DocumentType::DrivingLicense => "jp_driving_license_static",
        crate::card::DocumentType::Passport => return Err(Error::ClaimUnavailable),
    };
    Ok(
        json!({"type":"electronic_record","record":{"type":source_type},
        "check_details":[{"check_method":"data","time":timestamp(document.verified_at)?}],
        "_mikaki":{"verifier":"consumer","document_type":document.attributes.document_type,
        "trusted_key_id":document.trusted_key_id,"assurance":document.assurance,
        "attributes_source":document.attributes_source,"predicate_verified_at":timestamp(at)?,
        "live_possession_verified":false,"revocation_checked":false,"government_credential":false}}),
    )
}
