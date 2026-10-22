//! Bounded selection for the Wallet's linked-document types and one validated receipt.
use super::{Claim, Dcql, Query, authorities};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

const UNSUPPORTED_QUERY: &str = "unsupported_query";
const UNSATISFIED_QUERY: &str = "credential_query_unsatisfied";

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CredentialSet {
    options: Vec<Vec<String>>,
    #[serde(default = "required")]
    required: bool,
}
fn required() -> bool {
    true
}
pub(super) fn non_null_sets<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<Vec<CredentialSet>>, D::Error> {
    Vec::<CredentialSet>::deserialize(d).map(Some)
}
pub(super) fn non_null_types<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<Vec<String>>, D::Error> {
    Vec::<String>::deserialize(d).map(Some)
}
pub(super) fn present_claims<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Vec<Claim>, D::Error> {
    let claims = Vec::<Claim>::deserialize(d)?;
    if claims.is_empty() || claims.len() > 7 {
        return Err(serde::de::Error::custom("nonempty bounded claims required"));
    }
    Ok(claims)
}
fn id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}
/// Validate every entry before selection, including optional/nonmatching entries.
/// This is profile/type feasibility, not proof of a valid or available receipt.
pub(super) fn select(dcql: &Dcql, vct: &str) -> Result<Vec<usize>, &'static str> {
    select_available(dcql, vct, None)
}
pub(super) fn select_available(
    dcql: &Dcql,
    vct: &str,
    available: Option<&[bool]>,
) -> Result<Vec<usize>, &'static str> {
    select_available_types(dcql, &[vct.to_owned()], available)
}
pub(super) fn catalog(vct: &str) -> Vec<String> {
    let mut types = vec![vct.to_owned()];
    if let Some(issuer) = vct.strip_suffix("/types/linked-document") {
        types.push(crate::passport::credential::vct(issuer));
    }
    types
}
pub(super) fn select_available_types(
    dcql: &Dcql,
    vcts: &[String],
    available: Option<&[bool]>,
) -> Result<Vec<usize>, &'static str> {
    let matches = matching_credentials(dcql, vcts, available)?;
    let Some(sets) = &dcql.credential_sets else {
        if matches.iter().any(|m| !m) {
            return Err(UNSATISFIED_QUERY);
        }
        return Ok((0..matches.len()).collect());
    };
    validate_sets(dcql, sets)?;
    select_sets(dcql, sets, &matches)
}

fn credential_type_matches(query: &Query, vcts: &[String]) -> Result<bool, &'static str> {
    match query.format.as_str() {
        "dc+sd-jwt" => {
            if query.meta.doctype_value.is_some() {
                return Err(UNSUPPORTED_QUERY);
            }
            match &query.meta.vct_values {
                None => Ok(true),
                Some(types) => {
                    if types.is_empty()
                        || types.len() > 8
                        || types.iter().any(|t| t.is_empty() || t.len() > 1024)
                    {
                        return Err(UNSUPPORTED_QUERY);
                    }
                    Ok(types.iter().any(|t| vcts.contains(t)))
                }
            }
        }
        "mso_mdoc" => {
            if query.meta.vct_values.is_some() {
                return Err(UNSUPPORTED_QUERY);
            }
            match &query.meta.doctype_value {
                None => Ok(true),
                Some(t) if !t.is_empty() && t.len() <= 1024 => Ok(t == crate::mdoc::DOCTYPE),
                _ => Err(UNSUPPORTED_QUERY),
            }
        }
        _ => Err(UNSUPPORTED_QUERY),
    }
}

fn validate_claim_paths(query: &Query) -> Result<(), &'static str> {
    let mut paths = HashSet::new();
    for claim in &query.claims {
        if !paths.insert(&claim.path) || claim.path.iter().any(|p| p.is_empty() || p.len() > 1024) {
            return Err(UNSUPPORTED_QUERY);
        }
        match (query.format.as_str(), claim.path.as_slice()) {
            ("dc+sd-jwt", [_]) if claim.intent_to_retain.is_none() => {}
            ("mso_mdoc", [_, _]) => {}
            _ => return Err(UNSUPPORTED_QUERY),
        }
    }
    Ok(())
}

fn matching_credentials(
    dcql: &Dcql,
    vcts: &[String],
    available: Option<&[bool]>,
) -> Result<Vec<bool>, &'static str> {
    if available.is_some_and(|a| a.len() != dcql.credentials.len()) {
        return Err(UNSUPPORTED_QUERY);
    }
    if dcql.credentials.is_empty() || dcql.credentials.len() > 8 {
        return Err(UNSUPPORTED_QUERY);
    }
    let mut ids = HashSet::new();
    let mut matches = Vec::new();
    for query in &dcql.credentials {
        if !id(&query.id) || !ids.insert(query.id.as_str()) || query.claims.len() > 7 {
            return Err(UNSUPPORTED_QUERY);
        }
        let type_matches = credential_type_matches(query, vcts)?;
        if let Some(authorities) = &query.trusted_authorities {
            authorities::validate(authorities)?;
        }
        validate_claim_paths(query)?;
        // Claim/authority evaluation is deferred to the actual validated receipt.
        // Unknown claims on a potentially matching type remain unsupported.
        if type_matches {
            fields(query)?;
        }
        matches.push(type_matches && available.is_none_or(|a| a[matches.len()]));
    }
    Ok(matches)
}

fn credential_index(dcql: &Dcql, name: &str) -> Result<usize, &'static str> {
    dcql.credentials
        .iter()
        .position(|query| query.id == name)
        .ok_or(UNSUPPORTED_QUERY)
}

fn validate_sets(dcql: &Dcql, sets: &[CredentialSet]) -> Result<(), &'static str> {
    if sets.is_empty() || sets.len() > 8 {
        return Err(UNSUPPORTED_QUERY);
    }
    for set in sets {
        if set.options.is_empty() || set.options.len() > 8 {
            return Err(UNSUPPORTED_QUERY);
        }
        for option in &set.options {
            if option.is_empty() || option.len() > 8 {
                return Err(UNSUPPORTED_QUERY);
            }
            let mut seen = HashSet::new();
            for name in option {
                credential_index(dcql, name)?;
                if !seen.insert(name) {
                    return Err(UNSUPPORTED_QUERY);
                }
            }
        }
    }
    Ok(())
}

// Set references have all been validated before checking whether an option is satisfiable.
fn option_matches(dcql: &Dcql, option: &[String], matches: &[bool]) -> bool {
    option
        .iter()
        .all(|name| matches[credential_index(dcql, name).expect("validated ID")])
}

fn select_sets(
    dcql: &Dcql,
    sets: &[CredentialSet],
    matches: &[bool],
) -> Result<Vec<usize>, &'static str> {
    let required: Vec<_> = sets.iter().filter(|set| set.required).collect();
    for set in &required {
        if !set
            .options
            .iter()
            .any(|option| option_matches(dcql, option, matches))
        {
            return Err(UNSATISFIED_QUERY);
        }
    }
    let mut selected = Vec::new();
    // First type-feasible option for every required set; optional sets are omitted.
    for set in &required {
        let option = set
            .options
            .iter()
            .find(|option| option_matches(dcql, option, matches))
            .ok_or(UNSATISFIED_QUERY)?;
        for name in option {
            let index = credential_index(dcql, name)?;
            if !selected.contains(&index) {
                selected.push(index);
            }
        }
    }
    if required.is_empty() {
        let option = sets
            .iter()
            .flat_map(|set| &set.options)
            .find(|option| option_matches(dcql, option, matches))
            .ok_or(UNSATISFIED_QUERY)?;
        for name in option {
            selected.push(credential_index(dcql, name)?);
        }
    }
    Ok(selected)
}

pub(super) fn fields(query: &Query) -> Result<(Vec<String>, Vec<String>), &'static str> {
    let mut names = HashSet::new();
    let mut fields = Vec::new();
    let mut retained = Vec::new();
    for claim in &query.claims {
        let name = match (query.format.as_str(), claim.path.as_slice()) {
            ("dc+sd-jwt", [name]) if claim.intent_to_retain.is_none() => name,
            ("mso_mdoc", [ns, name]) if ns == crate::mdoc::NAMESPACE => name,
            _ => return Err(UNSUPPORTED_QUERY),
        };
        if !(crate::claim_profile::supported(name)
            || (query.format == "dc+sd-jwt"
                && crate::passport::credential::FIELDS.contains(&name.as_str())))
            || !names.insert(name)
        {
            return Err(UNSUPPORTED_QUERY);
        }
        fields.push(name.clone());
        if claim.intent_to_retain == Some(true) {
            retained.push(name.clone());
        }
    }
    Ok((fields, retained))
}

#[cfg(test)]
mod tests;
