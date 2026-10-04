//! Bounded selection for the Wallet's linked-document types and one validated receipt.
use super::*;

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
    if claims.is_empty() || claims.len() > 5 {
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
    let invalid = "unsupported_query";
    if available.is_some_and(|a| a.len() != dcql.credentials.len()) {
        return Err(invalid);
    }
    if dcql.credentials.is_empty() || dcql.credentials.len() > 8 {
        return Err(invalid);
    }
    let mut ids = HashSet::new();
    let mut matches = Vec::new();
    for q in &dcql.credentials {
        if !id(&q.id) || !ids.insert(q.id.as_str()) || q.claims.len() > 5 {
            return Err(invalid);
        }
        let type_matches = match q.format.as_str() {
            "dc+sd-jwt" => {
                if q.meta.doctype_value.is_some() {
                    return Err(invalid);
                }
                match &q.meta.vct_values {
                    None => true,
                    Some(types) => {
                        if types.is_empty()
                            || types.len() > 8
                            || types.iter().any(|t| t.is_empty() || t.len() > 1024)
                        {
                            return Err(invalid);
                        }
                        types.iter().any(|t| t == vct)
                    }
                }
            }
            "mso_mdoc" => {
                if q.meta.vct_values.is_some() {
                    return Err(invalid);
                }
                match &q.meta.doctype_value {
                    None => true,
                    Some(t) if !t.is_empty() && t.len() <= 1024 => t == crate::mdoc::DOCTYPE,
                    _ => return Err(invalid),
                }
            }
            _ => return Err(invalid),
        };
        if let Some(a) = &q.trusted_authorities {
            authorities::validate(a)?;
        }
        let mut paths = HashSet::new();
        for c in &q.claims {
            if !paths.insert(&c.path) || c.path.iter().any(|p| p.is_empty() || p.len() > 1024) {
                return Err(invalid);
            }
            match (q.format.as_str(), c.path.as_slice()) {
                ("dc+sd-jwt", [_]) if c.intent_to_retain.is_none() => {}
                ("mso_mdoc", [_, _]) => {}
                _ => return Err(invalid),
            }
        }
        // Claim/authority evaluation is deferred to the actual validated receipt.
        // Unknown claims on a potentially matching type remain unsupported.
        if type_matches {
            fields(q)?;
        }
        matches.push(type_matches && available.is_none_or(|a| a[matches.len()]));
    }
    let index = |name: &str| {
        dcql.credentials
            .iter()
            .position(|q| q.id == name)
            .ok_or(invalid)
    };
    let Some(sets) = &dcql.credential_sets else {
        if matches.iter().any(|m| !m) {
            return Err("credential_query_unsatisfied");
        }
        return Ok((0..matches.len()).collect());
    };
    if sets.is_empty() || sets.len() > 8 {
        return Err(invalid);
    }
    for set in sets {
        if set.options.is_empty() || set.options.len() > 8 {
            return Err(invalid);
        }
        for option in &set.options {
            if option.is_empty() || option.len() > 8 {
                return Err(invalid);
            }
            let mut seen = HashSet::new();
            for name in option {
                index(name)?;
                if !seen.insert(name) {
                    return Err(invalid);
                }
            }
        }
    }
    let required: Vec<_> = sets.iter().filter(|s| s.required).collect();
    for set in &required {
        if !set
            .options
            .iter()
            .any(|o| o.iter().all(|n| matches[index(n).expect("validated ID")]))
        {
            return Err("credential_query_unsatisfied");
        }
    }
    let mut selected = Vec::new();
    // First type-feasible option for every required set; optional sets are omitted.
    for set in &required {
        let option = set
            .options
            .iter()
            .find(|o| o.iter().all(|n| matches[index(n).expect("validated ID")]))
            .ok_or("credential_query_unsatisfied")?;
        for name in option {
            let i = index(name)?;
            if !selected.contains(&i) {
                selected.push(i);
            }
        }
    }
    if required.is_empty() {
        let option = sets
            .iter()
            .flat_map(|s| &s.options)
            .find(|o| o.iter().all(|n| matches[index(n).expect("validated ID")]))
            .ok_or("credential_query_unsatisfied")?;
        for name in option {
            selected.push(index(name)?);
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
            _ => return Err("unsupported_query"),
        };
        if !matches!(
            name.as_str(),
            "name" | "address" | "birthdate" | "gender" | "document_expiry_date"
        ) || !names.insert(name)
        {
            return Err("unsupported_query");
        }
        fields.push(name.clone());
        if claim.intent_to_retain == Some(true) {
            retained.push(name.clone());
        }
    }
    Ok((fields, retained))
}
