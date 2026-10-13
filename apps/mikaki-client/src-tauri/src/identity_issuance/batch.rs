//! Validate the complete response before one inventory write. No partial installation.
use super::*;
use mikaki_identity::{
    age_batch::MAX_SIZE,
    claim_profile::{self, ClaimProfile},
};

pub(super) fn metadata_claims(metadata: &Value, configuration: &str) -> Result<String, String> {
    if metadata["mikaki_age_batch_intake"]["batch_size"].as_u64() != Some(MAX_SIZE as u64) {
        return Err("age_batch_unavailable".into());
    }
    let paths = metadata["credential_configurations_supported"][configuration]
        ["credential_metadata"]["claims"]
        .as_array()
        .filter(|v| !v.is_empty() && v.len() <= 2)
        .ok_or("invalid_metadata")?;
    let names = paths
        .iter()
        .map(|v| {
            let path = v["path"].as_array().ok_or("invalid_metadata")?;
            match path.as_slice() {
                [name] if configuration == issuance::CONFIGURATION => {
                    name.as_str().ok_or("invalid_metadata")
                }
                [ns, name] if configuration == mdoc::CONFIGURATION && ns == mdoc::NAMESPACE => {
                    name.as_str().ok_or("invalid_metadata")
                }
                _ => Err("invalid_metadata"),
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    let profile =
        ClaimProfile::from_json(&json!(names).to_string()).map_err(|_| "invalid_metadata")?;
    if !profile.is_age_only() {
        return Err("invalid_metadata".into());
    }
    Ok(profile.to_json())
}

pub(super) fn verify_response(
    issued: Value,
    keys: Vec<HolderKey>,
    configuration: &str,
    issuer_key: PublicJwk,
    kid: String,
    claims_json: Option<&str>,
    at: u64,
) -> Result<Vec<Receipt>, String> {
    let entries = issued["credentials"]
        .as_array()
        .filter(|a| a.len() == keys.len() && !a.is_empty() && a.len() <= MAX_SIZE)
        .ok_or("invalid_response")?;
    let expected: Option<Vec<String>> = claims_json
        .map(serde_json::from_str)
        .transpose()
        .map_err(|_| "invalid_metadata")?;
    if keys.len() > 1 && expected.is_none() {
        return Err("invalid_response".into());
    }
    let format = match configuration {
        issuance::CONFIGURATION => "dc+sd-jwt",
        mdoc::CONFIGURATION => "mso_mdoc",
        _ => return Err("invalid_configuration".into()),
    };
    let mut receipts = Vec::with_capacity(keys.len());
    for (entry, key) in entries.iter().zip(keys) {
        if entry.as_object().is_none_or(|o| o.len() != 1) {
            return Err("invalid_response".into());
        }
        let mut receipt = Receipt {
            credential: Zeroizing::new(
                entry["credential"]
                    .as_str()
                    .ok_or("invalid_response")?
                    .to_owned(),
            ),
            format: format.into(),
            key,
            expires_at: 0,
            issuer_key: issuer_key.clone(),
            issuer_kid: kid.clone(),
            credential_trust: None,
        };
        let (expiry, values) = receipt.verified_values(ISSUER, at)?;
        if let Some(expected) = &expected {
            let fields: Vec<_> = values
                .as_object()
                .ok_or("invalid_credential")?
                .keys()
                .filter(|n| claim_profile::supported(n))
                .collect();
            if fields.len() != expected.len()
                || fields.iter().any(|n| !expected.contains(n))
                || expected
                    .iter()
                    .any(|n| !claim_profile::is_age_claim(n) || !values[n].is_boolean())
                || expiry > at.saturating_add(300)
            {
                return Err("invalid_credential".into());
            }
        }
        receipt.expires_at = expiry;
        receipts.push(receipt);
    }
    Ok(receipts)
}

pub(super) fn install(
    existing: &[Receipt],
    incoming: Vec<Receipt>,
    at: u64,
    persist: impl FnOnce(&[Receipt]) -> Result<(), String>,
) -> Result<Vec<Receipt>, String> {
    let mut inventory: Vec<_> = existing
        .iter()
        .filter(|r| r.expires_at > at)
        .cloned()
        .collect();
    if incoming.is_empty() || inventory.len() + incoming.len() > MAX_SIZE {
        return Err("wallet_inventory_full".into());
    }
    for receipt in &incoming {
        if receipt.validate(ISSUER, at)? != receipt.expires_at {
            return Err("invalid_credential".into());
        }
    }
    inventory.extend(incoming);
    let mut credentials = std::collections::HashSet::new();
    let mut holders = std::collections::HashSet::new();
    for receipt in &inventory {
        if !credentials.insert(credential_hash(&receipt.credential))
            || !holders.insert(receipt.key.public()?.thumbprint().map_err(str::to_string)?)
        {
            return Err("credential_already_saved".into());
        }
    }
    persist(&inventory)?;
    Ok(inventory)
}

#[cfg(all(test, not(target_os = "android")))]
mod tests {
    use super::*;
    use crate::identity_wallet::credential_trust_tests::receipt_with_profile;
    const AT: u64 = 1791000000;
    fn receipt(format: &str, seed: u8, profile: &ClaimProfile) -> Receipt {
        receipt_with_profile(format, seed, ISSUER, profile)
    }
    fn wire(receipts: &[Receipt]) -> Value {
        json!({"credentials":receipts.iter().map(|r|json!({"credential":&*r.credential})).collect::<Vec<_>>()})
    }
    fn verify(
        issued: Value,
        receipts: &[Receipt],
        configuration: &str,
    ) -> Result<Vec<Receipt>, String> {
        verify_response(
            issued,
            receipts.iter().map(|r| r.key.clone()).collect(),
            configuration,
            receipts[0].issuer_key.clone(),
            receipts[0].issuer_kid.clone(),
            Some(&ClaimProfile::age_only().to_json()),
            AT,
        )
    }
    #[test]
    fn both_formats_validate_all_eight_bindings_before_a_single_write() {
        for (format, configuration) in [
            ("dc+sd-jwt", issuance::CONFIGURATION),
            ("mso_mdoc", mdoc::CONFIGURATION),
        ] {
            let fixtures = (1..=8)
                .map(|i| receipt(format, i, &ClaimProfile::age_only()))
                .collect::<Vec<_>>();
            let validated = verify(wire(&fixtures), &fixtures, configuration).unwrap();
            let mut writes = 0;
            let installed = install(&[], validated, AT, |all| {
                writes += 1;
                assert_eq!(all.len(), 8);
                Ok(())
            })
            .unwrap();
            assert_eq!(writes, 1);
            assert_eq!(installed.len(), 8);
            let mut bad = wire(&fixtures);
            bad["credentials"][7]["credential"] = json!("tampered");
            assert!(verify(bad, &fixtures, configuration).is_err());
            let mut swapped = wire(&fixtures);
            swapped["credentials"].as_array_mut().unwrap().swap(0, 7);
            assert!(verify(swapped, &fixtures, configuration).is_err());
            let mut duplicate = wire(&fixtures);
            duplicate["credentials"][7] = duplicate["credentials"][0].clone();
            assert!(verify(duplicate, &fixtures, configuration).is_err());
            let mut partial = wire(&fixtures);
            partial["credentials"].as_array_mut().unwrap().pop();
            assert!(verify(partial, &fixtures, configuration).is_err());
            let mut mixed = fixtures.clone();
            mixed[7] = receipt(format, 8, &ClaimProfile::all());
            assert!(verify(wire(&mixed), &mixed, configuration).is_err());
            let one = ClaimProfile::from_json("[\"age_over_18\"]").unwrap();
            let mut missing = fixtures.clone();
            missing[7] = receipt(format, 8, &one);
            assert!(verify(wire(&missing), &missing, configuration).is_err());
        }
    }
    #[test]
    fn failed_persistence_capacity_or_final_signature_never_installs_a_partial_batch() {
        let old = vec![receipt("dc+sd-jwt", 1, &ClaimProfile::age_only())];
        let new = vec![
            receipt("dc+sd-jwt", 2, &ClaimProfile::age_only()),
            receipt("mso_mdoc", 3, &ClaimProfile::age_only()),
        ];
        let original = credential_hash(&old[0].credential);
        assert_eq!(
            install(&old, new.clone(), AT, |all| {
                assert_eq!(all.len(), 3);
                Err("wallet_storage_unavailable".into())
            })
            .err()
            .as_deref(),
            Some("wallet_storage_unavailable")
        );
        assert_eq!(credential_hash(&old[0].credential), original);
        let mut invalid = new.clone();
        invalid[1].credential.push_str("tamper");
        assert!(install(&old, invalid, AT, |_| panic!("verify all before writing")).is_err());
        assert!(install(&old, vec![old[0].clone()], AT, |_| panic!("duplicate key")).is_err());
        let too_many = (2..=9)
            .map(|i| receipt("dc+sd-jwt", i, &ClaimProfile::age_only()))
            .collect();
        assert!(install(&old, too_many, AT, |_| panic!("capacity checked first")).is_err());
        let installed = install(&old, new, AT, |all| {
            assert_eq!(credential_hash(&all[0].credential), original);
            Ok(())
        })
        .unwrap();
        assert_eq!(installed.len(), 3);
    }
    #[test]
    fn capability_and_complete_metadata_profile_are_required() {
        let mut metadata = json!({"mikaki_age_batch_intake":{"batch_size":8},"credential_configurations_supported":{"linked_document":{"credential_metadata":{"claims":[{"path":["age_over_18"]},{"path":["age_over_20"]}]}}}});
        assert_eq!(
            metadata_claims(&metadata, issuance::CONFIGURATION).unwrap(),
            ClaimProfile::age_only().to_json()
        );
        metadata["credential_configurations_supported"][issuance::CONFIGURATION]
            ["credential_metadata"]["claims"][1]["path"] = json!(["birthdate"]);
        assert!(metadata_claims(&metadata, issuance::CONFIGURATION).is_err());
        metadata["mikaki_age_batch_intake"]["batch_size"] = json!(16);
        assert!(metadata_claims(&metadata, issuance::CONFIGURATION).is_err());
    }
}
