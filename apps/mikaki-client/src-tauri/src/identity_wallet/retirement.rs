//! Commit age-only receipt retirement before any external presentation dispatch.
use super::{HolderKey, Receipt};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

fn hash(receipt: &Receipt) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(receipt.credential.as_bytes()))
}

/// Validate every selected receipt before writing once. A repeated selection of
/// one credential consumes it once; no matching credential may be substituted.
/// On storage failure no caller may dispatch. On success update memory before
/// returning keys for destruction, including when the last slot was consumed.
pub(crate) fn commit(
    receipts: &mut Vec<Receipt>,
    selected: &[String],
    issuer: &str,
    at: u64,
    persist: impl FnOnce(&[Receipt], &Receipt) -> Result<(), String>,
) -> Result<Vec<HolderKey>, String> {
    if receipts.len() > 8 || selected.is_empty() || selected.len() > 8 {
        return Err("invalid_inventory".into());
    }
    let mut retired = HashSet::new();
    for id in selected {
        let receipt = receipts
            .iter()
            .find(|r| hash(r) == *id)
            .ok_or("credential_changed")?;
        if receipt.single_use(issuer, at)? {
            retired.insert(id.as_str());
        }
    }
    if retired.is_empty() {
        return Ok(Vec::new());
    }
    let remaining: Vec<_> = receipts
        .iter()
        .filter(|r| !retired.contains(hash(r).as_str()))
        .cloned()
        .collect();
    let anchor = receipts
        .iter()
        .find(|r| retired.contains(hash(r).as_str()))
        .ok_or("credential_changed")?;
    persist(&remaining, anchor)?;
    let removed: Vec<_> = receipts
        .iter()
        .filter(|r| retired.contains(hash(r).as_str()))
        .map(|r| r.key.clone())
        .collect();
    *receipts = remaining;
    Ok(removed)
}

#[cfg(all(test, not(target_os = "android")))]
mod tests {
    use super::*;
    use crate::identity_wallet::credential_trust_tests::receipt_with_profile;
    use mikaki_identity::claim_profile::ClaimProfile;
    const AT: u64 = 1791000000;
    const ISSUER: &str = "https://issuer.example/identity/issuer";
    fn receipt(format: &str, seed: u8, age: bool) -> Receipt {
        receipt_with_profile(
            format,
            seed,
            ISSUER,
            &if age {
                ClaimProfile::age_only()
            } else {
                ClaimProfile::all()
            },
        )
    }
    #[test]
    fn retirement_uses_complete_authenticated_profile_and_keeps_unselected_and_mixed_receipts() {
        let mut receipts = vec![
            receipt("dc+sd-jwt", 3, true),
            receipt("mso_mdoc", 4, true),
            receipt("dc+sd-jwt", 5, false),
        ];
        assert!(receipts[0].single_use(ISSUER, AT).unwrap());
        assert!(receipts[1].single_use(ISSUER, AT).unwrap());
        assert!(!receipts[2].single_use(ISSUER, AT).unwrap());
        let selected = vec![hash(&receipts[0]), hash(&receipts[0]), hash(&receipts[2])];
        let retained = vec![hash(&receipts[1]), hash(&receipts[2])];
        let mut writes = 0;
        let removed = commit(&mut receipts, &selected, ISSUER, AT, |remaining, anchor| {
            writes += 1;
            assert_eq!(remaining.iter().map(hash).collect::<Vec<_>>(), retained);
            assert_eq!(hash(anchor), selected[0]);
            Ok(())
        })
        .unwrap();
        assert_eq!(writes, 1);
        assert_eq!(removed.len(), 1);
        assert_eq!(receipts.iter().map(hash).collect::<Vec<_>>(), retained);
        assert!(commit(&mut receipts, &selected, ISSUER, AT, |_, _| panic!(
            "no substitution or second use"
        ))
        .is_err());
        let mixed = vec![hash(&receipts[1])];
        assert!(commit(&mut receipts, &mixed, ISSUER, AT, |_, _| panic!(
            "mixed profiles remain reusable"
        ))
        .unwrap()
        .is_empty());
    }
    #[test]
    fn last_receipt_commit_is_empty_and_network_failure_never_replenishes_the_inventory() {
        for format in ["dc+sd-jwt", "mso_mdoc"] {
            let mut receipts = vec![receipt(format, 3, true)];
            let selected = vec![hash(&receipts[0])];
            let holder = receipts[0].key.public().unwrap();
            let mut stored = false;
            let keys = commit(&mut receipts, &selected, ISSUER, AT, |remaining, anchor| {
                assert!(remaining.is_empty());
                assert_eq!(anchor.key.public().unwrap(), holder);
                stored = true;
                Ok(())
            })
            .unwrap();
            assert!(stored && receipts.is_empty());
            assert_eq!(keys.len(), 1);
            // A failed/unknown dispatch has no rollback/requeue path. Neither a
            // different request nor another RP can select the consumed receipt.
            let transport: Result<(), &str> = Err("unknown delivery");
            assert!(transport.is_err());
            assert!(commit(&mut receipts, &selected, ISSUER, AT, |_, _| panic!(
                "used receipt must not be persisted again"
            ))
            .is_err());
        }
    }
    #[test]
    fn persistence_failure_and_any_invalid_selection_stop_before_retirement_or_dispatch() {
        let mut receipts = vec![receipt("dc+sd-jwt", 3, true), receipt("mso_mdoc", 4, true)];
        let original = receipts.iter().map(hash).collect::<Vec<_>>();
        assert_eq!(
            commit(&mut receipts, &original, ISSUER, AT, |_, _| Err(
                "wallet_storage_unavailable".into()
            ))
            .err()
            .as_deref(),
            Some("wallet_storage_unavailable")
        );
        assert_eq!(receipts.iter().map(hash).collect::<Vec<_>>(), original);
        let mut unknown = original.clone();
        unknown.push("unknown".into());
        assert!(commit(&mut receipts, &unknown, ISSUER, AT, |_, _| panic!(
            "validate the complete selection before persisting"
        ))
        .is_err());
        receipts[1].credential.push_str("tamper");
        let changed = receipts.iter().map(hash).collect::<Vec<_>>();
        assert!(commit(&mut receipts, &changed, ISSUER, AT, |_, _| panic!(
            "signature failure must not partially retire another receipt"
        ))
        .is_err());
        assert_eq!(receipts.len(), 2);
        assert!(commit(&mut receipts, &[], ISSUER, AT, |_, _| panic!()).is_err());
    }
}
