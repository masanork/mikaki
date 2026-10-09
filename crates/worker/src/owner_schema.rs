//! Narrow bridges for reviewed additive owner-schema migrations.
//! The deployment gate still compares the complete schema before promotion.
const BASELINE: &str = "0001_owner_vault_initial.sql";
const WRAPPERS: &str = "0002_owner_key_wrap_operations.sql";
const WAITLIST: &str = "0003_enrollment_waitlist.sql";

pub fn ready(ledger: &str, compiled_latest: &str) -> bool {
    match compiled_latest {
        BASELINE => ledger == BASELINE || ledger == format!("{BASELINE},{WRAPPERS}"),
        WRAPPERS => {
            ledger == format!("{BASELINE},{WRAPPERS}")
                || ledger == format!("{BASELINE},{WRAPPERS},{WAITLIST}")
        }
        WAITLIST => ledger == format!("{BASELINE},{WRAPPERS},{WAITLIST}"),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridge_accepts_only_the_two_reviewed_complete_ledgers() {
        let upgraded = format!("{BASELINE},{WRAPPERS}");
        assert!(ready(BASELINE, BASELINE));
        assert!(ready(&upgraded, BASELINE));
        assert!(ready(&upgraded, WRAPPERS));
        assert!(!ready(BASELINE, WRAPPERS));
        for invalid in [
            "".to_owned(),
            WRAPPERS.to_owned(),
            format!("{WRAPPERS},{BASELINE}"),
            format!("{BASELINE},{BASELINE},{WRAPPERS}"),
            format!("{upgraded},0003_unknown.sql"),
            format!("0035_old.sql,{upgraded}"),
        ] {
            assert!(!ready(&invalid, BASELINE));
            assert!(!ready(&invalid, WRAPPERS));
        }
        assert!(!ready(&upgraded, "0003_unknown.sql"));
    }

    #[test]
    fn waitlist_requires_the_exact_complete_feature_chain() {
        let ledger = format!("{BASELINE},{WRAPPERS},{WAITLIST}");
        assert!(ready(&ledger, WAITLIST));
        for invalid in [
            BASELINE.to_owned(),
            format!("{BASELINE},{WRAPPERS}"),
            format!("{BASELINE},{WAITLIST}"),
            format!("{ledger},{WAITLIST}"),
            format!("{ledger},0004_unknown.sql"),
        ] {
            assert!(!ready(&invalid, WAITLIST));
        }
    }

    #[test]
    fn wrapper_binary_remains_ready_during_the_reviewed_waitlist_upgrade() {
        let ledger = format!("{BASELINE},{WRAPPERS},{WAITLIST}");
        assert!(ready(&ledger, WRAPPERS));
        assert!(!ready(&ledger, BASELINE));
        for invalid in [
            format!("{BASELINE},{WAITLIST}"),
            format!("{BASELINE},{WAITLIST},{WRAPPERS}"),
            format!("{ledger},{WAITLIST}"),
            format!("{ledger},0004_unknown.sql"),
        ] {
            assert!(!ready(&invalid, WRAPPERS));
        }
    }
}
