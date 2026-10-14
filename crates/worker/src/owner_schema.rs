//! Narrow bridges for reviewed additive owner-schema migrations.
//! The deployment gate still compares the complete schema before promotion.
const BASELINE: &str = "0001_owner_vault_initial.sql";
const WRAPPERS: &str = "0002_owner_key_wrap_operations.sql";
const WAITLIST: &str = "0003_enrollment_waitlist.sql";
const AGE_REQUESTS: &str = "0004_identity_age_requests.sql";
const LOGIN_REVIEW: &str = "0005_login_connection_review.sql";

pub fn ready(ledger: &str, compiled_latest: &str) -> bool {
    match compiled_latest {
        BASELINE => ledger == BASELINE || ledger == format!("{BASELINE},{WRAPPERS}"),
        WRAPPERS => {
            ledger == format!("{BASELINE},{WRAPPERS}")
                || ledger == format!("{BASELINE},{WRAPPERS},{WAITLIST}")
        }
        WAITLIST => {
            ledger == format!("{BASELINE},{WRAPPERS},{WAITLIST}")
                || ledger == format!("{BASELINE},{WRAPPERS},{WAITLIST},{AGE_REQUESTS}")
        }
        AGE_REQUESTS => {
            ledger == format!("{BASELINE},{WRAPPERS},{WAITLIST},{AGE_REQUESTS}")
                || ledger
                    == format!("{BASELINE},{WRAPPERS},{WAITLIST},{AGE_REQUESTS},{LOGIN_REVIEW}")
        }
        LOGIN_REVIEW => {
            ledger == format!("{BASELINE},{WRAPPERS},{WAITLIST},{AGE_REQUESTS},{LOGIN_REVIEW}")
        }
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

    #[test]
    fn age_request_chain_bridges_only_the_immediately_previous_binary() {
        let ledger = format!("{BASELINE},{WRAPPERS},{WAITLIST},{AGE_REQUESTS}");
        assert!(ready(&ledger, WAITLIST));
        assert!(ready(&ledger, AGE_REQUESTS));
        assert!(!ready(&ledger, WRAPPERS));
        for invalid in [
            format!("{BASELINE},{WRAPPERS},{WAITLIST}"),
            format!("{BASELINE},{WRAPPERS},{AGE_REQUESTS}"),
            format!("{ledger},{AGE_REQUESTS}"),
        ] {
            assert!(!ready(&invalid, AGE_REQUESTS));
        }
    }

    #[test]
    fn login_review_upgrade_keeps_only_the_previous_binary_ready() {
        let previous = format!("{BASELINE},{WRAPPERS},{WAITLIST},{AGE_REQUESTS}");
        let upgraded = format!("{previous},{LOGIN_REVIEW}");
        assert!(ready(&previous, AGE_REQUESTS));
        assert!(ready(&upgraded, AGE_REQUESTS));
        assert!(ready(&upgraded, LOGIN_REVIEW));
        assert!(!ready(&previous, LOGIN_REVIEW));
        assert!(!ready(&upgraded, WAITLIST));
        for invalid in [
            format!("{BASELINE},{WRAPPERS},{WAITLIST},{LOGIN_REVIEW}"),
            format!("{upgraded},{LOGIN_REVIEW}"),
            format!("{previous},0005_unknown.sql"),
            format!("{upgraded},0006_unknown.sql"),
        ] {
            assert!(!ready(&invalid, AGE_REQUESTS));
            assert!(!ready(&invalid, LOGIN_REVIEW));
        }
    }
}
