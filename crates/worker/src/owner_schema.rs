//! Narrow migration bridge for the additive owner-key wrapper receipt table.
//! The deployment gate still compares the complete schema before promotion.
const BASELINE: &str = "0001_owner_vault_initial.sql";
const WRAPPERS: &str = "0002_owner_key_wrap_operations.sql";

pub fn ready(ledger: &str, compiled_latest: &str) -> bool {
    match compiled_latest {
        BASELINE => ledger == BASELINE || ledger == format!("{BASELINE},{WRAPPERS}"),
        WRAPPERS => ledger == format!("{BASELINE},{WRAPPERS}"),
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
}
