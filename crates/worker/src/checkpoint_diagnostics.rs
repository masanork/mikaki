//! Closed diagnostic vocabulary. Never emit provider messages, SQL or bound data.

pub(crate) fn storage_category(message: &str) -> &'static str {
    // Specific causes precede wrappers. These labels are diagnostic only: they
    // must never be used to infer that an unknown write aborted.
    for (needle, category) in [
        ("work_checkpoint_guard_failed", "authority_guard"),
        ("work_guard_passed", "transition_guard"),
        ("work_resource_exhausted", "resource_guard"),
        ("work_source_guard_failed", "source_guard"),
        ("work_preparation_guard_failed", "preparation_guard"),
        ("FOREIGN KEY constraint failed", "foreign_key_constraint"),
        ("UNIQUE constraint failed", "unique_constraint"),
        ("CHECK constraint failed", "check_constraint"),
        ("SQLITE_CONSTRAINT", "sqlite_constraint"),
        ("SQLITE_BUSY", "sqlite_busy"),
        ("SQLITE_LOCKED", "sqlite_locked"),
        ("SQLITE_FULL", "sqlite_full"),
        ("SQLITE_IOERR", "sqlite_io"),
        ("SQLITE_CORRUPT", "sqlite_corrupt"),
        ("SQLITE_TOOBIG", "sqlite_too_big"),
        ("SQLITE_MISMATCH", "sqlite_type"),
        ("SQLITE_ERROR", "sqlite_error"),
        ("storage operation exceeded timeout", "storage_timeout"),
        ("is overloaded", "overloaded"),
        ("exceeded its memory limit", "memory_limit"),
        ("exceeded its CPU time limit", "cpu_limit"),
        ("Exceeded maximum DB size", "database_size_limit"),
        ("maximum account storage limit", "account_storage_limit"),
        ("daily row read limit", "daily_read_limit"),
        ("daily row write limit", "daily_write_limit"),
        ("Network connection lost", "network_lost"),
        ("Replica disconnected from primary", "replica_disconnected"),
        ("transient issue on remote node", "remote_node_unavailable"),
        (
            "reset because its code was updated",
            "database_update_reset",
        ),
        ("starting up D1 DB storage", "database_startup_reset"),
        (
            "D1 DB storage caused object to be reset",
            "database_storage_reset",
        ),
        ("client disconnected", "client_disconnected"),
        ("D1_TYPE_ERROR", "d1_type"),
        ("D1_COLUMN_NOTFOUND", "d1_column"),
        ("D1_EXEC_ERROR", "d1_exec"),
        ("D1_ERROR", "d1_unknown"),
    ] {
        if message.contains(needle) {
            return category;
        }
    }
    "unknown"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostic_labels_keep_provider_and_bound_data_out_of_logs() {
        let private = "PRIVATE_COOKIE_AND_SQL_BINDING";
        for (message, expected) in [
            (
                format!("D1_ERROR: UNIQUE constraint failed: {private}: SQLITE_CONSTRAINT"),
                "unique_constraint",
            ),
            (
                format!("D1_ERROR: Network connection lost. {private}"),
                "network_lost",
            ),
            (
                format!(
                    "D1_ERROR: D1 DB storage operation exceeded timeout which caused object to be reset. {private}"
                ),
                "storage_timeout",
            ),
            (
                format!("D1_ERROR: D1 DB reset because its code was updated. {private}"),
                "database_update_reset",
            ),
            (format!("D1_ERROR: {private}"), "d1_unknown"),
            (private.to_owned(), "unknown"),
        ] {
            let label = storage_category(&message);
            assert_eq!(label, expected);
            assert!(!label.contains(private));
        }
    }
}
