INSERT INTO messaging_commit_guard(operation_id,valid)
VALUES(?1,CASE WHEN EXISTS(SELECT 1 FROM messaging_enrollment e
 JOIN messaging_live_owner a ON a.account_id=e.owner_id AND a.secret_hash=e.secret_hash AND a.credential_id=e.credential_id
 JOIN messaging_generation g ON g.enrollment_id=e.enrollment_id
 JOIN messaging_device_head h ON h.account_id=g.account_id AND h.device_id=g.device_id AND h.generation=g.generation AND h.revision=g.revision
 WHERE e.enrollment_id=?1 AND e.secret_hash=?2 AND e.consumed_proof=?3 AND g.status='active'
 AND ?4<=unixepoch() AND ?5>unixepoch()) THEN 1 ELSE 0 END)
ON CONFLICT(operation_id) DO UPDATE SET valid=excluded.valid;
