INSERT INTO messaging_device_head(account_id,device_id,generation,revision)
SELECT g.account_id,g.device_id,g.generation,g.revision FROM messaging_generation g
JOIN messaging_enrollment e ON e.enrollment_id=g.enrollment_id
JOIN messaging_live_owner a ON a.account_id=e.owner_id AND a.secret_hash=e.secret_hash AND a.credential_id=e.credential_id
WHERE e.enrollment_id=?1 AND e.secret_hash=?2 AND e.consumed_proof IS NULL AND e.expires_at>unixepoch()
ON CONFLICT(account_id,device_id) DO UPDATE SET generation=excluded.generation,revision=excluded.revision
WHERE messaging_device_head.revision=excluded.revision-1 AND messaging_device_head.generation=excluded.generation-1;
