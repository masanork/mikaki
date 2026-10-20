UPDATE messaging_enrollment SET consumed_proof=?3
WHERE enrollment_id=?1 AND secret_hash=?2 AND consumed_proof IS NULL AND expires_at>unixepoch()
AND EXISTS(SELECT 1 FROM messaging_live_owner a WHERE a.account_id=owner_id AND a.secret_hash=messaging_enrollment.secret_hash AND a.credential_id=messaging_enrollment.credential_id)
AND EXISTS(SELECT 1 FROM messaging_generation g JOIN messaging_device_head h
 ON h.account_id=g.account_id AND h.device_id=g.device_id AND h.generation=g.generation AND h.revision=g.revision
 WHERE g.enrollment_id=?1 AND g.status='active');
