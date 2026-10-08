SELECT operation_id
FROM work_preparation p JOIN work_disclosure_source_current d ON d.digest=p.disclosure_digest
WHERE p.operation_id=?1
AND p.state='dispatched'
AND p.expires_at>unixepoch()
AND EXISTS(SELECT 1
FROM work_credential_policy
WHERE id=1)
AND EXISTS(SELECT 1
FROM work_preparation_policy
WHERE id=1)
AND EXISTS(SELECT 1
FROM work_resource_policy
WHERE id=1)
