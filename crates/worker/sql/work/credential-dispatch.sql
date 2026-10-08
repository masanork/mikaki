UPDATE work_credential_attempt
SET state='dispatched',revision=revision+1,dispatched=1
WHERE attempt_id=?1
AND revision=?2
AND state='reserved'
AND EXISTS(SELECT 1
FROM work_credential_key
WHERE version=?3
AND fingerprint=?4
AND state='active')
