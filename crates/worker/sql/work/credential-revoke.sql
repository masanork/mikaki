UPDATE work_credential_attempt
SET state='revocation_pending',revision=revision+1
WHERE attempt_id=?1
AND revision=?2
AND state IN('reserved','dispatched','captured')
