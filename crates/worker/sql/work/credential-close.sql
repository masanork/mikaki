UPDATE work_credential_attempt
SET state='closed',revision=revision+1,envelope=NULL,confirmation=?3,receipt=?4
WHERE attempt_id=?1
AND revision=?2
AND state='revocation_pending'
