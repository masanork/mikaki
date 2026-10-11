UPDATE work_credential_attempt
SET state=?3,revision=revision+1,observation=?4,key_version=?5,envelope=?6,nonce=json_extract(?6,'$.data.nonce')
WHERE attempt_id=?1
AND revision=?2
AND observation IS NULL
AND state IN('dispatched','revocation_pending')
