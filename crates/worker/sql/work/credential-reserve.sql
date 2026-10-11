INSERT INTO work_credential_attempt(attempt_id,digest,preparation_id,owner_id,role,purpose,state,revision,reserved_bytes,dispatched,body) SELECT ?1,?2,?3,?4,?5,?6,'reserved',1,8192,0,?7
WHERE EXISTS(SELECT 1
FROM work_credential_key
WHERE version=?8
AND fingerprint=?9
AND state='active')
