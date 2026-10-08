INSERT INTO work_request_head(owner_id,request_id,revision,digest)
SELECT owner_id,request_id,revision,digest FROM work_request WHERE digest=?1
ON CONFLICT(owner_id,request_id) DO UPDATE SET revision=excluded.revision,digest=excluded.digest
WHERE work_request_head.revision=excluded.revision-1
