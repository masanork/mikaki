INSERT INTO messaging_enrollment(enrollment_id,owner_id,secret_hash,credential_id,request_hash,device_id,generation,expected_revision,public_key,storage_id,key_id,nonce,expires_at)
SELECT ?1,a.account_id,a.secret_hash,a.credential_id,?3,?4,COALESCE(h.generation,0)+1,?5,?6,?7,?8,?9,unixepoch()+60
FROM messaging_live_owner a JOIN messaging_account m ON m.owner_id=a.account_id
LEFT JOIN messaging_device_head h ON h.account_id=m.account_id AND h.device_id=?4
WHERE a.secret_hash=?2 AND COALESCE(h.revision,0)=?5 AND COALESCE(h.generation,0)<9007199254740991 AND COALESCE(h.revision,0)<9007199254740991
AND NOT EXISTS(SELECT 1 FROM messaging_generation g WHERE g.account_id=m.account_id AND g.public_key=?6)
AND (h.device_id IS NOT NULL OR (SELECT count(*) FROM messaging_device_head d WHERE d.account_id=m.account_id)<8)
AND (SELECT count(*) FROM messaging_generation g WHERE g.account_id=m.account_id)<64
AND (SELECT count(*) FROM messaging_enrollment e WHERE e.owner_id=a.account_id)<128
AND (SELECT count(*) FROM messaging_enrollment e WHERE e.owner_id=a.account_id AND e.consumed_proof IS NULL AND e.expires_at>unixepoch())<4
ON CONFLICT(enrollment_id) DO NOTHING;
