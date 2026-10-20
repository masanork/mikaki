INSERT INTO messaging_generation(account_id,device_id,generation,revision,public_key,status,storage_id,key_id,fingerprint,scope_hash,enrollment_id)
SELECT account_id,device_id,generation,expected_revision+1,public_key,'active',storage_id,key_id,?3,?4,enrollment_id
FROM messaging_enrollment_ready WHERE enrollment_id=?1 AND secret_hash=?2
AND ?5<=unixepoch() AND ?6>unixepoch()
ON CONFLICT DO NOTHING;
