INSERT INTO work_candidate(digest,request_digest,owner_id,grant_id,run_id,body)
SELECT json_extract(?1,'$.data.digest'),r.request_digest,w.owner_id,r.grant_id,r.run_id,?1
FROM work_live_run r JOIN work_live_grant g ON g.grant_id=r.grant_id JOIN work_request w ON w.digest=r.request_digest
WHERE r.run_id=json_extract(?1,'$.data.producer.run') AND g.grant_id=json_extract(?1,'$.data.producer.grant')
 AND r.revision=json_extract(?1,'$.data.producer.run_revision') AND g.revision=json_extract(?1,'$.data.producer.grant_revision')
 AND w.digest=json_extract(?1,'$.data.request') AND w.owner_id=json_extract(?1,'$.data.owner')
 AND w.owner_epoch=json_extract(?1,'$.data.provenance.owner_epoch') AND w.policy_generation=json_extract(?1,'$.data.provenance.policy_revision')
 AND w.revision=json_extract(?1,'$.data.provenance.request_revision')
 AND g.task_revision=json_extract(?1,'$.data.provenance.task_revision')
 AND json_extract(r.body,'$.data.proof_key')=json_extract(?1,'$.data.provenance.proof_key')
 AND json_extract(?1,'$.data.provenance.authentication_expires')>unixepoch()
 AND json_extract(?1,'$.data.provenance.expires_at')>unixepoch()
 AND json_extract(?1,'$.data.provenance.disclosure')=json_extract(w.body,'$.data.input.disclosure_digest')
