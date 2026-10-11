INSERT INTO work_code_approval(approval_id,candidate_digest,owner_id,owner_epoch,policy_generation,policy_projection,
 grant_id,grant_revision,run_id,run_revision,target_revision,expires_at,body)
SELECT json_extract(?1,'$.data.id'),c.digest,c.owner_id,a.epoch,p.generation,p.projection_revision,
 g.grant_id,g.revision,r.run_id,r.revision,t.revision,json_extract(?1,'$.data.expires_at'),?1
FROM work_candidate c JOIN work_grant g ON g.grant_id=c.grant_id JOIN work_run r ON r.run_id=c.run_id AND r.grant_id=g.grant_id
 JOIN account_security a ON a.account_id=c.owner_id AND a.active=1
 JOIN runtime_policy_active p ON p.id=1 AND p.projection_revision=?2
 JOIN work_code_target t ON t.repository_id=json_extract(c.body,'$.data.adoption_repository')
  AND t.reference=json_extract(c.body,'$.data.adoption_ref') AND t.owner_id=c.owner_id AND t.writable=1
  AND t.head=json_extract(c.body,'$.data.expected_head')
WHERE c.digest=json_extract(?1,'$.data.candidate') AND c.owner_id=json_extract(?1,'$.data.owner')
 AND a.epoch=json_extract(?1,'$.data.owner_epoch') AND p.generation=json_extract(?1,'$.data.policy_revision')
 AND g.grant_id=json_extract(?1,'$.data.producer.grant') AND g.revision=json_extract(?1,'$.data.producer.grant_revision')
 AND r.run_id=json_extract(?1,'$.data.producer.run') AND r.revision=json_extract(?1,'$.data.producer.run_revision')
 AND t.revision=json_extract(?1,'$.data.target_revision')
 AND json_extract(?1,'$.data.expires_at')>unixepoch() AND json_extract(?1,'$.data.expires_at')<=unixepoch()+300
 AND EXISTS(SELECT 1 FROM sso_context sx JOIN sso_session ss ON ss.sso_id=sx.sso_id
  JOIN credential cr ON cr.credential_id=ss.credential_id AND cr.account_id=ss.account_id AND cr.active=1
  WHERE sx.secret_hash=?3 AND ss.account_id=c.owner_id AND ss.epoch=a.epoch AND ss.revoked=0
   AND ss.expires_at>=json_extract(?1,'$.data.expires_at'))
