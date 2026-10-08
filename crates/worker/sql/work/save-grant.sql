INSERT INTO work_grant(grant_id,request_digest,task_revision,expires_at,body)
SELECT json_extract(?1,'$.data.id'),w.digest,t.revision,w.expires_at,?1
FROM work_live_request w JOIN work_task_repository t ON t.repository_id=json_extract(w.body,'$.data.input.task_repository')
WHERE w.digest=json_extract(?1,'$.data.request') AND t.revision=json_extract(?1,'$.data.task_revision')
 AND w.expires_at=json_extract(?1,'$.data.expires_at')
 AND (?3 IS NULL OR EXISTS(SELECT 1 FROM work_request_disclosure b JOIN work_disclosure_source_current d ON d.digest=b.disclosure_digest
  WHERE b.request_digest=w.digest AND b.disclosure_digest=?3))
 AND EXISTS(SELECT 1 FROM sso_context sx JOIN sso_session ss ON ss.sso_id=sx.sso_id
  JOIN credential c ON c.credential_id=ss.credential_id AND c.account_id=ss.account_id AND c.active=1
  WHERE sx.secret_hash=?2 AND ss.account_id=w.owner_id AND ss.epoch=w.owner_epoch AND ss.revoked=0 AND ss.expires_at>unixepoch())
