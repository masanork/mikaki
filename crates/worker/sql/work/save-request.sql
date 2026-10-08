INSERT INTO work_request(digest,request_id,owner_id,revision,owner_epoch,policy_generation,policy_projection,expires_at,body)
SELECT json_extract(?1,'$.data.digest'),json_extract(?1,'$.data.input.request_id'),json_extract(?1,'$.data.owner'),
 json_extract(?1,'$.data.input.revision'),json_extract(?1,'$.data.owner_epoch'),json_extract(?1,'$.data.policy_revision'),?2,
 json_extract(?1,'$.data.input.deadline'),?1
WHERE json_extract(?1,'$.data.input.deadline')>unixepoch() AND json_extract(?1,'$.data.input.deadline')<=unixepoch()+3600
 AND EXISTS(SELECT 1 FROM runtime_policy_active WHERE id=1 AND generation=json_extract(?1,'$.data.policy_revision') AND projection_revision=?2)
 AND EXISTS(SELECT 1 FROM sso_context sx JOIN sso_session ss ON ss.sso_id=sx.sso_id
  JOIN credential c ON c.credential_id=ss.credential_id AND c.account_id=ss.account_id AND c.active=1
  JOIN account_security a ON a.account_id=ss.account_id AND a.active=1 AND a.epoch=ss.epoch
  WHERE sx.secret_hash=?3 AND ss.account_id=json_extract(?1,'$.data.owner') AND ss.epoch=json_extract(?1,'$.data.owner_epoch')
   AND ss.revoked=0 AND ss.expires_at>unixepoch())
 AND (NOT EXISTS(SELECT 1 FROM work_request_head WHERE owner_id=json_extract(?1,'$.data.owner') AND request_id=json_extract(?1,'$.data.input.request_id'))
  AND json_extract(?1,'$.data.input.revision')=1
  OR EXISTS(SELECT 1 FROM work_request_head WHERE owner_id=json_extract(?1,'$.data.owner') AND request_id=json_extract(?1,'$.data.input.request_id')
   AND revision=json_extract(?1,'$.data.input.revision')-1))
