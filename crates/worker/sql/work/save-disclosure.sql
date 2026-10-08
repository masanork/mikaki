INSERT INTO work_disclosure(digest,owner_id,owner_epoch,policy_generation,policy_projection,expires_at,selected_bytes,body)
SELECT json_extract(?1,'$.data.digest'),json_extract(?1,'$.data.data.owner'),json_extract(?1,'$.data.data.owner_epoch'),
 json_extract(?1,'$.data.data.policy_revision'),?2,json_extract(?1,'$.data.data.expires_at'),json_extract(?1,'$.data.data.selected_bytes'),?1
WHERE json_extract(?1,'$.data.data.expires_at')>unixepoch() AND json_extract(?1,'$.data.data.expires_at')<=unixepoch()+3600
 AND EXISTS(SELECT 1 FROM runtime_policy_active WHERE id=1 AND generation=json_extract(?1,'$.data.data.policy_revision') AND projection_revision=?2)
 AND EXISTS(SELECT 1 FROM sso_context sx JOIN sso_session ss ON ss.sso_id=sx.sso_id
  JOIN credential c ON c.credential_id=ss.credential_id AND c.account_id=ss.account_id AND c.active=1
  JOIN account_security a ON a.account_id=ss.account_id AND a.active=1 AND a.epoch=ss.epoch
  WHERE sx.secret_hash=?3 AND ss.account_id=json_extract(?1,'$.data.data.owner') AND ss.epoch=json_extract(?1,'$.data.data.owner_epoch')
   AND ss.revoked=0 AND ss.expires_at>unixepoch())
