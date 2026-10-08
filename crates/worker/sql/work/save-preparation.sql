INSERT INTO work_preparation(operation_id,digest,disclosure_digest,owner_id,owner_epoch,policy_generation,policy_projection,
 expires_at,reserved_bytes,task_repository,task_namespace,task_name,snapshot_namespace,snapshot_name,state,revision,body)
SELECT json_extract(?1,'$.data.plan.operation_id'),json_extract(?1,'$.data.digest'),json_extract(?1,'$.data.plan.binding.disclosure'),
 json_extract(?1,'$.data.plan.binding.owner'),json_extract(?1,'$.data.plan.binding.owner_epoch'),
 json_extract(?1,'$.data.plan.binding.policy_revision'),json_extract(?1,'$.data.plan.binding.policy_projection'),
 json_extract(?1,'$.data.plan.binding.expires_at'),json_extract(?1,'$.data.plan.binding.reserved_bytes'),
 json_extract(?1,'$.data.plan.task_repository'),json_extract(?1,'$.data.plan.task_namespace'),json_extract(?1,'$.data.plan.task_name'),
 json_extract(?1,'$.data.plan.snapshot_namespace'),json_extract(?1,'$.data.plan.snapshot_name'),'reserved',1,?1
WHERE EXISTS(SELECT 1 FROM sso_context sx JOIN sso_session ss ON ss.sso_id=sx.sso_id
 JOIN credential c ON c.credential_id=ss.credential_id AND c.account_id=ss.account_id AND c.active=1
 JOIN account_security a ON a.account_id=ss.account_id AND a.active=1 AND a.epoch=ss.epoch
 WHERE sx.secret_hash=?2 AND ss.account_id=json_extract(?1,'$.data.plan.binding.owner')
 AND ss.epoch=json_extract(?1,'$.data.plan.binding.owner_epoch') AND ss.revoked=0 AND ss.expires_at>unixepoch())
