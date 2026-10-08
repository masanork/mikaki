UPDATE work_code_operation SET state='cancelled',revision=revision+1
WHERE operation_id=?1 AND revision=?2 AND body=?3 AND state='prepared'
 AND EXISTS(SELECT 1 FROM sso_context sx JOIN sso_session ss ON ss.sso_id=sx.sso_id
 JOIN credential c ON c.credential_id=ss.credential_id AND c.account_id=ss.account_id AND c.active=1
 JOIN account_security a ON a.account_id=ss.account_id AND a.epoch=ss.epoch AND a.active=1
 WHERE sx.secret_hash=?4 AND ss.account_id=work_code_operation.owner_id AND ss.revoked=0 AND ss.expires_at>unixepoch())
