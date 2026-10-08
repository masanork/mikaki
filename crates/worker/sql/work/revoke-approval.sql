UPDATE work_code_approval SET revision=2,revoked=1 WHERE approval_id=?1 AND revoked=0
 AND EXISTS(SELECT 1 FROM sso_session ss JOIN sso_context sx ON sx.sso_id=ss.sso_id
  JOIN account_security a ON a.account_id=ss.account_id AND a.active=1 AND a.epoch=ss.epoch
  JOIN credential c ON c.credential_id=ss.credential_id AND c.account_id=ss.account_id AND c.active=1
  WHERE ss.account_id=work_code_approval.owner_id AND sx.secret_hash=?2 AND ss.revoked=0 AND ss.expires_at>unixepoch())
