SELECT ss.account_id,ss.epoch FROM sso_context sx
JOIN sso_session ss ON ss.sso_id=sx.sso_id
JOIN credential c ON c.credential_id=ss.credential_id AND c.account_id=ss.account_id AND c.active=1
JOIN account_security a ON a.account_id=ss.account_id AND a.epoch=ss.epoch AND a.active=1
WHERE sx.secret_hash=?1 AND ss.revoked=0 AND ss.expires_at>unixepoch()
