INSERT INTO work_request_disclosure(request_digest,disclosure_digest,owner_id)
SELECT ?1,?2,?3 WHERE EXISTS(SELECT 1 FROM sso_context sx JOIN sso_session ss ON ss.sso_id=sx.sso_id
 JOIN credential c ON c.credential_id=ss.credential_id AND c.account_id=ss.account_id AND c.active=1
 JOIN account_security a ON a.account_id=ss.account_id AND a.active=1 AND a.epoch=ss.epoch
 WHERE sx.secret_hash=?4 AND ss.account_id=?3 AND ss.revoked=0 AND ss.expires_at>unixepoch())
