-- Historical approval acknowledgment requires a live same-owner session only;
-- it cannot create authority or reapply ciphertext. Use database clock expiry.
SELECT 1 AS valid FROM sso_context sx JOIN sso_session ss ON ss.sso_id=sx.sso_id
JOIN account_security a ON a.account_id=ss.account_id AND a.active=1 AND a.epoch=ss.epoch
JOIN credential c ON c.credential_id=ss.credential_id AND c.account_id=ss.account_id AND c.active=1
WHERE sx.secret_hash=?1 AND ss.account_id=?2 AND ss.credential_id=?3
AND ss.revoked=0 AND ss.expires_at>unixepoch()
