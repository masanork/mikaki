INSERT INTO client_session(client_id,sid,sso_id,account_id,sub,grant_version,revoked)
SELECT c.client_id,?1,ss.sso_id,ss.account_id,ps.sub,g.grant_version,0
FROM sso_session ss
JOIN sso_context sx ON sx.sso_id=ss.sso_id
JOIN account_security a ON a.account_id=ss.account_id
JOIN credential cr ON cr.credential_id=ss.credential_id AND cr.account_id=ss.account_id
JOIN client c ON c.client_id=?4 AND c.active=1 AND c.revision=?5
JOIN client_redirect_uri r ON r.client_id=c.client_id AND r.redirect_uri=?6
JOIN app_connection g ON g.account_id=ss.account_id AND g.client_id=c.client_id AND g.active=1
JOIN pairwise_subject ps ON ps.account_id=ss.account_id AND ps.sector_identifier=c.sector_identifier
WHERE ss.sso_id=?2 AND sx.secret_hash=?3 AND ss.revoked=0 AND ss.expires_at>?7
  AND a.active=1 AND a.epoch=ss.epoch AND cr.active=1
