INSERT INTO authorization_code(code_hash,client_id,sid,client_revision,redirect_uri,pkce_challenge,expires_at)
SELECT ?1,c.client_id,cs.sid,c.revision,?5,?6,?7
FROM client c
JOIN client_session cs ON cs.client_id=c.client_id AND cs.sid=?3
JOIN sso_session ss ON ss.sso_id=cs.sso_id
JOIN client_redirect_uri r ON r.client_id=c.client_id AND r.redirect_uri=?5
WHERE c.client_id=?2 AND c.active=1 AND c.revision=?4 AND ss.expires_at>=?7
  AND ?7>?8
