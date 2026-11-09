UPDATE authorization_code SET consumed_by=?19, consumed_at=CAST(strftime('%s','now') AS INTEGER)
WHERE code_hash=?1
  AND client_id=?2
  AND client_revision=?5
  AND (CASE WHEN redirect_uri_actual='' THEN redirect_uri ELSE redirect_uri_actual END)=?3
  AND pkce_challenge=?4
  AND consumed_by IS NULL
  AND (?31=0 OR EXISTS(SELECT 1 FROM authorization_email_scope es
WHERE es.code_hash=authorization_code.code_hash))
  AND (?30 IS NULL OR EXISTS(SELECT 1 FROM client_session cs JOIN eligible_verified_email_release er ON er.account_id=cs.account_id
  AND er.client_id=cs.client_id
WHERE cs.sid=authorization_code.sid
  AND cs.client_id=?2
  AND er.email=?30
  AND er.email_revision=?32
  AND er.release_revision=?33))
  AND (?28=0 OR EXISTS (SELECT 1 FROM par_request p
WHERE p.consumed_by=authorization_code.code_hash
  AND p.client_id=?2))
  AND (dpop_jkt IS NULL OR dpop_jkt=?25)
  AND expires_at > CAST(strftime('%s','now') AS INTEGER)
  AND EXISTS (SELECT 1 FROM client c
WHERE c.client_id=?2
  AND c.active=1
  AND c.revision=?5
  AND c.auth_method=?8)
  AND EXISTS (SELECT 1 FROM eligible_client_session v
WHERE v.client_id=?2
  AND v.sid=?14
  AND v.sub=?15
  AND v.expires_at=?18)
  AND EXISTS (SELECT 1 FROM client_session cs JOIN sso_context sx ON sx.sso_id=cs.sso_id JOIN code_context cc ON cc.code_hash=?1
WHERE cs.client_id=?2
  AND cs.sid=?14
  AND sx.auth_time=?17
  AND cc.nonce IS ?16
  AND (cc.scope=?29 OR (?29='openid profile'
  AND cc.scope='profile openid')))
  AND EXISTS (SELECT 1 FROM client_auth_use au
WHERE au.client_id=?2
  AND au.method=?8
  AND au.credential_id=?6
  AND au.client_revision=?5
  AND au.credential_revision=?7
  AND au.endpoint=?9
  AND au.accepted_by=?10
  AND au.retain_until=?11
  AND au.retain_until > CAST(strftime('%s','now') AS INTEGER))
  AND ((?8='private_key_jwt'
  AND EXISTS (SELECT 1 FROM client_key ck
WHERE ck.client_id=?2
  AND ck.kid=?6
  AND ck.revision=?7
  AND ck.active=1)) OR (?8 IN ('client_secret_basic','client_secret_post')
  AND EXISTS (SELECT 1 FROM client_secret s
WHERE s.client_id=?2
  AND s.revision=?7
  AND s.active=1)) OR (?8='none'
  AND ?6=''
  AND CAST(?7 AS INTEGER)=0
  AND EXISTS (SELECT 1 FROM client nc
WHERE nc.client_id=?2
  AND nc.client_type='native'
  AND nc.auth_method='none')))
  AND EXISTS (SELECT 1 FROM signing_key sk
WHERE sk.kid=?12
  AND sk.generation=?13
  AND sk.active=1
  AND sk.public_jwk=?23
  AND sk.algorithm=?24)
  AND (?25 IS NULL OR EXISTS (SELECT 1 FROM dpop_proof_use p
WHERE p.jkt=?25
  AND p.jti_hash=?26
  AND p.accepted_by=?27
  AND p.retain_until>=CAST(strftime('%s','now') AS INTEGER)))
  AND CAST(?20 AS INTEGER) > CAST(strftime('%s','now') AS INTEGER)
  AND CAST(?20 AS INTEGER) <= CAST(?18 AS INTEGER)
  AND CAST(?21 AS INTEGER) > CAST(strftime('%s','now') AS INTEGER)
  AND CAST(?21 AS INTEGER) <= CAST(?18 AS INTEGER)
