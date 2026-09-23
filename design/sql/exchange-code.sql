-- 全文を一回のD1 batchにする。暗号検証と署名生成は先に済ませる。
-- :pkce_challengeは受信verifierからS256で計算した値。
-- 有効なassertionの受理は独立batch。code失敗でも受理を戻さない。
UPDATE authorization_code SET consumed_by=:operation_id,
  consumed_at=CAST(strftime('%s','now') AS INTEGER)
WHERE code_hash=:code_hash AND consumed_by IS NULL
  AND client_id=:client_id AND redirect_uri=:redirect_uri
  AND pkce_challenge=:pkce_challenge
  AND expires_at > CAST(strftime('%s','now') AS INTEGER)
  AND EXISTS (SELECT 1 FROM client c WHERE c.client_id=:client_id
    AND c.active=1 AND c.revision=authorization_code.client_revision)
  AND EXISTS (SELECT 1 FROM eligible_client_session v
    WHERE v.client_id=authorization_code.client_id AND v.sid=authorization_code.sid)
  AND EXISTS (SELECT 1 FROM client_key k WHERE k.client_id=:client_id
    AND k.kid=:client_kid AND k.revision=:client_key_revision AND k.active=1)
  AND EXISTS (SELECT 1 FROM assertion_use au WHERE au.client_id=:client_id
    AND au.jti=:jti AND au.endpoint=:endpoint AND au.accepted_by=:assertion_operation_id
    AND au.retain_until > CAST(strftime('%s','now') AS INTEGER))
  AND EXISTS (SELECT 1 FROM signing_key sk WHERE sk.kid=:signing_kid
    AND sk.generation=:signing_generation AND sk.active=1);

INSERT INTO token_issue(code_hash,operation_id,access_hash,access_expires_at,signing_kid,issued_at,revoked)
SELECT ac.code_hash,:operation_id,:access_hash,
  MIN(:access_expires_at,v.expires_at),:signing_kid,ac.consumed_at,0
FROM authorization_code ac
JOIN eligible_client_session v ON v.client_id=ac.client_id AND v.sid=ac.sid
WHERE ac.code_hash=:code_hash AND ac.consumed_by=:operation_id
  AND :access_expires_at > CAST(strftime('%s','now') AS INTEGER);

-- VALUESは常に一行を評価。0件のUPDATE/INSERTを成功として確定しない。
INSERT INTO atomic_guard(operation_id,passed)
VALUES(:operation_id, CASE WHEN EXISTS (
  SELECT 1 FROM authorization_code ac JOIN token_issue ti ON ti.code_hash=ac.code_hash
  JOIN valid_client_session v ON v.client_id=ac.client_id AND v.sid=ac.sid
  WHERE ac.code_hash=:code_hash AND ac.consumed_by=:operation_id
    AND ti.operation_id=:operation_id AND ti.access_hash=:access_hash
    AND ac.expires_at > CAST(strftime('%s','now') AS INTEGER)
    AND ti.access_expires_at > CAST(strftime('%s','now') AS INTEGER)
) THEN 1 ELSE 0 END);
DELETE FROM atomic_guard WHERE operation_id=:operation_id;
