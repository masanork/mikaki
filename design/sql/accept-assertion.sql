-- 呼出し前に署名・iss/sub/aud/alg/iat/expを検証済みであること。
-- retain_untilは検証したexp+clock_skew。入力JWTから無検証で設定しない。
INSERT INTO assertion_use(client_id,jti,endpoint,accepted_by,retain_until)
SELECT :client_id,:jti,:endpoint,:operation_id,:retain_until
FROM client c JOIN client_key k ON k.client_id=c.client_id
WHERE c.client_id=:client_id AND c.active=1
  AND k.kid=:client_kid AND k.revision=:client_key_revision AND k.active=1
  AND :retain_until > CAST(strftime('%s','now') AS INTEGER);
INSERT INTO atomic_guard(operation_id,passed)
VALUES(:operation_id, CASE WHEN EXISTS (
  SELECT 1 FROM assertion_use WHERE accepted_by=:operation_id
    AND client_id=:client_id AND jti=:jti AND endpoint=:endpoint
) THEN 1 ELSE 0 END);
DELETE FROM atomic_guard WHERE operation_id=:operation_id;
