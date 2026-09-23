INSERT INTO atomic_guard(operation_id,passed)
VALUES(?1,CASE WHEN EXISTS (
  SELECT 1 FROM authorization_code ac
  JOIN code_context cc ON cc.code_hash=ac.code_hash
  JOIN eligible_client_session v ON v.client_id=ac.client_id AND v.sid=ac.sid
  WHERE ac.code_hash=?1 AND ac.client_id=?2 AND ac.redirect_uri=?3
    AND ac.expires_at>?5 AND ac.consumed_by IS NULL AND cc.nonce=?4
) THEN 1 ELSE 0 END)
