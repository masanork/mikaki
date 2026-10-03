SELECT h.vault_id,h.origin,h.key_generation,h.revision,h.format_version,h.suite,
       unixepoch() AS observed_at
FROM vault_owner_key_head h
JOIN vault_owner_key_wrap w ON w.account_id=h.account_id AND w.key_generation=h.key_generation AND w.credential_id=?3
WHERE h.account_id=?1
AND EXISTS (
  SELECT 1 FROM sso_context sx JOIN sso_session ss ON ss.sso_id=sx.sso_id
  JOIN account_security a ON a.account_id=ss.account_id
  JOIN credential c ON c.credential_id=ss.credential_id AND c.account_id=ss.account_id
  WHERE sx.secret_hash=?2 AND ss.account_id=?1 AND ss.credential_id=?3
    AND ss.revoked=0 AND ss.expires_at>unixepoch() AND a.active=1 AND a.epoch=ss.epoch AND c.active=1
)
