-- All authority/limits are rechecked after the R2 upload, inside the D1 batch.
-- ?18 is a database-observed admission time, never a client-supplied deadline.
INSERT INTO vault_owner_record_head(account_id,vault_id,collection_id,record_id,kind,revision,key_generation,format_version,object_key,ciphertext_sha256,key_envelope,deleted,updated_at)
SELECT ?1,?2,?3,?4,?5,?6,?7,2,?8,?9,?10,?11,unixepoch()
WHERE ?6=CASE WHEN ?12=-1 THEN 1 ELSE ?12+1 END
AND (?11=0 OR ?12>0)
AND (?8 IS NULL OR EXISTS(SELECT 1 FROM vault_gc_candidate WHERE object_key=?8 AND state='pending'))
AND unixepoch() BETWEEN ?18 AND ?18+300
AND NOT EXISTS(SELECT 1 FROM vault_owner_record_mutation WHERE account_id=?1 AND operation_id=?19)
AND ((?12=-1 AND NOT EXISTS(SELECT 1 FROM vault_owner_record_head WHERE account_id=?1 AND vault_id=?2 AND collection_id=?3 AND record_id=?4))
  OR (?12>0 AND EXISTS(SELECT 1 FROM vault_owner_record_head WHERE account_id=?1 AND vault_id=?2 AND collection_id=?3 AND record_id=?4 AND revision=?12 AND kind=?5 AND key_generation=?7 AND (deleted=0 OR ?11=0))))
AND EXISTS (
  SELECT 1 FROM sso_context sx JOIN sso_session ss ON ss.sso_id=sx.sso_id
  JOIN account_security a ON a.account_id=ss.account_id
  JOIN credential c ON c.credential_id=ss.credential_id AND c.account_id=ss.account_id
  WHERE sx.secret_hash=?13 AND ss.account_id=?1 AND ss.credential_id=?14
    AND ss.revoked=0 AND ss.expires_at>unixepoch() AND a.active=1 AND a.epoch=ss.epoch AND c.active=1
)
AND EXISTS (
  SELECT 1 FROM vault_owner_key_head h JOIN vault_owner_key_wrap w ON w.account_id=h.account_id AND w.key_generation=h.key_generation AND w.credential_id=?14
  WHERE h.account_id=?1 AND h.vault_id=?2 AND h.key_generation=?7 AND h.revision=?15 AND h.origin=?16 AND h.format_version=2 AND h.suite=?17
)
AND (SELECT COUNT(*) FROM vault_owner_record_mutation WHERE account_id=?1 AND created_at>unixepoch()-60)<20
AND (?12>0 OR (SELECT COUNT(*) FROM vault_owner_record_head WHERE account_id=?1)<256)
ON CONFLICT(account_id,vault_id,collection_id,record_id) DO UPDATE SET
  revision=excluded.revision,object_key=excluded.object_key,ciphertext_sha256=excluded.ciphertext_sha256,
  key_envelope=excluded.key_envelope,deleted=excluded.deleted,updated_at=excluded.updated_at
WHERE vault_owner_record_head.revision=?12 AND vault_owner_record_head.kind=?5
  AND vault_owner_record_head.key_generation=?7 AND (vault_owner_record_head.deleted=0 OR ?11=0)
