INSERT INTO vault_claim_disclosure_audit
  (account_id,client_id,claim,attribute_revision,release_version,occurred_at)
SELECT v.account_id,ac.client_id,'name',h.revision,r.version,unixepoch()
{ACTIVE_NAME_RELEASE}
AND v.account_id=?2 AND ac.client_id=?3
AND h.revision=?4 AND r.version=?5 AND h.ciphertext_sha256=?6
AND e.recipient_key_id=?7
RETURNING id
