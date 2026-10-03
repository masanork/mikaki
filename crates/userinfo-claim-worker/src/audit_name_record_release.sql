INSERT INTO vault_claim_disclosure_audit
 (account_id,client_id,claim,attribute_revision,release_version,occurred_at,source_storage_version,source_json)
SELECT v.account_id,ac.client_id,'name',h.revision,r.version,unixepoch(),2,
 json_object('storage_version',2,'origin',g.origin,'owner_id',g.account_id,'vault_id',g.vault_id,
 'collection_id',g.collection_id,'record_id',g.record_id,'kind',g.kind,'revision',g.record_revision,
 'ciphertext_sha256',g.ciphertext_sha256,'key_generation',g.key_generation,'owner_key_revision',g.owner_key_revision,
 'system_grant_version',g.version,'recipient_key_id',k.key_id,'recipient_generation',k.generation)
{ACTIVE_NAME_RELEASE}
AND v.account_id=?2 AND ac.client_id=?3
AND h.revision=?4 AND r.version=?5 AND h.ciphertext_sha256=?6 AND e.recipient_key_id=?7
AND g.origin=?8 AND g.vault_id=?9 AND g.collection_id=?10 AND g.record_id=?11 AND g.kind=?12
AND g.key_generation=?13 AND g.owner_key_revision=?14 AND g.version=?15
AND k.generation=?16 AND e.envelope_id=?17
RETURNING id
