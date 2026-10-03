-- The same predicate gates preflight and transactional consumption. A v1 source
-- or target is deliberately not an alternate branch of this v2 authority.
SELECT 1 AS valid
FROM agent_attribute_proposal p
JOIN agent_attribute_commit ac ON ac.proposal_id=p.proposal_id
JOIN agent_grant g ON g.grant_id=p.grant_id AND g.account_id=?4 AND g.storage_version=2
JOIN agent_attribute_capability cap ON cap.grant_id=g.grant_id AND cap.storage_version=2
JOIN agent_recipient_key rk ON rk.key_id=g.recipient_key_id AND rk.state='active'
JOIN account_security a ON a.account_id=g.account_id AND a.active=1 AND a.epoch=g.owner_epoch
JOIN credential c ON c.credential_id=g.credential_id AND c.account_id=g.account_id AND c.active=1
WHERE (p.proposal_id=?1 AND p.request_hash=?2 AND p.storage_version=2
AND p.attribute_id='owner_note' AND p.base_revision=?3 AND p.state='approved' AND p.expires_at>unixepoch())
AND (ac.storage_version=2 AND ac.account_id=?4 AND ac.operation_id=?5
AND ac.candidate_sha256=?6 AND ac.origin=?7 AND ac.candidate=?13 AND ac.result_revision IS NULL)
AND (p.target_origin=?7 AND p.target_vault_id=?10 AND p.target_collection_id='personal'
AND p.target_record_id='owner_note' AND p.target_kind='owner_note'
AND p.target_key_generation=?11 AND p.target_owner_key_revision=?12)
AND (cap.attribute_id=p.attribute_id AND cap.base_revision=p.base_revision
AND cap.grant_revision=p.grant_revision AND cap.expires_at>=p.expires_at AND cap.expires_at>unixepoch()
AND cap.expires_at<=g.expires_at
AND cap.target_origin=p.target_origin AND cap.target_vault_id=p.target_vault_id
AND cap.target_collection_id=p.target_collection_id AND cap.target_record_id=p.target_record_id
AND cap.target_kind=p.target_kind AND cap.target_ciphertext_sha256 IS p.target_ciphertext_sha256
AND cap.target_deleted=p.target_deleted AND cap.target_key_generation=p.target_key_generation
AND cap.target_owner_key_revision=p.target_owner_key_revision)
AND (g.revoked=0 AND g.revision=p.grant_revision AND g.expires_at>unixepoch()
AND g.encrypted_snapshot IS NOT NULL)
AND EXISTS(SELECT 1 FROM json_each(g.operations) WHERE value='propose')
-- Equivalent to the v2 branch of agent-worker/store.ts liveSource.
AND EXISTS(SELECT 1 FROM vault_owner_record_head h JOIN vault_owner_key_head k
 ON k.account_id=h.account_id AND k.vault_id=h.vault_id
 WHERE h.account_id=g.account_id AND h.vault_id=g.source_vault_id
 AND h.collection_id=g.source_collection_id AND h.record_id=g.source_record_id
 AND h.kind=g.source_kind AND h.revision=g.source_revision AND h.deleted=0 AND h.format_version=2
 AND h.ciphertext_sha256=g.source_ciphertext_sha256 AND h.key_generation=g.source_key_generation
 AND k.origin=g.source_origin AND k.key_generation=g.source_key_generation
 AND k.revision=g.source_owner_key_revision AND k.format_version=2
 AND k.suite='PRF-HKDF-SHA256-AES256GCM-v2')
AND ((p.base_revision=0 AND p.target_deleted=0 AND p.target_ciphertext_sha256 IS NULL
 AND NOT EXISTS(SELECT 1 FROM vault_owner_record_head h WHERE h.account_id=?4 AND h.vault_id=?10
   AND h.collection_id='personal' AND h.record_id='owner_note'))
 OR (p.base_revision>0 AND EXISTS(SELECT 1 FROM vault_owner_record_head h
   WHERE h.account_id=?4 AND h.vault_id=?10 AND h.collection_id='personal' AND h.record_id='owner_note'
   AND h.kind=p.target_kind AND h.revision=p.base_revision AND h.deleted=p.target_deleted
   AND h.ciphertext_sha256 IS p.target_ciphertext_sha256 AND h.key_generation=?11 AND h.format_version=2)))
AND EXISTS(SELECT 1 FROM sso_context sx JOIN sso_session ss ON ss.sso_id=sx.sso_id
 JOIN account_security a ON a.account_id=ss.account_id AND a.active=1 AND a.epoch=ss.epoch
 JOIN credential c ON c.credential_id=ss.credential_id AND c.account_id=ss.account_id AND c.active=1
 WHERE sx.secret_hash=?8 AND ss.account_id=?4 AND ss.credential_id=?9
 AND ss.revoked=0 AND ss.expires_at>unixepoch())
AND EXISTS(SELECT 1 FROM vault_owner_key_head h JOIN vault_owner_key_wrap w
 ON w.account_id=h.account_id AND w.key_generation=h.key_generation AND w.credential_id=?9
 WHERE h.account_id=?4 AND h.vault_id=?10 AND h.origin=?7 AND h.key_generation=?11
 AND h.revision=?12 AND h.format_version=2 AND h.suite='PRF-HKDF-SHA256-AES256GCM-v2')
