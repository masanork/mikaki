WITH current_share AS ({CURRENT_RECORD_SHARE})
SELECT 2 AS storage_version,g.account_id AS owner_id,g.vault_id,g.origin,g.collection_id,g.record_id,g.kind,
 g.record_revision,g.ciphertext_sha256,g.key_generation,g.owner_key_revision,g.version,g.status,g.expires_at,
 e.recipient_key_id,e.recipient_generation,e.directory_revision,e.policy_revision,
 EXISTS(SELECT 1 FROM current_share s WHERE s.envelope_id=g.envelope_id AND s.version=g.version) AS authority_current
FROM vault_record_grant g
JOIN vault_owner_key_head root ON root.account_id=g.account_id AND root.vault_id=g.vault_id
JOIN vault_record_recipient_envelope e ON e.envelope_id=g.envelope_id AND e.account_id=g.account_id
WHERE g.account_id=?1 AND g.collection_id='personal' AND g.record_id='name'
 AND g.recipient_service='userinfo' AND g.purpose='oidc.userinfo.name'
