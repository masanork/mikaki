SELECT g.*
FROM vault_record_grant g
JOIN vault_owner_record_head h ON h.account_id=g.account_id AND h.vault_id=g.vault_id
 AND h.collection_id=g.collection_id AND h.record_id=g.record_id
JOIN vault_owner_key_head root ON root.account_id=g.account_id AND root.vault_id=g.vault_id
JOIN account_security a ON a.account_id=g.account_id
JOIN vault_record_recipient_envelope e ON e.envelope_id=g.envelope_id
JOIN vault_recipient_key k ON k.key_id=e.recipient_key_id
JOIN vault_record_share_policy p ON p.id=1
WHERE g.account_id=?1 AND g.recipient_service='userinfo' AND g.purpose='oidc.userinfo.name'
 AND g.collection_id='personal' AND g.record_id='name' AND g.kind='name'
 AND g.status='active' AND g.expires_at>unixepoch() AND a.active=1
 AND h.deleted=0 AND h.format_version=2 AND h.kind=g.kind AND h.revision=g.record_revision
 AND h.ciphertext_sha256=g.ciphertext_sha256 AND h.key_generation=g.key_generation
 AND root.origin=g.origin AND root.key_generation=g.key_generation AND root.revision=g.owner_key_revision
 AND root.format_version=2 AND root.suite='PRF-HKDF-SHA256-AES256GCM-v2'
 AND e.account_id=g.account_id AND e.origin=g.origin AND e.vault_id=g.vault_id
 AND e.collection_id=g.collection_id AND e.record_id=g.record_id AND e.kind=g.kind
 AND e.record_revision=g.record_revision AND e.ciphertext_sha256=g.ciphertext_sha256
 AND e.key_generation=g.key_generation AND e.owner_key_revision=g.owner_key_revision
 AND e.recipient_service='userinfo' AND e.purpose='oidc.userinfo.name'
 AND e.suite='ML-KEM-768-HKDF-SHA256-AES-256-GCM-draft04-record-v2'
 AND k.service_id='userinfo' AND k.algorithm='ML-KEM-768' AND k.state='active'
 AND k.generation=e.recipient_generation AND k.revision=e.directory_revision
 AND p.enabled=1 AND p.revision=e.policy_revision
