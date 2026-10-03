FROM token_issue ti
JOIN authorization_code ac ON ac.code_hash=ti.code_hash AND ac.consumed_by=ti.operation_id
JOIN code_context cc ON cc.code_hash=ac.code_hash
JOIN valid_client_session v ON v.client_id=ac.client_id AND v.sid=ac.sid
JOIN vault_claim_release r ON r.account_id=v.account_id AND r.client_id=ac.client_id AND r.claim='name'
JOIN vault_claim_release_policy rp ON rp.id=1
JOIN vault_record_share_policy sp ON sp.id=1
JOIN vault_record_grant g ON g.account_id=v.account_id AND g.vault_id=r.source_vault_id
 AND g.collection_id=r.source_collection_id AND g.record_id=r.source_record_id
 AND g.recipient_service='userinfo' AND g.purpose='oidc.userinfo.name'
JOIN vault_owner_record_head h ON h.account_id=g.account_id AND h.vault_id=g.vault_id
 AND h.collection_id=g.collection_id AND h.record_id=g.record_id
JOIN vault_owner_key_head root ON root.account_id=g.account_id AND root.vault_id=g.vault_id
JOIN vault_record_recipient_envelope e ON e.envelope_id=g.envelope_id
JOIN vault_recipient_key k ON k.key_id=e.recipient_key_id
JOIN client c ON c.client_id=ac.client_id
JOIN app_connection a ON a.account_id=v.account_id AND a.client_id=ac.client_id
WHERE ti.access_hash=?1 AND ti.revoked=0 AND ti.access_expires_at>unixepoch()
AND cc.scope IN ('openid profile','profile openid')
AND r.source_storage_version=2 AND rp.enabled=1 AND sp.enabled=1 AND sp.revision=e.policy_revision
AND r.status='active' AND r.expires_at>unixepoch() AND g.status='active' AND g.expires_at>unixepoch()
AND r.attribute_revision=g.record_revision AND r.system_grant_version=g.version
AND r.source_origin=g.origin AND r.source_kind=g.kind AND r.source_ciphertext_sha256=g.ciphertext_sha256
AND r.source_key_generation=g.key_generation AND r.source_owner_key_revision=g.owner_key_revision
AND r.client_revision=c.revision AND ac.client_revision=c.revision
AND r.connection_grant_version=a.grant_version AND c.active=1 AND c.auth_method='private_key_jwt' AND a.active=1
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
