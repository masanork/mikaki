WITH current_share AS ({CURRENT_RECORD_SHARE})
SELECT c.client_id,c.sector_identifier,c.revision AS client_revision,a.grant_version AS connection_grant_version,
 r.version AS release_version,r.status AS release_status,r.expires_at,r.source_storage_version,
 r.source_origin,r.source_vault_id,r.source_collection_id,r.source_record_id,r.source_kind,
 r.attribute_revision,r.source_ciphertext_sha256,r.source_key_generation,r.source_owner_key_revision,r.system_grant_version,
 EXISTS(SELECT 1 FROM current_share s JOIN vault_claim_release_policy p ON p.id=1
  WHERE s.account_id=r.account_id AND s.vault_id=r.source_vault_id
   AND s.collection_id=r.source_collection_id AND s.record_id=r.source_record_id
   AND r.source_storage_version=2 AND r.status='active' AND r.expires_at>unixepoch() AND p.enabled=1
   AND r.attribute_revision=s.record_revision AND r.system_grant_version=s.version
   AND r.source_origin=s.origin AND r.source_kind=s.kind AND r.source_ciphertext_sha256=s.ciphertext_sha256
   AND r.source_key_generation=s.key_generation AND r.source_owner_key_revision=s.owner_key_revision
   AND r.client_revision=c.revision AND r.connection_grant_version=a.grant_version) AS authority_current
FROM app_connection a JOIN client c ON c.client_id=a.client_id
LEFT JOIN vault_claim_release r ON r.account_id=a.account_id AND r.client_id=a.client_id AND r.claim='name'
WHERE a.account_id=?1 AND a.active=1 AND c.active=1 AND c.auth_method='private_key_jwt'
ORDER BY c.client_id LIMIT 100
