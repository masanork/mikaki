INSERT INTO vault_claim_release
 (account_id,client_id,claim,attribute_revision,system_grant_version,client_revision,connection_grant_version,
 version,status,expires_at,updated_at,source_storage_version,source_origin,source_vault_id,source_collection_id,
 source_record_id,source_kind,source_ciphertext_sha256,source_key_generation,source_owner_key_revision)
SELECT ?1,?13,'name',?7,?17,?14,?15,1,'active',
 MIN((SELECT unixepoch()+ttl_seconds FROM vault_claim_release_policy WHERE id=1),
     (SELECT expires_at FROM vault_record_grant WHERE account_id=?1 AND vault_id=?3 AND collection_id=?4
      AND record_id=?5 AND recipient_service='userinfo' AND purpose='oidc.userinfo.name')),
 unixepoch(),2,?2,?3,?4,?5,?6,?8,?9,?10
{LIVE_SOURCE}
AND EXISTS(SELECT 1 FROM vault_record_grant g WHERE g.account_id=?1 AND g.vault_id=?3
 AND g.collection_id=?4 AND g.record_id=?5 AND g.kind=?6 AND g.record_revision=?7
 AND g.ciphertext_sha256=?8 AND g.key_generation=?9 AND g.owner_key_revision=?10
 AND g.recipient_service='userinfo' AND g.purpose='oidc.userinfo.name' AND g.version=?17
 AND g.status='active' AND g.expires_at>unixepoch())
AND EXISTS(SELECT 1 FROM vault_claim_release_policy WHERE id=1 AND enabled=1 AND revision=?16)
AND EXISTS(SELECT 1 FROM client c JOIN app_connection a ON a.client_id=c.client_id
 WHERE c.client_id=?13 AND c.active=1 AND c.auth_method='private_key_jwt' AND c.revision=?14
 AND a.account_id=?1 AND a.active=1 AND a.grant_version=?15)
AND COALESCE((SELECT version FROM vault_claim_release
 WHERE account_id=?1 AND client_id=?13 AND claim='name'),0)=?18
ON CONFLICT(account_id,client_id,claim) DO UPDATE SET
 attribute_revision=excluded.attribute_revision,system_grant_version=excluded.system_grant_version,
 client_revision=excluded.client_revision,connection_grant_version=excluded.connection_grant_version,
 version=vault_claim_release.version+1,status='active',expires_at=excluded.expires_at,updated_at=excluded.updated_at,
 source_storage_version=2,source_origin=excluded.source_origin,source_vault_id=excluded.source_vault_id,
 source_collection_id=excluded.source_collection_id,source_record_id=excluded.source_record_id,source_kind=excluded.source_kind,
 source_ciphertext_sha256=excluded.source_ciphertext_sha256,source_key_generation=excluded.source_key_generation,
 source_owner_key_revision=excluded.source_owner_key_revision
