-- Separate record-recipient profile. Disabled by default; no production policy changes.
CREATE TABLE vault_record_share_policy (
 id INTEGER PRIMARY KEY CHECK(id=1), enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
 grant_ttl_seconds INTEGER NOT NULL CHECK(grant_ttl_seconds BETWEEN 60 AND 2592000),
 revision INTEGER NOT NULL CHECK(revision>0)
) STRICT;
INSERT INTO vault_record_share_policy VALUES(1,0,604800,1);
CREATE TRIGGER vault_record_share_policy_revision BEFORE UPDATE ON vault_record_share_policy
WHEN NEW.revision != OLD.revision+1
BEGIN SELECT RAISE(ABORT,'record share policy revision must increase'); END;

CREATE TABLE vault_record_recipient_envelope (
 envelope_id TEXT PRIMARY KEY NOT NULL CHECK(length(envelope_id)=43),
 account_id TEXT NOT NULL, origin TEXT NOT NULL, vault_id TEXT NOT NULL,
 collection_id TEXT NOT NULL CHECK(collection_id='personal'),
 record_id TEXT NOT NULL CHECK(record_id='name'), kind TEXT NOT NULL CHECK(kind='name'),
 record_revision INTEGER NOT NULL CHECK(record_revision BETWEEN 1 AND 9007199254740991),
 ciphertext_sha256 TEXT NOT NULL CHECK(length(ciphertext_sha256)=43),
 key_generation INTEGER NOT NULL CHECK(key_generation BETWEEN 1 AND 9007199254740991),
 owner_key_revision INTEGER NOT NULL CHECK(owner_key_revision BETWEEN 1 AND 9007199254740991),
 recipient_service TEXT NOT NULL CHECK(recipient_service='userinfo'),
 purpose TEXT NOT NULL CHECK(purpose='oidc.userinfo.name'),
 recipient_key_id TEXT NOT NULL REFERENCES vault_recipient_key(key_id),
 recipient_generation INTEGER NOT NULL CHECK(recipient_generation BETWEEN 1 AND 9007199254740991),
 directory_revision INTEGER NOT NULL CHECK(directory_revision BETWEEN 1 AND 9007199254740991),
 policy_revision INTEGER NOT NULL CHECK(policy_revision BETWEEN 1 AND 9007199254740991),
 suite TEXT NOT NULL CHECK(suite='ML-KEM-768-HKDF-SHA256-AES-256-GCM-draft04-record-v2'),
 frame BLOB NOT NULL CHECK(length(frame)=1187 AND hex(substr(frame,1,5))='4D4B565202'),
 created_at INTEGER NOT NULL CHECK(created_at>0),
 FOREIGN KEY(account_id,vault_id,collection_id,record_id)
  REFERENCES vault_owner_record_head(account_id,vault_id,collection_id,record_id),
 UNIQUE(envelope_id,account_id),
 UNIQUE(envelope_id,account_id,origin,vault_id,collection_id,record_id,kind,record_revision,
  ciphertext_sha256,key_generation,owner_key_revision,recipient_service,purpose)
) STRICT;
CREATE TRIGGER vault_record_envelope_no_update BEFORE UPDATE ON vault_record_recipient_envelope
BEGIN SELECT RAISE(ABORT,'record recipient envelope is immutable'); END;
CREATE TRIGGER vault_record_envelope_no_delete BEFORE DELETE ON vault_record_recipient_envelope
BEGIN SELECT RAISE(ABORT,'record recipient envelope is immutable'); END;

CREATE TABLE vault_record_grant (
 account_id TEXT NOT NULL, origin TEXT NOT NULL, vault_id TEXT NOT NULL,
 collection_id TEXT NOT NULL CHECK(collection_id='personal'),
 record_id TEXT NOT NULL CHECK(record_id='name'),kind TEXT NOT NULL CHECK(kind='name'),
 record_revision INTEGER NOT NULL CHECK(record_revision BETWEEN 1 AND 9007199254740991),
 ciphertext_sha256 TEXT NOT NULL CHECK(length(ciphertext_sha256)=43),
 key_generation INTEGER NOT NULL CHECK(key_generation BETWEEN 1 AND 9007199254740991),
 owner_key_revision INTEGER NOT NULL CHECK(owner_key_revision BETWEEN 1 AND 9007199254740991),
 recipient_service TEXT NOT NULL CHECK(recipient_service='userinfo'),
 purpose TEXT NOT NULL CHECK(purpose='oidc.userinfo.name'),envelope_id TEXT NOT NULL,
 version INTEGER NOT NULL CHECK(version BETWEEN 1 AND 9007199254740991),status TEXT NOT NULL CHECK(status IN ('active','revoked')),
 expires_at INTEGER NOT NULL CHECK(expires_at>0),updated_at INTEGER NOT NULL CHECK(updated_at>0),
 PRIMARY KEY(account_id,vault_id,collection_id,record_id,recipient_service,purpose),
 FOREIGN KEY(envelope_id,account_id,origin,vault_id,collection_id,record_id,kind,record_revision,
  ciphertext_sha256,key_generation,owner_key_revision,recipient_service,purpose)
 REFERENCES vault_record_recipient_envelope(envelope_id,account_id,origin,vault_id,collection_id,record_id,kind,
  record_revision,ciphertext_sha256,key_generation,owner_key_revision,recipient_service,purpose)
) STRICT;
CREATE TRIGGER vault_record_grant_version BEFORE UPDATE ON vault_record_grant
WHEN NEW.version != OLD.version+1
BEGIN SELECT RAISE(ABORT,'record grant version must increase'); END;

-- A single per-RP consent ledger chooses exactly one source. Existing consent
-- remains explicitly format 1; adding a v2 name never changes that selection.
ALTER TABLE vault_claim_release ADD COLUMN source_storage_version INTEGER NOT NULL DEFAULT 1 CHECK(source_storage_version IN (1,2));
ALTER TABLE vault_claim_release ADD COLUMN source_origin TEXT;
ALTER TABLE vault_claim_release ADD COLUMN source_vault_id TEXT;
ALTER TABLE vault_claim_release ADD COLUMN source_collection_id TEXT;
ALTER TABLE vault_claim_release ADD COLUMN source_record_id TEXT;
ALTER TABLE vault_claim_release ADD COLUMN source_kind TEXT;
ALTER TABLE vault_claim_release ADD COLUMN source_ciphertext_sha256 TEXT;
ALTER TABLE vault_claim_release ADD COLUMN source_key_generation INTEGER;
ALTER TABLE vault_claim_release ADD COLUMN source_owner_key_revision INTEGER;
ALTER TABLE vault_claim_release_audit ADD COLUMN source_storage_version INTEGER NOT NULL DEFAULT 1 CHECK(source_storage_version IN (1,2));
ALTER TABLE vault_claim_release_audit ADD COLUMN source_json TEXT;
ALTER TABLE vault_claim_disclosure_audit ADD COLUMN source_storage_version INTEGER NOT NULL DEFAULT 1 CHECK(source_storage_version IN (1,2));
ALTER TABLE vault_claim_disclosure_audit ADD COLUMN source_json TEXT;

CREATE TABLE vault_record_share_audit (
 account_id TEXT NOT NULL,operation_id TEXT NOT NULL CHECK(length(operation_id)=43),
 request_hash TEXT NOT NULL CHECK(length(request_hash)=43),action TEXT NOT NULL CHECK(action IN ('share','revoke')),
 envelope_id TEXT NOT NULL,
 grant_version INTEGER NOT NULL CHECK(grant_version>0),occurred_at INTEGER NOT NULL CHECK(occurred_at>0),
 PRIMARY KEY(account_id,operation_id),
 FOREIGN KEY(envelope_id,account_id) REFERENCES vault_record_recipient_envelope(envelope_id,account_id)
) STRICT;
CREATE TRIGGER vault_record_share_audit_no_update BEFORE UPDATE ON vault_record_share_audit
BEGIN SELECT RAISE(ABORT,'record share audit is immutable'); END;
CREATE TRIGGER vault_record_share_audit_no_delete BEFORE DELETE ON vault_record_share_audit
BEGIN SELECT RAISE(ABORT,'record share audit is immutable'); END;
CREATE TABLE vault_record_share_guard (
 account_id TEXT NOT NULL,operation_id TEXT NOT NULL,passed INTEGER NOT NULL CHECK(passed=1),
 PRIMARY KEY(account_id,operation_id)
) STRICT;

CREATE TRIGGER vault_record_grant_active_insert BEFORE INSERT ON vault_record_grant
WHEN NEW.status='active' AND NOT EXISTS (SELECT 1 FROM vault_record_recipient_envelope e
 JOIN vault_owner_record_head h ON h.account_id=e.account_id AND h.vault_id=e.vault_id
  AND h.collection_id=e.collection_id AND h.record_id=e.record_id
 JOIN vault_owner_key_head root ON root.account_id=e.account_id AND root.vault_id=e.vault_id
 JOIN account_security a ON a.account_id=e.account_id
 JOIN vault_recipient_key k ON k.key_id=e.recipient_key_id
 JOIN vault_record_share_policy p ON p.id=1
 WHERE e.envelope_id=NEW.envelope_id AND e.account_id=NEW.account_id
 AND e.origin=NEW.origin AND e.vault_id=NEW.vault_id AND e.collection_id=NEW.collection_id
 AND e.record_id=NEW.record_id AND e.kind=NEW.kind AND e.record_revision=NEW.record_revision
 AND e.ciphertext_sha256=NEW.ciphertext_sha256 AND e.key_generation=NEW.key_generation
 AND e.owner_key_revision=NEW.owner_key_revision AND e.recipient_service=NEW.recipient_service AND e.purpose=NEW.purpose
 AND h.deleted=0 AND h.kind=e.kind AND h.revision=e.record_revision AND h.ciphertext_sha256=e.ciphertext_sha256
 AND h.key_generation=e.key_generation AND h.format_version=2
 AND root.origin=e.origin AND root.key_generation=e.key_generation AND root.revision=e.owner_key_revision
 AND root.format_version=2 AND root.suite='PRF-HKDF-SHA256-AES256GCM-v2' AND a.active=1
 AND k.service_id=e.recipient_service AND k.algorithm='ML-KEM-768' AND k.state='active'
 AND k.generation=e.recipient_generation AND k.revision=e.directory_revision
 AND p.enabled=1 AND p.revision=e.policy_revision
 AND NEW.expires_at>unixepoch() AND NEW.expires_at<=unixepoch()+p.grant_ttl_seconds)
BEGIN SELECT RAISE(ABORT,'record grant preconditions failed'); END;
CREATE TRIGGER vault_record_grant_active_update BEFORE UPDATE ON vault_record_grant
WHEN NEW.status='active' AND NOT EXISTS (SELECT 1 FROM vault_record_recipient_envelope e
 JOIN vault_owner_record_head h ON h.account_id=e.account_id AND h.vault_id=e.vault_id
  AND h.collection_id=e.collection_id AND h.record_id=e.record_id
 JOIN vault_owner_key_head root ON root.account_id=e.account_id AND root.vault_id=e.vault_id
 JOIN account_security a ON a.account_id=e.account_id
 JOIN vault_recipient_key k ON k.key_id=e.recipient_key_id
 JOIN vault_record_share_policy p ON p.id=1
 WHERE e.envelope_id=NEW.envelope_id AND e.account_id=NEW.account_id
 AND e.origin=NEW.origin AND e.vault_id=NEW.vault_id AND e.collection_id=NEW.collection_id
 AND e.record_id=NEW.record_id AND e.kind=NEW.kind AND e.record_revision=NEW.record_revision
 AND e.ciphertext_sha256=NEW.ciphertext_sha256 AND e.key_generation=NEW.key_generation
 AND e.owner_key_revision=NEW.owner_key_revision AND e.recipient_service=NEW.recipient_service AND e.purpose=NEW.purpose
 AND h.deleted=0 AND h.kind=e.kind AND h.revision=e.record_revision AND h.ciphertext_sha256=e.ciphertext_sha256
 AND h.key_generation=e.key_generation AND h.format_version=2
 AND root.origin=e.origin AND root.key_generation=e.key_generation AND root.revision=e.owner_key_revision
 AND root.format_version=2 AND root.suite='PRF-HKDF-SHA256-AES256GCM-v2' AND a.active=1
 AND k.service_id=e.recipient_service AND k.algorithm='ML-KEM-768' AND k.state='active'
 AND k.generation=e.recipient_generation AND k.revision=e.directory_revision
 AND p.enabled=1 AND p.revision=e.policy_revision
 AND NEW.expires_at>unixepoch() AND NEW.expires_at<=unixepoch()+p.grant_ttl_seconds)
BEGIN SELECT RAISE(ABORT,'record grant preconditions failed'); END;

DROP TRIGGER vault_claim_release_active_insert;
CREATE TRIGGER vault_claim_release_active_insert BEFORE INSERT ON vault_claim_release
WHEN NEW.status = 'active' AND NEW.source_storage_version=1 AND NOT EXISTS (
  SELECT 1 FROM vault_claim_release_policy rp
  JOIN vault_share_policy sp ON sp.id=rp.id
  JOIN account_security a ON a.account_id=NEW.account_id
  JOIN client c ON c.client_id=NEW.client_id
  JOIN app_connection ac ON ac.account_id=NEW.account_id AND ac.client_id=NEW.client_id
  JOIN vault_attribute_grant g ON g.account_id=NEW.account_id
    AND g.attribute_id='name' AND g.recipient_service='userinfo'
    AND g.purpose='oidc.userinfo.name'
  JOIN vault_attribute_recipient_envelope e ON e.envelope_id=g.envelope_id
  JOIN vault_recipient_key k ON k.key_id=e.recipient_key_id
  JOIN vault_attribute_head h ON h.account_id=NEW.account_id AND h.attribute_id='name'
  WHERE rp.id=1 AND rp.enabled=1 AND sp.enabled=1 AND a.active=1
    AND c.active=1 AND c.auth_method='private_key_jwt'
    AND c.revision=NEW.client_revision
    AND ac.active=1 AND ac.grant_version=NEW.connection_grant_version
    AND g.status='active' AND g.version=NEW.system_grant_version
    AND g.attribute_revision=NEW.attribute_revision
    AND g.expires_at>=NEW.expires_at
    AND g.expires_at>CAST(strftime('%s','now') AS INTEGER)
    AND e.account_id=NEW.account_id AND e.attribute_revision=NEW.attribute_revision
    AND h.revision=NEW.attribute_revision AND h.deleted=0
    AND h.ciphertext_sha256=e.ciphertext_sha256
    AND k.state='active'
    AND NEW.expires_at>CAST(strftime('%s','now') AS INTEGER)
    AND NEW.expires_at<=CAST(strftime('%s','now') AS INTEGER)+rp.ttl_seconds
)
BEGIN SELECT RAISE(ABORT, 'claim release preconditions failed'); END;

DROP TRIGGER vault_claim_release_active_update;
CREATE TRIGGER vault_claim_release_active_update BEFORE UPDATE ON vault_claim_release
WHEN NEW.status = 'active' AND NEW.source_storage_version=1 AND NOT EXISTS (
  SELECT 1 FROM vault_claim_release_policy rp
  JOIN vault_share_policy sp ON sp.id=rp.id
  JOIN account_security a ON a.account_id=NEW.account_id
  JOIN client c ON c.client_id=NEW.client_id
  JOIN app_connection ac ON ac.account_id=NEW.account_id AND ac.client_id=NEW.client_id
  JOIN vault_attribute_grant g ON g.account_id=NEW.account_id
    AND g.attribute_id='name' AND g.recipient_service='userinfo'
    AND g.purpose='oidc.userinfo.name'
  JOIN vault_attribute_recipient_envelope e ON e.envelope_id=g.envelope_id
  JOIN vault_recipient_key k ON k.key_id=e.recipient_key_id
  JOIN vault_attribute_head h ON h.account_id=NEW.account_id AND h.attribute_id='name'
  WHERE rp.id=1 AND rp.enabled=1 AND sp.enabled=1 AND a.active=1
    AND c.active=1 AND c.auth_method='private_key_jwt'
    AND c.revision=NEW.client_revision
    AND ac.active=1 AND ac.grant_version=NEW.connection_grant_version
    AND g.status='active' AND g.version=NEW.system_grant_version
    AND g.attribute_revision=NEW.attribute_revision
    AND g.expires_at>=NEW.expires_at
    AND g.expires_at>CAST(strftime('%s','now') AS INTEGER)
    AND e.account_id=NEW.account_id AND e.attribute_revision=NEW.attribute_revision
    AND h.revision=NEW.attribute_revision AND h.deleted=0
    AND h.ciphertext_sha256=e.ciphertext_sha256
    AND k.state='active'
    AND NEW.expires_at>CAST(strftime('%s','now') AS INTEGER)
    AND NEW.expires_at<=CAST(strftime('%s','now') AS INTEGER)+rp.ttl_seconds
)
BEGIN SELECT RAISE(ABORT, 'claim release preconditions failed'); END;
CREATE TRIGGER vault_claim_release_record_insert BEFORE INSERT ON vault_claim_release
WHEN NEW.status='active' AND NEW.source_storage_version=2 AND NOT EXISTS (SELECT 1 FROM vault_record_grant g
 JOIN vault_record_recipient_envelope e ON e.envelope_id=g.envelope_id
 JOIN vault_owner_record_head h ON h.account_id=g.account_id AND h.vault_id=g.vault_id
  AND h.collection_id=g.collection_id AND h.record_id=g.record_id
 JOIN vault_owner_key_head root ON root.account_id=g.account_id AND root.vault_id=g.vault_id
 JOIN account_security a ON a.account_id=g.account_id
 JOIN vault_recipient_key k ON k.key_id=e.recipient_key_id
 JOIN vault_record_share_policy sp ON sp.id=1
 JOIN vault_claim_release_policy rp ON rp.id=1
 JOIN client c ON c.client_id=NEW.client_id
 JOIN app_connection ac ON ac.account_id=g.account_id AND ac.client_id=NEW.client_id
 WHERE g.account_id=NEW.account_id AND g.origin=NEW.source_origin AND g.vault_id=NEW.source_vault_id
 AND g.collection_id=NEW.source_collection_id AND g.record_id=NEW.source_record_id AND g.kind=NEW.source_kind
 AND g.record_revision=NEW.attribute_revision AND g.ciphertext_sha256=NEW.source_ciphertext_sha256
 AND g.key_generation=NEW.source_key_generation AND g.owner_key_revision=NEW.source_owner_key_revision
 AND g.recipient_service='userinfo' AND g.purpose='oidc.userinfo.name'
 AND g.status='active' AND g.version=NEW.system_grant_version AND g.expires_at>=NEW.expires_at
 AND h.deleted=0 AND h.kind=g.kind AND h.revision=g.record_revision AND h.ciphertext_sha256=g.ciphertext_sha256
 AND h.key_generation=g.key_generation AND h.format_version=2
 AND root.origin=g.origin AND root.key_generation=g.key_generation AND root.revision=g.owner_key_revision
 AND root.format_version=2 AND root.suite='PRF-HKDF-SHA256-AES256GCM-v2' AND a.active=1
 AND k.service_id='userinfo' AND k.state='active' AND k.generation=e.recipient_generation AND k.revision=e.directory_revision
 AND sp.enabled=1 AND sp.revision=e.policy_revision AND rp.enabled=1
 AND c.active=1 AND c.auth_method='private_key_jwt' AND c.revision=NEW.client_revision
 AND ac.active=1 AND ac.grant_version=NEW.connection_grant_version
 AND NEW.expires_at>unixepoch() AND NEW.expires_at<=unixepoch()+rp.ttl_seconds)
BEGIN SELECT RAISE(ABORT,'record claim release preconditions failed'); END;
CREATE TRIGGER vault_claim_release_source_insert BEFORE INSERT ON vault_claim_release
WHEN COALESCE(((NEW.source_storage_version=1 AND NEW.source_origin IS NULL AND NEW.source_vault_id IS NULL
 AND NEW.source_collection_id IS NULL AND NEW.source_record_id IS NULL AND NEW.source_kind IS NULL
 AND NEW.source_ciphertext_sha256 IS NULL AND NEW.source_key_generation IS NULL AND NEW.source_owner_key_revision IS NULL)
 OR (NEW.source_storage_version=2 AND NEW.source_origin IS NOT NULL AND NEW.source_vault_id IS NOT NULL
 AND NEW.source_collection_id='personal' AND NEW.source_record_id='name' AND NEW.source_kind='name'
 AND length(NEW.source_ciphertext_sha256)=43 AND NEW.source_key_generation BETWEEN 1 AND 9007199254740991
 AND NEW.source_owner_key_revision BETWEEN 1 AND 9007199254740991)),0)=0
BEGIN SELECT RAISE(ABORT,'invalid claim source'); END;
CREATE TRIGGER vault_claim_release_record_update BEFORE UPDATE ON vault_claim_release
WHEN NEW.status='active' AND NEW.source_storage_version=2 AND NOT EXISTS (SELECT 1 FROM vault_record_grant g
 JOIN vault_record_recipient_envelope e ON e.envelope_id=g.envelope_id
 JOIN vault_owner_record_head h ON h.account_id=g.account_id AND h.vault_id=g.vault_id
  AND h.collection_id=g.collection_id AND h.record_id=g.record_id
 JOIN vault_owner_key_head root ON root.account_id=g.account_id AND root.vault_id=g.vault_id
 JOIN account_security a ON a.account_id=g.account_id
 JOIN vault_recipient_key k ON k.key_id=e.recipient_key_id
 JOIN vault_record_share_policy sp ON sp.id=1
 JOIN vault_claim_release_policy rp ON rp.id=1
 JOIN client c ON c.client_id=NEW.client_id
 JOIN app_connection ac ON ac.account_id=g.account_id AND ac.client_id=NEW.client_id
 WHERE g.account_id=NEW.account_id AND g.origin=NEW.source_origin AND g.vault_id=NEW.source_vault_id
 AND g.collection_id=NEW.source_collection_id AND g.record_id=NEW.source_record_id AND g.kind=NEW.source_kind
 AND g.record_revision=NEW.attribute_revision AND g.ciphertext_sha256=NEW.source_ciphertext_sha256
 AND g.key_generation=NEW.source_key_generation AND g.owner_key_revision=NEW.source_owner_key_revision
 AND g.recipient_service='userinfo' AND g.purpose='oidc.userinfo.name'
 AND g.status='active' AND g.version=NEW.system_grant_version AND g.expires_at>=NEW.expires_at
 AND h.deleted=0 AND h.kind=g.kind AND h.revision=g.record_revision AND h.ciphertext_sha256=g.ciphertext_sha256
 AND h.key_generation=g.key_generation AND h.format_version=2
 AND root.origin=g.origin AND root.key_generation=g.key_generation AND root.revision=g.owner_key_revision
 AND root.format_version=2 AND root.suite='PRF-HKDF-SHA256-AES256GCM-v2' AND a.active=1
 AND k.service_id='userinfo' AND k.state='active' AND k.generation=e.recipient_generation AND k.revision=e.directory_revision
 AND sp.enabled=1 AND sp.revision=e.policy_revision AND rp.enabled=1
 AND c.active=1 AND c.auth_method='private_key_jwt' AND c.revision=NEW.client_revision
 AND ac.active=1 AND ac.grant_version=NEW.connection_grant_version
 AND NEW.expires_at>unixepoch() AND NEW.expires_at<=unixepoch()+rp.ttl_seconds)
BEGIN SELECT RAISE(ABORT,'record claim release preconditions failed'); END;
CREATE TRIGGER vault_claim_release_source_update BEFORE UPDATE ON vault_claim_release
WHEN COALESCE(((NEW.source_storage_version=1 AND NEW.source_origin IS NULL AND NEW.source_vault_id IS NULL
 AND NEW.source_collection_id IS NULL AND NEW.source_record_id IS NULL AND NEW.source_kind IS NULL
 AND NEW.source_ciphertext_sha256 IS NULL AND NEW.source_key_generation IS NULL AND NEW.source_owner_key_revision IS NULL)
 OR (NEW.source_storage_version=2 AND NEW.source_origin IS NOT NULL AND NEW.source_vault_id IS NOT NULL
 AND NEW.source_collection_id='personal' AND NEW.source_record_id='name' AND NEW.source_kind='name'
 AND length(NEW.source_ciphertext_sha256)=43 AND NEW.source_key_generation BETWEEN 1 AND 9007199254740991
 AND NEW.source_owner_key_revision BETWEEN 1 AND 9007199254740991)),0)=0
BEGIN SELECT RAISE(ABORT,'invalid claim source'); END;

DROP TRIGGER vault_claim_release_system_grant_change_revoke;
CREATE TRIGGER vault_claim_release_system_grant_change_revoke AFTER UPDATE ON vault_attribute_grant
BEGIN UPDATE vault_claim_release SET status='revoked',version=version+1,updated_at=NEW.updated_at
 WHERE account_id=NEW.account_id AND claim=NEW.attribute_id AND source_storage_version=1 AND status='active'; END;
CREATE TRIGGER vault_claim_release_record_grant_change AFTER UPDATE ON vault_record_grant
BEGIN UPDATE vault_claim_release SET status='revoked',version=version+1,updated_at=NEW.updated_at
 WHERE account_id=NEW.account_id AND source_storage_version=2 AND source_vault_id=NEW.vault_id
 AND source_collection_id=NEW.collection_id AND source_record_id=NEW.record_id AND status='active'; END;
CREATE TRIGGER vault_record_share_head_change AFTER UPDATE ON vault_owner_record_head
BEGIN UPDATE vault_record_grant SET status='revoked',version=version+1,updated_at=unixepoch()
 WHERE status='active' AND account_id=NEW.account_id AND vault_id=NEW.vault_id AND collection_id=NEW.collection_id AND record_id=NEW.record_id; END;
CREATE TRIGGER vault_record_share_root_change AFTER UPDATE ON vault_owner_key_head
BEGIN UPDATE vault_record_grant SET status='revoked',version=version+1,updated_at=unixepoch()
 WHERE status='active' AND account_id=NEW.account_id; END;
CREATE TRIGGER vault_record_share_policy_change AFTER UPDATE ON vault_record_share_policy
BEGIN UPDATE vault_record_grant SET status='revoked',version=version+1,updated_at=unixepoch()
 WHERE status='active' AND 1; END;
CREATE TRIGGER vault_record_share_recipient_change AFTER UPDATE ON vault_recipient_key
BEGIN UPDATE vault_record_grant SET status='revoked',version=version+1,updated_at=unixepoch()
 WHERE status='active' AND envelope_id IN (SELECT envelope_id FROM vault_record_recipient_envelope WHERE recipient_key_id=NEW.key_id); END;
CREATE TRIGGER vault_record_share_account_change AFTER UPDATE ON account_security WHEN NEW.active!=OLD.active OR NEW.epoch!=OLD.epoch
BEGIN UPDATE vault_record_grant SET status='revoked',version=version+1,updated_at=unixepoch()
 WHERE status='active' AND account_id=NEW.account_id; END;
