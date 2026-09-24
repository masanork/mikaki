-- Owner-approved system sharing. No RP claim release is implied by a Grant.
-- Disabled until the recipient envelope suite and live key interop are approved.
CREATE TABLE vault_share_policy (
  id INTEGER PRIMARY KEY CHECK(id = 1),
  enabled INTEGER NOT NULL CHECK(enabled IN (0, 1)),
  grant_ttl_seconds INTEGER NOT NULL CHECK(grant_ttl_seconds BETWEEN 60 AND 2592000),
  revision INTEGER NOT NULL CHECK(revision > 0)
) STRICT;
INSERT INTO vault_share_policy(id,enabled,grant_ttl_seconds,revision) VALUES(1,0,604800,1);
CREATE TRIGGER vault_share_policy_revision BEFORE UPDATE ON vault_share_policy
WHEN NEW.revision != OLD.revision + 1
BEGIN SELECT RAISE(ABORT, 'share policy revision must increase'); END;

CREATE TABLE vault_attribute_recipient_envelope (
  envelope_id TEXT PRIMARY KEY NOT NULL CHECK(length(envelope_id) = 43),
  account_id TEXT NOT NULL,
  attribute_id TEXT NOT NULL CHECK(attribute_id = 'name'),
  attribute_revision INTEGER NOT NULL CHECK(attribute_revision > 0),
  recipient_service TEXT NOT NULL CHECK(recipient_service = 'userinfo'),
  recipient_key_id TEXT NOT NULL REFERENCES vault_recipient_key(key_id),
  recipient_generation INTEGER NOT NULL CHECK(recipient_generation > 0),
  suite TEXT NOT NULL CHECK(suite = 'ML-KEM-768-HKDF-SHA256-AES-256-GCM-draft04-v1'),
  ciphertext_sha256 TEXT NOT NULL CHECK(length(ciphertext_sha256) = 43),
  frame BLOB NOT NULL CHECK(length(frame) = 1187),
  created_at INTEGER NOT NULL CHECK(created_at > 0),
  FOREIGN KEY(account_id,attribute_id) REFERENCES vault_attribute_head(account_id,attribute_id)
) STRICT;
CREATE INDEX vault_attribute_envelope_owner
  ON vault_attribute_recipient_envelope(account_id,attribute_id,attribute_revision);

CREATE TABLE vault_attribute_grant (
  account_id TEXT NOT NULL,
  attribute_id TEXT NOT NULL CHECK(attribute_id = 'name'),
  recipient_service TEXT NOT NULL CHECK(recipient_service = 'userinfo'),
  purpose TEXT NOT NULL CHECK(purpose = 'oidc.userinfo.name'),
  envelope_id TEXT NOT NULL REFERENCES vault_attribute_recipient_envelope(envelope_id),
  attribute_revision INTEGER NOT NULL CHECK(attribute_revision > 0),
  version INTEGER NOT NULL CHECK(version > 0),
  status TEXT NOT NULL CHECK(status IN ('active','revoked')),
  expires_at INTEGER NOT NULL CHECK(expires_at > 0),
  updated_at INTEGER NOT NULL CHECK(updated_at > 0),
  PRIMARY KEY(account_id,attribute_id,recipient_service,purpose)
) STRICT;

CREATE TRIGGER vault_attribute_grant_version BEFORE UPDATE ON vault_attribute_grant
WHEN NEW.version != OLD.version + 1
BEGIN SELECT RAISE(ABORT, 'grant version must increase'); END;

CREATE TRIGGER vault_attribute_grant_active_insert BEFORE INSERT ON vault_attribute_grant
WHEN NEW.status = 'active' AND NOT EXISTS (
  SELECT 1 FROM vault_attribute_recipient_envelope e
  JOIN vault_attribute_head h ON h.account_id=e.account_id AND h.attribute_id=e.attribute_id
  JOIN vault_recipient_key k ON k.key_id=e.recipient_key_id
  JOIN vault_share_policy p ON p.id=1
  WHERE e.envelope_id=NEW.envelope_id AND e.account_id=NEW.account_id AND e.attribute_id=NEW.attribute_id
    AND e.attribute_revision=NEW.attribute_revision AND e.recipient_service=NEW.recipient_service
    AND h.revision=e.attribute_revision AND h.deleted=0
    AND h.ciphertext_sha256=e.ciphertext_sha256
    AND k.service_id=e.recipient_service AND k.generation=e.recipient_generation
    AND k.state='active' AND p.enabled=1
)
BEGIN SELECT RAISE(ABORT, 'grant preconditions failed'); END;

CREATE TRIGGER vault_attribute_grant_active_update BEFORE UPDATE ON vault_attribute_grant
WHEN NEW.status = 'active' AND NOT EXISTS (
  SELECT 1 FROM vault_attribute_recipient_envelope e
  JOIN vault_attribute_head h ON h.account_id=e.account_id AND h.attribute_id=e.attribute_id
  JOIN vault_recipient_key k ON k.key_id=e.recipient_key_id
  JOIN vault_share_policy p ON p.id=1
  WHERE e.envelope_id=NEW.envelope_id AND e.account_id=NEW.account_id AND e.attribute_id=NEW.attribute_id
    AND e.attribute_revision=NEW.attribute_revision AND e.recipient_service=NEW.recipient_service
    AND h.revision=e.attribute_revision AND h.deleted=0
    AND h.ciphertext_sha256=e.ciphertext_sha256
    AND k.service_id=e.recipient_service AND k.generation=e.recipient_generation
    AND k.state='active' AND p.enabled=1
)
BEGIN SELECT RAISE(ABORT, 'grant preconditions failed'); END;

-- A new Vault revision immediately invalidates a previously approved Grant.
CREATE TRIGGER vault_attribute_head_revoke_grant AFTER UPDATE ON vault_attribute_head
BEGIN
  UPDATE vault_attribute_grant SET status='revoked',version=version+1,updated_at=NEW.updated_at
  WHERE account_id=NEW.account_id AND attribute_id=NEW.attribute_id AND status='active';
END;

CREATE TRIGGER vault_share_policy_change_revoke_grants AFTER UPDATE ON vault_share_policy
WHEN NEW.enabled!=OLD.enabled OR NEW.grant_ttl_seconds!=OLD.grant_ttl_seconds
BEGIN
  UPDATE vault_attribute_grant SET status='revoked',version=version+1,
    updated_at=CAST(strftime('%s','now') AS INTEGER)
  WHERE status='active';
END;

CREATE TABLE vault_attribute_share_audit (
  account_id TEXT NOT NULL,
  operation_id TEXT NOT NULL CHECK(length(operation_id) = 43),
  request_hash TEXT NOT NULL CHECK(length(request_hash) = 43),
  attribute_id TEXT NOT NULL CHECK(attribute_id = 'name'),
  action TEXT NOT NULL CHECK(action IN ('share','revoke')),
  attribute_revision INTEGER NOT NULL CHECK(attribute_revision > 0),
  grant_version INTEGER NOT NULL CHECK(grant_version > 0),
  occurred_at INTEGER NOT NULL CHECK(occurred_at > 0),
  PRIMARY KEY(account_id,operation_id)
) STRICT;
CREATE TRIGGER vault_attribute_share_audit_no_update BEFORE UPDATE ON vault_attribute_share_audit
BEGIN SELECT RAISE(ABORT, 'share audit is immutable'); END;
CREATE TRIGGER vault_attribute_share_audit_no_delete BEFORE DELETE ON vault_attribute_share_audit
BEGIN SELECT RAISE(ABORT, 'share audit is immutable'); END;

-- A failed compare-and-swap aborts its entire D1 batch, including the envelope.
CREATE TABLE vault_share_atomic_guard (
  operation_id TEXT PRIMARY KEY,
  passed INTEGER NOT NULL CHECK(passed = 1)
) STRICT;
