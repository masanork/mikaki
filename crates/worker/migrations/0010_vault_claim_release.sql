-- RP-specific consent is distinct from the UserInfo system recipient Grant.
-- Both policies start disabled; adding these tables cannot disclose a claim.
CREATE TABLE vault_claim_release_policy (
  id INTEGER PRIMARY KEY CHECK(id = 1),
  enabled INTEGER NOT NULL CHECK(enabled IN (0, 1)),
  ttl_seconds INTEGER NOT NULL CHECK(ttl_seconds BETWEEN 60 AND 2592000),
  revision INTEGER NOT NULL CHECK(revision > 0)
) STRICT;
INSERT INTO vault_claim_release_policy(id,enabled,ttl_seconds,revision)
VALUES(1,0,86400,1);
CREATE TRIGGER vault_claim_release_policy_revision BEFORE UPDATE ON vault_claim_release_policy
WHEN NEW.revision != OLD.revision + 1
BEGIN SELECT RAISE(ABORT, 'claim release policy revision must increase'); END;

CREATE TABLE vault_claim_release (
  account_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  claim TEXT NOT NULL CHECK(claim = 'name'),
  attribute_revision INTEGER NOT NULL CHECK(attribute_revision > 0),
  system_grant_version INTEGER NOT NULL CHECK(system_grant_version > 0),
  client_revision INTEGER NOT NULL CHECK(client_revision >= 0),
  connection_grant_version INTEGER NOT NULL CHECK(connection_grant_version >= 0),
  version INTEGER NOT NULL CHECK(version > 0),
  status TEXT NOT NULL CHECK(status IN ('active','revoked')),
  expires_at INTEGER NOT NULL CHECK(expires_at > 0),
  updated_at INTEGER NOT NULL CHECK(updated_at > 0),
  PRIMARY KEY(account_id,client_id,claim),
  FOREIGN KEY(account_id,client_id) REFERENCES app_connection(account_id,client_id)
) STRICT;

CREATE TRIGGER vault_claim_release_version BEFORE UPDATE ON vault_claim_release
WHEN NEW.version != OLD.version + 1
BEGIN SELECT RAISE(ABORT, 'claim release version must increase'); END;

CREATE TRIGGER vault_claim_release_active_insert BEFORE INSERT ON vault_claim_release
WHEN NEW.status = 'active' AND NOT EXISTS (
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

CREATE TRIGGER vault_claim_release_active_update BEFORE UPDATE ON vault_claim_release
WHEN NEW.status = 'active' AND NOT EXISTS (
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

CREATE TRIGGER vault_claim_release_policy_change_revoke AFTER UPDATE ON vault_claim_release_policy
BEGIN
  UPDATE vault_claim_release SET status='revoked',version=version+1,
    updated_at=CAST(strftime('%s','now') AS INTEGER)
  WHERE status='active';
END;
CREATE TRIGGER vault_claim_release_system_grant_change_revoke AFTER UPDATE ON vault_attribute_grant
BEGIN
  UPDATE vault_claim_release SET status='revoked',version=version+1,
    updated_at=NEW.updated_at
  WHERE account_id=NEW.account_id AND claim=NEW.attribute_id AND status='active';
END;
CREATE TRIGGER vault_claim_release_client_change_revoke AFTER UPDATE ON client
BEGIN
  UPDATE vault_claim_release SET status='revoked',version=version+1,
    updated_at=CAST(strftime('%s','now') AS INTEGER)
  WHERE client_id=NEW.client_id AND status='active';
END;
CREATE TRIGGER vault_claim_release_connection_change_revoke AFTER UPDATE ON app_connection
BEGIN
  UPDATE vault_claim_release SET status='revoked',version=version+1,
    updated_at=CAST(strftime('%s','now') AS INTEGER)
  WHERE account_id=NEW.account_id AND client_id=NEW.client_id AND status='active';
END;
CREATE TRIGGER vault_claim_release_account_stop_revoke AFTER UPDATE OF active,epoch ON account_security
WHEN NEW.active!=OLD.active OR NEW.epoch!=OLD.epoch
BEGIN
  UPDATE vault_claim_release SET status='revoked',version=version+1,
    updated_at=CAST(strftime('%s','now') AS INTEGER)
  WHERE account_id=NEW.account_id AND status='active';
END;

CREATE TABLE vault_claim_release_audit (
  account_id TEXT NOT NULL,
  operation_id TEXT NOT NULL CHECK(length(operation_id)=43),
  request_hash TEXT NOT NULL CHECK(length(request_hash)=43),
  client_id TEXT NOT NULL,
  claim TEXT NOT NULL CHECK(claim='name'),
  action TEXT NOT NULL CHECK(action IN ('grant','revoke')),
  release_version INTEGER NOT NULL CHECK(release_version>0),
  occurred_at INTEGER NOT NULL CHECK(occurred_at>0),
  PRIMARY KEY(account_id,operation_id)
) STRICT;
CREATE TRIGGER vault_claim_release_audit_no_update BEFORE UPDATE ON vault_claim_release_audit
BEGIN SELECT RAISE(ABORT, 'claim release audit is immutable'); END;
CREATE TRIGGER vault_claim_release_audit_no_delete BEFORE DELETE ON vault_claim_release_audit
BEGIN SELECT RAISE(ABORT, 'claim release audit is immutable'); END;

CREATE TABLE vault_claim_release_atomic_guard (
  operation_id TEXT PRIMARY KEY,
  passed INTEGER NOT NULL CHECK(passed=1)
) STRICT;
