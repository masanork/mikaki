-- Account email is separate from enrollment invitation contacts. No OIDC
-- release occurs until a verified value, client policy and owner grant agree.
CREATE TABLE account_verified_email (
  account_id TEXT PRIMARY KEY NOT NULL REFERENCES account_security(account_id),
  email TEXT NOT NULL CHECK(length(email) BETWEEN 3 AND 254),
  revision INTEGER NOT NULL CHECK(revision > 0),
  account_epoch INTEGER NOT NULL CHECK(account_epoch > 0),
  verified_at INTEGER NOT NULL CHECK(verified_at > 0),
  active INTEGER NOT NULL CHECK(active IN (0,1))
) STRICT;
CREATE TABLE account_email_challenge (
  challenge_hash TEXT PRIMARY KEY NOT NULL CHECK(length(challenge_hash)=43),
  account_id TEXT NOT NULL REFERENCES account_security(account_id),
  email TEXT NOT NULL CHECK(length(email) BETWEEN 3 AND 254),
  account_epoch INTEGER NOT NULL CHECK(account_epoch > 0),
  expected_revision INTEGER NOT NULL CHECK(expected_revision >= 0),
  expires_at INTEGER NOT NULL CHECK(expires_at > 0),
  consumed_at INTEGER,
  CHECK(consumed_at IS NULL OR consumed_at > 0)
) STRICT;
CREATE INDEX account_email_challenge_account ON account_email_challenge(account_id,expires_at);
CREATE INDEX account_email_challenge_expiry ON account_email_challenge(expires_at);
CREATE TABLE client_email_policy (
  client_id TEXT PRIMARY KEY NOT NULL REFERENCES client(client_id),
  client_revision INTEGER NOT NULL CHECK(client_revision > 0),
  enabled INTEGER NOT NULL CHECK(enabled IN (0,1))
) STRICT;
CREATE TABLE authorization_email_scope (
  code_hash TEXT PRIMARY KEY NOT NULL REFERENCES authorization_code(code_hash) ON DELETE CASCADE
) STRICT;
CREATE TABLE client_email_policy_audit (
  operation_id TEXT PRIMARY KEY NOT NULL,
  client_id TEXT NOT NULL REFERENCES client(client_id),
  client_revision INTEGER NOT NULL CHECK(client_revision > 0),
  enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
  actor TEXT NOT NULL CHECK(length(actor) BETWEEN 1 AND 128),
  reason TEXT NOT NULL CHECK(length(reason) BETWEEN 1 AND 512),
  occurred_at INTEGER NOT NULL CHECK(occurred_at > 0)
) STRICT;
CREATE TRIGGER client_email_policy_audit_no_update BEFORE UPDATE ON client_email_policy_audit
BEGIN SELECT RAISE(ABORT,'email policy audit is immutable'); END;
CREATE TRIGGER client_email_policy_audit_no_delete BEFORE DELETE ON client_email_policy_audit
BEGIN SELECT RAISE(ABORT,'email policy audit is immutable'); END;
CREATE TABLE account_email_release (
  account_id TEXT NOT NULL REFERENCES account_security(account_id),
  client_id TEXT NOT NULL REFERENCES client(client_id),
  email_revision INTEGER NOT NULL CHECK(email_revision > 0),
  account_epoch INTEGER NOT NULL CHECK(account_epoch > 0),
  client_revision INTEGER NOT NULL CHECK(client_revision > 0),
  grant_version INTEGER NOT NULL CHECK(grant_version > 0),
  active INTEGER NOT NULL CHECK(active IN (0,1)),
  revision INTEGER NOT NULL DEFAULT 1 CHECK(revision > 0),
  PRIMARY KEY(account_id,client_id)
) STRICT;
CREATE VIEW eligible_verified_email_release AS
SELECT e.account_id, p.client_id, e.email, e.revision AS email_revision, r.revision AS release_revision
FROM account_verified_email e
JOIN account_security a ON a.account_id=e.account_id AND a.active=1 AND a.epoch=e.account_epoch
JOIN account_email_release r ON r.account_id=e.account_id AND r.active=1
  AND r.email_revision=e.revision AND r.account_epoch=e.account_epoch
JOIN client c ON c.client_id=r.client_id AND c.active=1 AND c.revision=r.client_revision
JOIN client_email_policy p ON p.client_id=c.client_id AND p.enabled=1 AND p.client_revision=c.revision
JOIN app_connection g ON g.account_id=e.account_id AND g.client_id=c.client_id
  AND g.active=1 AND g.grant_version=r.grant_version
WHERE e.active=1;
CREATE TRIGGER account_verified_email_revision BEFORE UPDATE ON account_verified_email
WHEN NEW.revision<=OLD.revision OR NEW.account_id<>OLD.account_id
BEGIN SELECT RAISE(ABORT,'email revision must increase'); END;
CREATE TRIGGER account_email_release_revision BEFORE UPDATE ON account_email_release
WHEN NEW.revision<=OLD.revision OR NEW.account_id<>OLD.account_id OR NEW.client_id<>OLD.client_id
BEGIN SELECT RAISE(ABORT,'email release revision must increase'); END;
CREATE TRIGGER account_email_challenge_no_reuse BEFORE UPDATE ON account_email_challenge
WHEN OLD.consumed_at IS NOT NULL OR NEW.challenge_hash<>OLD.challenge_hash
  OR NEW.account_id<>OLD.account_id OR NEW.email<>OLD.email
  OR NEW.account_epoch<>OLD.account_epoch OR NEW.expected_revision<>OLD.expected_revision
  OR NEW.expires_at<>OLD.expires_at OR NEW.consumed_at IS NULL
BEGIN SELECT RAISE(ABORT,'email challenge is immutable and one-use'); END;
