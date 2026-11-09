-- Explicitly provisioned identities for a particular relying party. This table
-- does not enable email disclosure; issuance must separately check client,
-- account, binding revision, scope and authorization in the same transaction.
CREATE TABLE access_email_binding (
  client_id TEXT NOT NULL REFERENCES client(client_id),
  account_id TEXT NOT NULL REFERENCES account_security(account_id),
  email TEXT NOT NULL CHECK(length(CAST(email AS BLOB)) BETWEEN 3 AND 254)
    CHECK(email = trim(email) AND instr(email, char(0)) = 0
      AND instr(email, char(10)) = 0 AND instr(email, char(13)) = 0),
  revision INTEGER NOT NULL CHECK(revision >= 1),
  active INTEGER NOT NULL CHECK(active IN (0, 1)),
  verified_at INTEGER NOT NULL CHECK(verified_at > 0),
  PRIMARY KEY(client_id, account_id)
) STRICT;

-- Email identifies a Cloudflare OS user. Never bind the same address to two
-- active accounts at one client, including ASCII case variants.
CREATE UNIQUE INDEX access_email_binding_active_email
  ON access_email_binding(client_id, email COLLATE NOCASE) WHERE active = 1;

-- An issuer can use this revision as an optimistic concurrency fence. Retain
-- revoked rows so a later binding cannot silently reuse an older revision.
CREATE TRIGGER access_email_binding_revision_guard
BEFORE UPDATE ON access_email_binding
WHEN NEW.client_id != OLD.client_id OR NEW.account_id != OLD.account_id
  OR NEW.revision <= OLD.revision
BEGIN
  SELECT RAISE(ABORT, 'binding revision must increase');
END;

CREATE TRIGGER access_email_binding_no_delete
BEFORE DELETE ON access_email_binding
BEGIN
  SELECT RAISE(ABORT, 'revoke binding instead of deleting');
END;

CREATE TABLE access_email_binding_audit (
  operation_id TEXT PRIMARY KEY NOT NULL CHECK(length(operation_id) BETWEEN 1 AND 128),
  client_id TEXT NOT NULL REFERENCES client(client_id),
  account_id TEXT NOT NULL REFERENCES account_security(account_id),
  action TEXT NOT NULL CHECK(action IN ('bind', 'replace', 'revoke')),
  revision INTEGER NOT NULL CHECK(revision >= 1),
  actor TEXT NOT NULL CHECK(length(actor) BETWEEN 1 AND 128),
  reason TEXT NOT NULL CHECK(length(reason) BETWEEN 1 AND 512),
  occurred_at INTEGER NOT NULL CHECK(occurred_at > 0)
) STRICT;

CREATE TABLE access_client_secret_audit (
  operation_id TEXT PRIMARY KEY NOT NULL CHECK(length(operation_id) BETWEEN 1 AND 128),
  client_id TEXT NOT NULL REFERENCES client(client_id),
  action TEXT NOT NULL CHECK(action IN ('register', 'rotate', 'revoke')),
  revision INTEGER NOT NULL CHECK(revision >= 1),
  actor TEXT NOT NULL CHECK(length(actor) BETWEEN 1 AND 128),
  reason TEXT NOT NULL CHECK(length(reason) BETWEEN 1 AND 512),
  occurred_at INTEGER NOT NULL CHECK(occurred_at > 0)
) STRICT;

-- Preserve operator audit records after insertion, as with verified-email policy audits.
CREATE TRIGGER access_email_binding_audit_no_update BEFORE UPDATE ON access_email_binding_audit
BEGIN SELECT RAISE(ABORT, 'access binding audit is immutable'); END;
CREATE TRIGGER access_email_binding_audit_no_delete BEFORE DELETE ON access_email_binding_audit
BEGIN SELECT RAISE(ABORT, 'access binding audit is immutable'); END;
CREATE TRIGGER access_client_secret_audit_no_update BEFORE UPDATE ON access_client_secret_audit
BEGIN SELECT RAISE(ABORT, 'access client secret audit is immutable'); END;
CREATE TRIGGER access_client_secret_audit_no_delete BEFORE DELETE ON access_client_secret_audit
BEGIN SELECT RAISE(ABORT, 'access client secret audit is immutable'); END;
