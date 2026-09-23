-- Registration is bound to an existing login transaction and browser cookie.
-- Invite secrets are never stored, only their SHA-256 base64url verifiers.
-- The internal client has no redirect URI or key, so it cannot use OIDC
-- authorization or token exchange. It only satisfies the login transaction FK.
INSERT INTO client(client_id,revision,active,auth_method,allow_missing_pkce,sector_identifier)
  VALUES('mikaki-internal-enrollment',1,1,'private_key_jwt',0,'mikaki.internal');

CREATE TABLE bootstrap_state (
  id INTEGER PRIMARY KEY NOT NULL CHECK(id = 1),
  closed INTEGER NOT NULL DEFAULT 0 CHECK(closed IN (0, 1))
) STRICT;
INSERT INTO bootstrap_state(id,closed) VALUES(1,0);

CREATE TABLE enrollment_policy (
  id INTEGER PRIMARY KEY NOT NULL CHECK(id = 1),
  bootstrap_ttl_seconds INTEGER NOT NULL CHECK(bootstrap_ttl_seconds BETWEEN 60 AND 86400),
  invite_ttl_seconds INTEGER NOT NULL CHECK(invite_ttl_seconds BETWEEN 3600 AND 604800),
  management_ttl_seconds INTEGER NOT NULL CHECK(management_ttl_seconds BETWEEN 60 AND 900),
  registration_ttl_seconds INTEGER NOT NULL CHECK(registration_ttl_seconds BETWEEN 60 AND 900),
  revision INTEGER NOT NULL CHECK(revision > 0)
) STRICT;
INSERT INTO enrollment_policy(id,bootstrap_ttl_seconds,invite_ttl_seconds,management_ttl_seconds,registration_ttl_seconds,revision)
  VALUES(1,900,86400,300,300,1);

CREATE TABLE account_role (
  account_id TEXT NOT NULL REFERENCES account_security(account_id),
  role TEXT NOT NULL CHECK(role = 'admin'),
  active INTEGER NOT NULL CHECK(active IN (0, 1)),
  PRIMARY KEY(account_id,role)
) STRICT;

CREATE TABLE enrollment_invite (
  invite_hash TEXT PRIMARY KEY NOT NULL CHECK(length(invite_hash) = 43),
  kind TEXT NOT NULL CHECK(kind IN ('bootstrap', 'normal')),
  issuer_account_id TEXT REFERENCES account_security(account_id),
  issued_at INTEGER NOT NULL CHECK(issued_at > 0),
  expires_at INTEGER NOT NULL CHECK(expires_at > issued_at),
  consumed_at INTEGER CHECK(consumed_at IS NULL OR consumed_at >= issued_at),
  revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0, 1)),
  CHECK((kind = 'bootstrap') = (issuer_account_id IS NULL))
) STRICT;
CREATE UNIQUE INDEX one_open_bootstrap_invite ON enrollment_invite(kind)
  WHERE kind='bootstrap' AND consumed_at IS NULL AND revoked=0;

CREATE TABLE enrollment_invite_audit (
  operation_id TEXT PRIMARY KEY NOT NULL,
  invite_hash TEXT NOT NULL REFERENCES enrollment_invite(invite_hash),
  action TEXT NOT NULL CHECK(action IN ('issue-bootstrap', 'issue-normal', 'revoke')),
  actor TEXT NOT NULL CHECK(length(actor) BETWEEN 1 AND 128),
  reason TEXT NOT NULL CHECK(length(reason) BETWEEN 1 AND 512),
  occurred_at INTEGER NOT NULL CHECK(occurred_at > 0)
) STRICT;
CREATE TRIGGER enrollment_invite_audit_no_update BEFORE UPDATE ON enrollment_invite_audit
BEGIN SELECT RAISE(ABORT, 'invite audit is immutable'); END;
CREATE TRIGGER enrollment_invite_audit_no_delete BEFORE DELETE ON enrollment_invite_audit
BEGIN SELECT RAISE(ABORT, 'invite audit is immutable'); END;

CREATE TABLE registration_transaction (
  tx_id TEXT PRIMARY KEY NOT NULL REFERENCES login_transaction(tx_id),
  browser_hash TEXT NOT NULL CHECK(length(browser_hash) = 43),
  invite_hash TEXT NOT NULL REFERENCES enrollment_invite(invite_hash),
  challenge TEXT NOT NULL CHECK(length(challenge) = 43),
  user_handle TEXT NOT NULL CHECK(length(user_handle) = 43),
  expires_at INTEGER NOT NULL CHECK(expires_at > 0),
  consumed INTEGER NOT NULL DEFAULT 0 CHECK(consumed IN (0, 1)),
  failures INTEGER NOT NULL DEFAULT 0 CHECK(failures BETWEEN 0 AND 5)
) STRICT;

CREATE TABLE admin_invitation_transaction (
  operation_id TEXT PRIMARY KEY NOT NULL CHECK(length(operation_id) = 43),
  account_id TEXT NOT NULL REFERENCES account_security(account_id),
  credential_id TEXT NOT NULL REFERENCES credential(credential_id),
  browser_hash TEXT NOT NULL CHECK(length(browser_hash) = 43),
  challenge TEXT NOT NULL CHECK(length(challenge) = 43),
  expires_at INTEGER NOT NULL CHECK(expires_at > 0),
  consumed INTEGER NOT NULL DEFAULT 0 CHECK(consumed IN (0, 1)),
  failures INTEGER NOT NULL DEFAULT 0 CHECK(failures BETWEEN 0 AND 5)
) STRICT;
