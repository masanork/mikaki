-- Initial D1 schema for the OIDC authorization-code flow.
-- Times are UTC Unix seconds. Token and authorization-code values are stored
-- only as hashes; private signing material stays outside D1.
CREATE TABLE account_security (
  account_id TEXT PRIMARY KEY NOT NULL CHECK(length(account_id) BETWEEN 1 AND 128),
  epoch INTEGER NOT NULL CHECK(epoch >= 0),
  active INTEGER NOT NULL CHECK(active IN (0, 1))
) STRICT;

CREATE TABLE credential (
  credential_id TEXT PRIMARY KEY NOT NULL CHECK(length(credential_id) BETWEEN 1 AND 512),
  account_id TEXT NOT NULL REFERENCES account_security(account_id),
  active INTEGER NOT NULL CHECK(active IN (0, 1)),
  UNIQUE(credential_id, account_id)
) STRICT;

CREATE TABLE client (
  client_id TEXT PRIMARY KEY NOT NULL CHECK(length(client_id) BETWEEN 1 AND 128),
  revision INTEGER NOT NULL CHECK(revision >= 0),
  active INTEGER NOT NULL CHECK(active IN (0, 1)),
  sector_identifier TEXT NOT NULL CHECK(length(sector_identifier) BETWEEN 1 AND 2048)
) STRICT;

-- Redirect URIs are exact static registrations. Authorization codes reference
-- this table so a code cannot be issued for a request-supplied callback.
CREATE TABLE client_redirect_uri (
  client_id TEXT NOT NULL REFERENCES client(client_id),
  redirect_uri TEXT NOT NULL CHECK(length(redirect_uri) BETWEEN 1 AND 2048),
  PRIMARY KEY(client_id, redirect_uri)
) STRICT;

-- Pairwise subjects remain stable for an account within a registered sector.
CREATE TABLE pairwise_subject (
  account_id TEXT NOT NULL REFERENCES account_security(account_id),
  sector_identifier TEXT NOT NULL CHECK(length(sector_identifier) BETWEEN 1 AND 2048),
  sub TEXT NOT NULL UNIQUE CHECK(length(sub) BETWEEN 1 AND 255),
  PRIMARY KEY(account_id, sector_identifier)
) STRICT;

CREATE TABLE client_key (
  client_id TEXT NOT NULL REFERENCES client(client_id),
  kid TEXT NOT NULL CHECK(length(kid) BETWEEN 1 AND 128),
  revision INTEGER NOT NULL CHECK(revision >= 0),
  active INTEGER NOT NULL CHECK(active IN (0, 1)),
  algorithm TEXT NOT NULL CHECK(algorithm = 'ES256'),
  public_key_sec1 BLOB NOT NULL
    CHECK(typeof(public_key_sec1) = 'blob' AND length(public_key_sec1) IN (33, 65)),
  PRIMARY KEY(client_id, kid)
) STRICT;

CREATE TABLE signing_key (
  kid TEXT PRIMARY KEY NOT NULL CHECK(length(kid) BETWEEN 1 AND 128),
  generation INTEGER NOT NULL CHECK(generation >= 0),
  active INTEGER NOT NULL CHECK(active IN (0, 1)),
  algorithm TEXT NOT NULL CHECK(algorithm IN ('ES256', 'RS256')),
  public_jwk TEXT NOT NULL CHECK(length(public_jwk) BETWEEN 1 AND 2048)
) STRICT;

CREATE TABLE app_connection (
  account_id TEXT NOT NULL REFERENCES account_security(account_id),
  client_id TEXT NOT NULL REFERENCES client(client_id),
  grant_version INTEGER NOT NULL CHECK(grant_version >= 0),
  active INTEGER NOT NULL CHECK(active IN (0, 1)),
  PRIMARY KEY(account_id, client_id)
) STRICT;

CREATE TABLE sso_session (
  sso_id TEXT PRIMARY KEY NOT NULL CHECK(length(sso_id) BETWEEN 1 AND 128),
  account_id TEXT NOT NULL REFERENCES account_security(account_id),
  credential_id TEXT NOT NULL,
  epoch INTEGER NOT NULL CHECK(epoch >= 0),
  expires_at INTEGER NOT NULL CHECK(expires_at > 0),
  revoked INTEGER NOT NULL CHECK(revoked IN (0, 1)),
  FOREIGN KEY(credential_id, account_id) REFERENCES credential(credential_id, account_id),
  UNIQUE(sso_id, account_id)
) STRICT;

CREATE TABLE sso_context (
  sso_id TEXT PRIMARY KEY NOT NULL REFERENCES sso_session(sso_id),
  secret_hash TEXT NOT NULL UNIQUE CHECK(length(secret_hash) BETWEEN 1 AND 128),
  auth_time INTEGER NOT NULL CHECK(auth_time > 0)
) STRICT;

CREATE TABLE client_session (
  client_id TEXT NOT NULL,
  sid TEXT NOT NULL CHECK(length(sid) BETWEEN 1 AND 128),
  sso_id TEXT NOT NULL,
  account_id TEXT NOT NULL,
  sub TEXT NOT NULL CHECK(length(sub) BETWEEN 1 AND 255),
  grant_version INTEGER NOT NULL CHECK(grant_version >= 0),
  revoked INTEGER NOT NULL CHECK(revoked IN (0, 1)),
  PRIMARY KEY(client_id, sid),
  FOREIGN KEY(sso_id, account_id) REFERENCES sso_session(sso_id, account_id),
  FOREIGN KEY(account_id, client_id) REFERENCES app_connection(account_id, client_id)
) STRICT;

CREATE TABLE authorization_code (
  code_hash TEXT PRIMARY KEY NOT NULL CHECK(length(code_hash) = 43),
  client_id TEXT NOT NULL,
  sid TEXT NOT NULL,
  client_revision INTEGER NOT NULL CHECK(client_revision >= 0),
  redirect_uri TEXT NOT NULL CHECK(length(redirect_uri) BETWEEN 1 AND 2048),
  pkce_challenge TEXT NOT NULL CHECK(length(pkce_challenge) = 43),
  expires_at INTEGER NOT NULL CHECK(expires_at > 0),
  consumed_by TEXT UNIQUE,
  consumed_at INTEGER,
  FOREIGN KEY(client_id, sid) REFERENCES client_session(client_id, sid),
  FOREIGN KEY(client_id, redirect_uri)
    REFERENCES client_redirect_uri(client_id, redirect_uri),
  CHECK((consumed_by IS NULL) = (consumed_at IS NULL))
) STRICT;

CREATE TABLE code_context (
  code_hash TEXT PRIMARY KEY NOT NULL REFERENCES authorization_code(code_hash),
  nonce TEXT NOT NULL CHECK(length(nonce) BETWEEN 1 AND 512)
) STRICT;

CREATE TABLE assertion_use (
  client_id TEXT NOT NULL REFERENCES client(client_id),
  jti TEXT NOT NULL CHECK(length(jti) BETWEEN 1 AND 256),
  endpoint TEXT NOT NULL CHECK(length(endpoint) BETWEEN 1 AND 2048),
  accepted_by TEXT NOT NULL UNIQUE CHECK(length(accepted_by) BETWEEN 1 AND 128),
  retain_until INTEGER NOT NULL CHECK(retain_until > 0),
  PRIMARY KEY(client_id, jti)
) STRICT;

CREATE TABLE token_issue (
  code_hash TEXT PRIMARY KEY NOT NULL REFERENCES authorization_code(code_hash),
  operation_id TEXT NOT NULL UNIQUE CHECK(length(operation_id) BETWEEN 1 AND 128),
  access_hash TEXT NOT NULL UNIQUE CHECK(length(access_hash) = 43),
  access_expires_at INTEGER NOT NULL CHECK(access_expires_at > 0),
  signing_kid TEXT NOT NULL REFERENCES signing_key(kid),
  issued_at INTEGER NOT NULL CHECK(issued_at > 0),
  revoked INTEGER NOT NULL CHECK(revoked IN (0, 1))
) STRICT;

CREATE TABLE revocation_event (
  operation_id TEXT PRIMARY KEY NOT NULL CHECK(length(operation_id) BETWEEN 1 AND 128),
  account_id TEXT NOT NULL REFERENCES account_security(account_id),
  through_epoch INTEGER NOT NULL CHECK(through_epoch >= 0),
  created_at INTEGER NOT NULL CHECK(created_at > 0)
) STRICT;

-- A failed guard violates CHECK and makes the entire D1 batch roll back.
CREATE TABLE atomic_guard (
  operation_id TEXT PRIMARY KEY NOT NULL CHECK(length(operation_id) BETWEEN 1 AND 128),
  passed INTEGER NOT NULL CHECK(passed = 1)
) STRICT;

CREATE INDEX client_session_sso ON client_session(sso_id, client_id, sid);
CREATE INDEX sso_account_epoch ON sso_session(account_id, epoch);
CREATE INDEX assertion_gc ON assertion_use(retain_until);

-- Code exchange preconditions. A row here alone does not imply an authenticated session.
CREATE VIEW eligible_client_session AS
SELECT cs.client_id, cs.sid, cs.sub, ss.expires_at, ss.account_id
FROM client_session cs
JOIN sso_session ss ON ss.sso_id = cs.sso_id AND ss.account_id = cs.account_id
JOIN account_security a ON a.account_id = ss.account_id
JOIN credential cr ON cr.credential_id = ss.credential_id AND cr.account_id = a.account_id
JOIN client c ON c.client_id = cs.client_id
JOIN app_connection g ON g.account_id = cs.account_id AND g.client_id = cs.client_id
WHERE a.active = 1 AND a.epoch = ss.epoch AND cr.active = 1
  AND c.active = 1 AND g.active = 1 AND g.grant_version = cs.grant_version
  AND ss.revoked = 0 AND cs.revoked = 0
  AND ss.expires_at > CAST(strftime('%s', 'now') AS INTEGER);

-- Token issuance evidence keeps the client session valid after access-token expiry.
CREATE VIEW valid_client_session AS
SELECT v.* FROM eligible_client_session v
WHERE EXISTS (
  SELECT 1 FROM authorization_code ac JOIN token_issue ti ON ti.code_hash = ac.code_hash
  WHERE ac.client_id = v.client_id AND ac.sid = v.sid
    AND ac.consumed_by = ti.operation_id AND ac.consumed_at IS NOT NULL AND ti.revoked = 0
);
