-- 実行可能な設計検証用の縮小schema。本番migrationではない。
-- 識別子・認証証拠・全endpointの実装は省略。時刻はUTC Unix秒。
PRAGMA foreign_keys = ON;
CREATE TABLE account_security (
  account_id TEXT PRIMARY KEY, epoch INTEGER NOT NULL CHECK(epoch >= 0),
  active INTEGER NOT NULL CHECK(active IN (0,1))
);
CREATE TABLE credential (
  credential_id TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES account_security,
  active INTEGER NOT NULL CHECK(active IN (0,1)), UNIQUE(credential_id, account_id)
);
CREATE TABLE client (
  client_id TEXT PRIMARY KEY, revision INTEGER NOT NULL,
  active INTEGER NOT NULL CHECK(active IN (0,1))
);
CREATE TABLE client_key (
  client_id TEXT NOT NULL REFERENCES client, kid TEXT NOT NULL,
  revision INTEGER NOT NULL, active INTEGER NOT NULL CHECK(active IN (0,1)),
  PRIMARY KEY(client_id, kid)
);
CREATE TABLE signing_key (
  kid TEXT PRIMARY KEY, generation INTEGER NOT NULL,
  active INTEGER NOT NULL CHECK(active IN (0,1))
);
CREATE TABLE app_connection (
  account_id TEXT NOT NULL REFERENCES account_security,
  client_id TEXT NOT NULL REFERENCES client, grant_version INTEGER NOT NULL,
  active INTEGER NOT NULL CHECK(active IN (0,1)),
  PRIMARY KEY(account_id, client_id)
);
CREATE TABLE sso_session (
  sso_id TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES account_security,
  credential_id TEXT NOT NULL, epoch INTEGER NOT NULL, expires_at INTEGER NOT NULL,
  revoked INTEGER NOT NULL CHECK(revoked IN (0,1)),
  FOREIGN KEY(credential_id, account_id) REFERENCES credential(credential_id, account_id),
  UNIQUE(sso_id, account_id)
);
CREATE TABLE client_session (
  client_id TEXT NOT NULL, sid TEXT NOT NULL, sso_id TEXT NOT NULL,
  account_id TEXT NOT NULL, sub TEXT NOT NULL, grant_version INTEGER NOT NULL,
  revoked INTEGER NOT NULL CHECK(revoked IN (0,1)),
  PRIMARY KEY(client_id, sid),
  FOREIGN KEY(sso_id, account_id) REFERENCES sso_session(sso_id, account_id),
  FOREIGN KEY(account_id, client_id) REFERENCES app_connection(account_id, client_id)
);
CREATE TABLE authorization_code (
  code_hash TEXT PRIMARY KEY, client_id TEXT NOT NULL, sid TEXT NOT NULL,
  client_revision INTEGER NOT NULL, redirect_uri TEXT NOT NULL,
  pkce_challenge TEXT NOT NULL, expires_at INTEGER NOT NULL,
  consumed_by TEXT UNIQUE, consumed_at INTEGER,
  FOREIGN KEY(client_id, sid) REFERENCES client_session(client_id, sid),
  CHECK((consumed_by IS NULL) = (consumed_at IS NULL))
);
CREATE TABLE assertion_use (
  client_id TEXT NOT NULL REFERENCES client, jti TEXT NOT NULL, endpoint TEXT NOT NULL,
  accepted_by TEXT NOT NULL UNIQUE, retain_until INTEGER NOT NULL,
  PRIMARY KEY(client_id, jti)
);
CREATE TABLE token_issue (
  code_hash TEXT PRIMARY KEY REFERENCES authorization_code, operation_id TEXT NOT NULL UNIQUE,
  access_hash TEXT NOT NULL UNIQUE, access_expires_at INTEGER NOT NULL,
  signing_kid TEXT NOT NULL REFERENCES signing_key,
  issued_at INTEGER NOT NULL, revoked INTEGER NOT NULL CHECK(revoked IN (0,1))
);
CREATE TABLE revocation_event (
  operation_id TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES account_security,
  through_epoch INTEGER NOT NULL, created_at INTEGER NOT NULL
);
CREATE TABLE atomic_guard (
  operation_id TEXT PRIMARY KEY, passed INTEGER NOT NULL CHECK(passed = 1)
);
CREATE INDEX client_session_sso ON client_session(sso_id, client_id, sid);
CREATE INDEX sso_account_epoch ON sso_session(account_id, epoch);
CREATE INDEX assertion_gc ON assertion_use(retain_until);
-- code交換の前提条件。これだけではログイン済みと扱わない。
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
  AND ss.expires_at > CAST(strftime('%s','now') AS INTEGER);
-- ID Token発行確定後に/session/checkが利用する有効状態。
-- Access Tokenの期限切れはアプリセッションの期限切れを意味しない。
CREATE VIEW valid_client_session AS
SELECT v.* FROM eligible_client_session v
WHERE EXISTS (
  SELECT 1 FROM authorization_code ac JOIN token_issue ti ON ti.code_hash=ac.code_hash
  WHERE ac.client_id=v.client_id AND ac.sid=v.sid AND ti.revoked=0
);
