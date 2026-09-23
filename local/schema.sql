-- LOCAL slice extension to design/sql/oidc-critical-schema.sql; not a production migration.
CREATE TABLE bootstrap (singleton INTEGER PRIMARY KEY CHECK(singleton=1), closed INTEGER NOT NULL CHECK(closed IN (0,1)));
INSERT INTO bootstrap VALUES(1,0);
CREATE TABLE invitation (hash TEXT PRIMARY KEY, kind TEXT NOT NULL CHECK(kind IN ('bootstrap','ordinary')), expires_at INTEGER NOT NULL, used_by TEXT UNIQUE);
CREATE TABLE account_role (account_id TEXT PRIMARY KEY REFERENCES account_security, role TEXT NOT NULL CHECK(role='admin'));
CREATE TABLE credential_data (credential_id TEXT PRIMARY KEY REFERENCES credential, public_key TEXT NOT NULL, user_handle TEXT NOT NULL, counter INTEGER NOT NULL, backup_eligible INTEGER NOT NULL, backup_state INTEGER NOT NULL, revision INTEGER NOT NULL);
CREATE TABLE sso_context (sso_id TEXT PRIMARY KEY REFERENCES sso_session, secret_hash TEXT NOT NULL UNIQUE, auth_time INTEGER NOT NULL);
CREATE TABLE subject (account_id TEXT NOT NULL REFERENCES account_security, sector TEXT NOT NULL, sub TEXT NOT NULL UNIQUE, PRIMARY KEY(account_id,sector));
CREATE TABLE op_login (id TEXT PRIMARY KEY, browser_hash TEXT NOT NULL, csrf TEXT NOT NULL, request TEXT NOT NULL, expires_at INTEGER NOT NULL, gc_after INTEGER NOT NULL, consumed INTEGER NOT NULL DEFAULT 0);
CREATE TABLE ceremony (id TEXT PRIMARY KEY, login_id TEXT NOT NULL REFERENCES op_login, purpose TEXT NOT NULL, challenge TEXT NOT NULL, account_id TEXT, invitation_hash TEXT REFERENCES invitation(hash), browser_hash TEXT NOT NULL, expires_at INTEGER NOT NULL, gc_after INTEGER NOT NULL, failures INTEGER NOT NULL DEFAULT 0, consumed INTEGER NOT NULL DEFAULT 0);
CREATE TABLE code_context (code_hash TEXT PRIMARY KEY REFERENCES authorization_code, nonce TEXT NOT NULL);
CREATE TABLE sso_logout_event (
  id TEXT PRIMARY KEY, sso_id TEXT NOT NULL UNIQUE REFERENCES sso_session,
  created_at INTEGER NOT NULL, deadline INTEGER NOT NULL, gc_after INTEGER NOT NULL,
  expanded INTEGER NOT NULL DEFAULT 0 CHECK(expanded IN (0,1)),
  revision INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE logout_delivery (
  id INTEGER PRIMARY KEY, event_id TEXT NOT NULL REFERENCES sso_logout_event,
  client_id TEXT NOT NULL, sid TEXT NOT NULL, created_at INTEGER NOT NULL, deadline INTEGER NOT NULL,
  state TEXT NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','leased','delivered','failed','expired')),
  attempts INTEGER NOT NULL DEFAULT 0, next_at INTEGER NOT NULL,
  lease TEXT, lease_until INTEGER, last_status INTEGER, reason TEXT, finished_at INTEGER, gc_after INTEGER,
  UNIQUE(event_id,client_id,sid),
  CHECK((state='leased') = (lease IS NOT NULL AND lease_until IS NOT NULL))
);
CREATE INDEX logout_delivery_due ON logout_delivery(state,next_at);
CREATE INDEX logout_delivery_client_lease ON logout_delivery(client_id,state,lease_until);
CREATE TABLE logout_transaction (csrf_hash TEXT PRIMARY KEY, browser_hash TEXT NOT NULL, sso_id TEXT NOT NULL REFERENCES sso_session, state TEXT NOT NULL, expires_at INTEGER NOT NULL, gc_after INTEGER NOT NULL);
CREATE TABLE rate_window (bucket TEXT PRIMARY KEY, count INTEGER NOT NULL, gc_after INTEGER NOT NULL);
ALTER TABLE assertion_use ADD COLUMN gc_after INTEGER;
CREATE INDEX gc_ceremony ON ceremony(gc_after);
CREATE INDEX gc_op_login ON op_login(gc_after);
CREATE INDEX gc_logout_transaction ON logout_transaction(gc_after);
CREATE INDEX gc_rate_window ON rate_window(gc_after);
CREATE INDEX gc_assertion_use ON assertion_use(gc_after);

ALTER TABLE sso_session ADD COLUMN gc_after INTEGER;
CREATE INDEX gc_sso_session ON sso_session(gc_after);
CREATE INDEX gc_logout_event ON sso_logout_event(gc_after);
CREATE INDEX gc_logout_delivery ON logout_delivery(gc_after);

-- Independent audit survives event GC; target identifiers are restricted operator data.
CREATE TABLE logout_retry_audit (
  operation_id TEXT PRIMARY KEY, event_id TEXT NOT NULL, revision INTEGER NOT NULL,
  actor TEXT NOT NULL, reason TEXT NOT NULL, created_at INTEGER NOT NULL,
  old_deadline INTEGER NOT NULL, new_deadline INTEGER NOT NULL, retain_until INTEGER NOT NULL,
  targets TEXT NOT NULL, gc_after INTEGER NOT NULL, UNIQUE(event_id,revision)
);
CREATE INDEX gc_logout_retry_audit ON logout_retry_audit(gc_after);

ALTER TABLE revocation_event ADD COLUMN actor TEXT;
ALTER TABLE revocation_event ADD COLUMN reason TEXT;
ALTER TABLE revocation_event ADD COLUMN deadline INTEGER;
ALTER TABLE revocation_event ADD COLUMN gc_after INTEGER;
ALTER TABLE revocation_event ADD COLUMN expanded INTEGER NOT NULL DEFAULT 0;
CREATE INDEX account_revocation_pending ON revocation_event(account_id,expanded,through_epoch);
CREATE INDEX gc_account_revocation ON revocation_event(gc_after);
