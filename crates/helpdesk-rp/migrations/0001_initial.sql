CREATE TABLE login_transaction (
  state_hash TEXT PRIMARY KEY,
  browser_hash TEXT NOT NULL,
  nonce TEXT NOT NULL,
  verifier TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE TABLE rp_session (
  token_hash TEXT PRIMARY KEY,
  sid TEXT NOT NULL,
  sub TEXT NOT NULL,
  auth_time INTEGER NOT NULL,
  lease_until INTEGER NOT NULL,
  parent_expires_at INTEGER NOT NULL,
  idle_expires_at INTEGER NOT NULL
);
CREATE TABLE staff (sub TEXT PRIMARY KEY);
CREATE TABLE ticket (
  id TEXT PRIMARY KEY,
  owner_sub TEXT NOT NULL,
  title TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','closed')),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE ticket_message (
  id TEXT PRIMARY KEY,
  ticket_id TEXT NOT NULL REFERENCES ticket(id),
  author_sub TEXT NOT NULL,
  body TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX ticket_owner_recent ON ticket(owner_sub, updated_at DESC);
CREATE INDEX ticket_recent ON ticket(updated_at DESC);
CREATE INDEX ticket_message_order ON ticket_message(ticket_id, created_at, id);
CREATE INDEX rp_session_expiry ON rp_session(parent_expires_at);
