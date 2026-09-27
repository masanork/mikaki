-- A confirmation is bound to the SSO cookie, exact registered return URI,
-- and a one-use CSRF value. The ID Token hint is never retained here.
CREATE TABLE logout_transaction (
  csrf_hash TEXT PRIMARY KEY NOT NULL CHECK(length(csrf_hash) = 43),
  sso_id TEXT NOT NULL REFERENCES sso_session(sso_id),
  cookie_hash TEXT NOT NULL CHECK(length(cookie_hash) = 43),
  redirect_uri TEXT NOT NULL CHECK(length(redirect_uri) <= 2048),
  state TEXT NOT NULL CHECK(length(state) <= 2048),
  expires_at INTEGER NOT NULL CHECK(expires_at > 0)
) STRICT;
CREATE INDEX logout_transaction_expiry ON logout_transaction(expires_at);

-- The event and its per-sid deliveries are committed with SSO revocation.
-- Delivery URLs are snapshotted so later registration rotation cannot redirect
-- a pending notification to a different endpoint.
CREATE TABLE sso_logout_event (
  event_id TEXT PRIMARY KEY NOT NULL CHECK(length(event_id) = 43),
  sso_id TEXT NOT NULL UNIQUE REFERENCES sso_session(sso_id),
  created_at INTEGER NOT NULL CHECK(created_at > 0),
  deadline INTEGER NOT NULL CHECK(deadline > created_at)
) STRICT;

CREATE TABLE logout_delivery (
  event_id TEXT NOT NULL REFERENCES sso_logout_event(event_id),
  client_id TEXT NOT NULL REFERENCES client(client_id),
  sid TEXT NOT NULL CHECK(length(sid) BETWEEN 1 AND 128),
  sub TEXT NOT NULL CHECK(length(sub) BETWEEN 1 AND 255),
  logout_uri TEXT NOT NULL CHECK(length(logout_uri) BETWEEN 1 AND 2048),
  state TEXT NOT NULL DEFAULT 'pending'
    CHECK(state IN ('pending', 'leased', 'delivered', 'failed', 'expired')),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
  next_at INTEGER NOT NULL CHECK(next_at > 0),
  lease_id TEXT,
  lease_until INTEGER,
  last_status INTEGER,
  finished_at INTEGER,
  PRIMARY KEY(event_id, client_id, sid),
  CHECK((state = 'leased') = (lease_id IS NOT NULL AND lease_until IS NOT NULL))
) STRICT;
CREATE INDEX logout_delivery_due ON logout_delivery(state, next_at);
