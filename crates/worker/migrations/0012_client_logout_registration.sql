-- Logout destinations are exact, operator-managed HTTPS registrations.
CREATE TABLE client_post_logout_redirect_uri (
  client_id TEXT NOT NULL REFERENCES client(client_id),
  redirect_uri TEXT NOT NULL CHECK(length(redirect_uri) BETWEEN 1 AND 2048),
  active INTEGER NOT NULL CHECK(active IN (0, 1)),
  PRIMARY KEY(client_id, redirect_uri)
) STRICT;

CREATE TABLE client_backchannel_logout_uri (
  client_id TEXT PRIMARY KEY NOT NULL REFERENCES client(client_id),
  logout_uri TEXT NOT NULL CHECK(length(logout_uri) BETWEEN 1 AND 2048),
  active INTEGER NOT NULL CHECK(active IN (0, 1))
) STRICT;

CREATE TABLE client_admin_audit_v3 (
  operation_id TEXT PRIMARY KEY NOT NULL,
  client_id TEXT NOT NULL,
  action TEXT NOT NULL CHECK(action IN (
    'register', 'add-key', 'retire-key', 'add-redirect', 'retire-redirect',
    'add-post-logout-redirect', 'retire-post-logout-redirect',
    'set-backchannel-logout', 'retire-backchannel-logout', 'disable'
  )),
  actor TEXT NOT NULL,
  reason TEXT NOT NULL,
  occurred_at INTEGER NOT NULL CHECK(occurred_at > 0)
) STRICT;

INSERT INTO client_admin_audit_v3
  SELECT operation_id,client_id,action,actor,reason,occurred_at FROM client_admin_audit;
DROP TABLE client_admin_audit;
ALTER TABLE client_admin_audit_v3 RENAME TO client_admin_audit;
