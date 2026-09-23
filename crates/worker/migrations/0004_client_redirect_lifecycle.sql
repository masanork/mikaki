-- Preserve redirect rows referenced by issued codes while allowing operators
-- to stop new authorizations and invalidate in-flight client revisions.
ALTER TABLE client_redirect_uri
  ADD COLUMN active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0, 1));

CREATE TABLE client_admin_audit_v2 (
  operation_id TEXT PRIMARY KEY NOT NULL,
  client_id TEXT NOT NULL,
  action TEXT NOT NULL CHECK(action IN (
    'register', 'add-key', 'retire-key', 'add-redirect', 'retire-redirect', 'disable'
  )),
  actor TEXT NOT NULL,
  reason TEXT NOT NULL,
  occurred_at INTEGER NOT NULL CHECK(occurred_at > 0)
) STRICT;

INSERT INTO client_admin_audit_v2
  SELECT operation_id,client_id,action,actor,reason,occurred_at FROM client_admin_audit;
DROP TABLE client_admin_audit;
ALTER TABLE client_admin_audit_v2 RENAME TO client_admin_audit;
