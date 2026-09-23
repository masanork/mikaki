CREATE TABLE client_admin_audit (
  operation_id TEXT PRIMARY KEY NOT NULL,
  client_id TEXT NOT NULL,
  action TEXT NOT NULL CHECK(action IN ('register', 'add-key', 'retire-key', 'disable')),
  actor TEXT NOT NULL,
  reason TEXT NOT NULL,
  occurred_at INTEGER NOT NULL CHECK(occurred_at > 0)
) STRICT;
