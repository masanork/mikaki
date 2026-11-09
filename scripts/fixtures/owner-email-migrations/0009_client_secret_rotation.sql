-- Audit immediate client-secret replacement without storing either secret.
CREATE TABLE client_secret_rotation_audit (
  operation_id TEXT PRIMARY KEY NOT NULL,
  client_id TEXT NOT NULL REFERENCES client(client_id),
  previous_revision INTEGER NOT NULL CHECK(previous_revision > 0),
  new_revision INTEGER NOT NULL CHECK(new_revision = previous_revision + 1),
  actor TEXT NOT NULL CHECK(length(actor) BETWEEN 1 AND 128),
  reason TEXT NOT NULL CHECK(length(reason) BETWEEN 1 AND 512),
  occurred_at INTEGER NOT NULL CHECK(occurred_at > 0)
) STRICT;

CREATE TRIGGER client_secret_rotation_audit_no_update BEFORE UPDATE ON client_secret_rotation_audit
BEGIN SELECT RAISE(ABORT, 'client secret audit is immutable'); END;
CREATE TRIGGER client_secret_rotation_audit_no_delete BEFORE DELETE ON client_secret_rotation_audit
BEGIN SELECT RAISE(ABORT, 'client secret audit is immutable'); END;
