-- Public directory only. The matching ML-KEM private seed belongs to the
-- dedicated UserInfo claim worker's protected secret binding, never D1/R2.
-- No row is activated by this migration.
CREATE TABLE vault_recipient_key (
  key_id TEXT PRIMARY KEY CHECK(length(key_id) = 43),
  service_id TEXT NOT NULL CHECK(service_id = 'userinfo'),
  algorithm TEXT NOT NULL CHECK(algorithm = 'ML-KEM-768'),
  public_key BLOB NOT NULL CHECK(length(public_key) = 1184),
  secret_ref TEXT NOT NULL UNIQUE CHECK(length(secret_ref) BETWEEN 1 AND 128),
  generation INTEGER NOT NULL CHECK(generation > 0),
  state TEXT NOT NULL CHECK(state IN ('staged', 'active', 'decrypt_only', 'disabled')),
  revision INTEGER NOT NULL CHECK(revision > 0),
  created_at INTEGER NOT NULL CHECK(created_at > 0),
  activated_at INTEGER CHECK(activated_at > 0),
  retired_at INTEGER CHECK(retired_at > 0),
  UNIQUE(service_id, generation),
  CHECK((state = 'staged' AND activated_at IS NULL AND retired_at IS NULL)
     OR (state = 'active' AND activated_at IS NOT NULL AND retired_at IS NULL)
     OR (state = 'decrypt_only' AND activated_at IS NOT NULL AND retired_at IS NOT NULL)
     OR (state = 'disabled' AND retired_at IS NOT NULL))
) STRICT;

CREATE UNIQUE INDEX vault_recipient_one_active
  ON vault_recipient_key(service_id) WHERE state = 'active';

CREATE TRIGGER vault_recipient_key_insert BEFORE INSERT ON vault_recipient_key
WHEN NEW.state != 'staged' OR NEW.revision != 1
  OR NEW.activated_at IS NOT NULL OR NEW.retired_at IS NOT NULL
BEGIN SELECT RAISE(ABORT, 'vault recipient key must start staged'); END;

CREATE TRIGGER vault_recipient_key_immutable BEFORE UPDATE ON vault_recipient_key
WHEN NEW.key_id != OLD.key_id OR NEW.service_id != OLD.service_id
  OR NEW.algorithm != OLD.algorithm OR NEW.public_key != OLD.public_key
  OR NEW.secret_ref != OLD.secret_ref OR NEW.generation != OLD.generation
  OR NEW.created_at != OLD.created_at
  OR (OLD.activated_at IS NOT NULL AND NEW.activated_at IS NOT OLD.activated_at)
  OR (OLD.retired_at IS NOT NULL AND NEW.retired_at IS NOT OLD.retired_at)
BEGIN SELECT RAISE(ABORT, 'vault recipient key identity is immutable'); END;

CREATE TRIGGER vault_recipient_key_transition BEFORE UPDATE ON vault_recipient_key
WHEN NEW.revision != OLD.revision + 1
  OR NOT ((OLD.state = 'staged' AND NEW.state IN ('active', 'disabled'))
       OR (OLD.state = 'active' AND NEW.state IN ('decrypt_only', 'disabled'))
       OR (OLD.state = 'decrypt_only' AND NEW.state = 'disabled'))
  OR (OLD.state = 'staged' AND NEW.activated_at IS NOT NULL AND NEW.activated_at < OLD.created_at)
  OR (NEW.state IN ('decrypt_only', 'disabled') AND NEW.retired_at IS NOT NULL
      AND NEW.retired_at < COALESCE(NEW.activated_at, OLD.created_at))
BEGIN SELECT RAISE(ABORT, 'invalid vault recipient key transition'); END;

CREATE TRIGGER vault_recipient_key_no_delete BEFORE DELETE ON vault_recipient_key
BEGIN SELECT RAISE(ABORT, 'vault recipient key history cannot be deleted'); END;

CREATE TABLE vault_recipient_key_audit (
  operation_id TEXT PRIMARY KEY NOT NULL,
  key_id TEXT NOT NULL REFERENCES vault_recipient_key(key_id),
  action TEXT NOT NULL CHECK(action IN ('stage', 'activate', 'rotate', 'disable')),
  actor TEXT NOT NULL CHECK(length(actor) BETWEEN 1 AND 128),
  reason TEXT NOT NULL CHECK(length(reason) BETWEEN 1 AND 512),
  revision INTEGER NOT NULL CHECK(revision > 0),
  occurred_at INTEGER NOT NULL CHECK(occurred_at > 0)
) STRICT;

-- A failed compare-and-swap aborts the whole D1 batch, including its audit rows.
CREATE TABLE vault_recipient_atomic_guard (
  operation_id TEXT PRIMARY KEY,
  passed INTEGER NOT NULL CHECK(passed = 1)
) STRICT;
