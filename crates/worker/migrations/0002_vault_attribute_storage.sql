-- Owner-only encrypted attribute snapshots. R2 holds immutable ciphertext;
-- D1 is the authoritative head and retry ledger. No plaintext claims live here.
CREATE TABLE vault_attribute_head (
  account_id TEXT NOT NULL REFERENCES account_security(account_id),
  attribute_id TEXT NOT NULL CHECK(length(attribute_id) BETWEEN 1 AND 64),
  revision INTEGER NOT NULL CHECK(revision > 0),
  format_version INTEGER NOT NULL CHECK(format_version = 1),
  object_key TEXT,
  ciphertext_sha256 TEXT,
  owner_envelope TEXT,
  deleted INTEGER NOT NULL CHECK(deleted IN (0, 1)),
  updated_at INTEGER NOT NULL CHECK(updated_at > 0),
  PRIMARY KEY(account_id, attribute_id),
  CHECK((deleted = 1 AND object_key IS NULL AND ciphertext_sha256 IS NULL AND owner_envelope IS NULL)
     OR (deleted = 0 AND object_key IS NOT NULL AND ciphertext_sha256 IS NOT NULL AND owner_envelope IS NOT NULL))
) STRICT;

CREATE TABLE vault_attribute_mutation (
  account_id TEXT NOT NULL REFERENCES account_security(account_id),
  operation_id TEXT NOT NULL CHECK(length(operation_id) = 43),
  request_hash TEXT NOT NULL CHECK(length(request_hash) = 43),
  attribute_id TEXT NOT NULL,
  result_revision INTEGER NOT NULL CHECK(result_revision > 0),
  deleted INTEGER NOT NULL CHECK(deleted IN (0, 1)),
  created_at INTEGER NOT NULL CHECK(created_at > 0),
  PRIMARY KEY(account_id, operation_id)
) STRICT;
