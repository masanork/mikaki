-- Isolated v2 owner records. No v1 import, recipient authority or key rotation.
CREATE UNIQUE INDEX vault_owner_key_identity ON vault_owner_key_head(account_id,vault_id);

CREATE TABLE vault_owner_record_head (
  account_id TEXT NOT NULL,
  vault_id TEXT NOT NULL,
  collection_id TEXT NOT NULL CHECK(length(collection_id) BETWEEN 1 AND 128),
  record_id TEXT NOT NULL CHECK(length(record_id) BETWEEN 1 AND 128),
  kind TEXT NOT NULL CHECK(length(kind) BETWEEN 1 AND 128),
  revision INTEGER NOT NULL CHECK(revision BETWEEN 1 AND 9007199254740991),
  key_generation INTEGER NOT NULL CHECK(key_generation BETWEEN 1 AND 9007199254740991),
  format_version INTEGER NOT NULL CHECK(format_version=2),
  object_key TEXT,
  ciphertext_sha256 TEXT,
  key_envelope TEXT,
  deleted INTEGER NOT NULL CHECK(deleted IN (0,1)),
  updated_at INTEGER NOT NULL,
  PRIMARY KEY(account_id,vault_id,collection_id,record_id),
  FOREIGN KEY(account_id,vault_id) REFERENCES vault_owner_key_head(account_id,vault_id),
  CHECK((deleted=1 AND object_key IS NULL AND ciphertext_sha256 IS NULL AND key_envelope IS NULL)
    OR (deleted=0 AND object_key IS NOT NULL AND ciphertext_sha256 IS NOT NULL AND key_envelope IS NOT NULL AND length(ciphertext_sha256)=43 AND length(key_envelope)=82))
) STRICT;
CREATE UNIQUE INDEX vault_owner_record_object ON vault_owner_record_head(object_key) WHERE object_key IS NOT NULL;

CREATE TABLE vault_owner_record_mutation (
  account_id TEXT NOT NULL REFERENCES account_security(account_id),
  operation_id TEXT NOT NULL CHECK(length(operation_id)=43),
  request_hash TEXT NOT NULL CHECK(length(request_hash)=43),
  result_revision INTEGER NOT NULL CHECK(result_revision BETWEEN 1 AND 9007199254740991),
  deleted INTEGER NOT NULL CHECK(deleted IN (0,1)),
  created_at INTEGER NOT NULL,
  PRIMARY KEY(account_id,operation_id)
) STRICT;
CREATE INDEX vault_owner_record_rate ON vault_owner_record_mutation(account_id,created_at);
CREATE INDEX vault_owner_record_retention ON vault_owner_record_mutation(created_at);

CREATE TABLE vault_owner_record_gc_cursor (
  id INTEGER PRIMARY KEY CHECK(id=1),
  cursor TEXT
) STRICT;
INSERT INTO vault_owner_record_gc_cursor VALUES(1,NULL);
