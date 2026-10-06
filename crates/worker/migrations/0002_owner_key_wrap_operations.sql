-- Additive receipt/audit only. Parent keys and record ciphertext are unchanged.
CREATE TABLE vault_owner_key_wrap_operation (
  account_id TEXT NOT NULL REFERENCES account_security(account_id),
  operation_id TEXT NOT NULL CHECK(length(operation_id)=43),
  request_hash TEXT NOT NULL CHECK(length(request_hash)=43),
  action TEXT NOT NULL CHECK(action IN ('add','remove')),
  source_credential_id TEXT NOT NULL CHECK(length(source_credential_id) BETWEEN 1 AND 683),
  credential_id TEXT NOT NULL CHECK(length(credential_id) BETWEEN 1 AND 683),
  vault_id TEXT NOT NULL CHECK(length(vault_id) BETWEEN 1 AND 128),
  key_generation INTEGER NOT NULL CHECK(key_generation BETWEEN 1 AND 9007199254740991),
  previous_revision INTEGER NOT NULL CHECK(previous_revision BETWEEN 1 AND 9007199254740990),
  revision INTEGER NOT NULL CHECK(revision=previous_revision+1),
  created_at INTEGER NOT NULL CHECK(created_at>0),
  PRIMARY KEY(account_id,operation_id)
) STRICT;
CREATE INDEX vault_owner_key_wrap_operation_recent
ON vault_owner_key_wrap_operation(account_id,created_at);
CREATE TRIGGER vault_owner_key_wrap_operation_no_update
BEFORE UPDATE ON vault_owner_key_wrap_operation
BEGIN SELECT RAISE(ABORT,'owner wrapper receipt is immutable'); END;
CREATE TRIGGER vault_owner_key_wrap_operation_no_delete
BEFORE DELETE ON vault_owner_key_wrap_operation
BEGIN SELECT RAISE(ABORT,'owner wrapper receipt is immutable'); END;
