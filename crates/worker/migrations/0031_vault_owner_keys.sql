-- New Vaults only. Ciphertext wrappers and public routing metadata; no PRF/root bytes.
CREATE TABLE vault_owner_key_head (
  account_id TEXT PRIMARY KEY NOT NULL REFERENCES account_security(account_id),
  vault_id TEXT NOT NULL CHECK(length(vault_id) BETWEEN 1 AND 128),
  origin TEXT NOT NULL,
  key_generation INTEGER NOT NULL CHECK(key_generation BETWEEN 1 AND 9007199254740991),
  revision INTEGER NOT NULL CHECK(revision BETWEEN 1 AND 9007199254740991),
  format_version INTEGER NOT NULL CHECK(format_version=2),
  suite TEXT NOT NULL,
  operation_id TEXT NOT NULL CHECK(length(operation_id)=43),
  request_hash TEXT NOT NULL CHECK(length(request_hash)=43),
  created_at INTEGER NOT NULL,
  UNIQUE(account_id,key_generation)
) STRICT;

CREATE TABLE vault_owner_key_wrap (
  account_id TEXT NOT NULL,
  key_generation INTEGER NOT NULL,
  credential_id TEXT NOT NULL,
  envelope TEXT NOT NULL CHECK(length(envelope) BETWEEN 1 AND 2048),
  PRIMARY KEY(account_id,key_generation,credential_id),
  FOREIGN KEY(account_id,key_generation) REFERENCES vault_owner_key_head(account_id,key_generation),
  FOREIGN KEY(credential_id,account_id) REFERENCES credential(credential_id,account_id)
) STRICT;
