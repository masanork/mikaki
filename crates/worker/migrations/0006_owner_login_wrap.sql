-- Same-credential supplemental custody of the existing root. This does not
-- change the root generation, registry revision, record ciphertext or grants.
CREATE TABLE vault_owner_login_wrap (
  account_id TEXT NOT NULL,
  key_generation INTEGER NOT NULL,
  credential_id TEXT NOT NULL,
  envelope TEXT NOT NULL CHECK(length(envelope) BETWEEN 1 AND 2048),
  PRIMARY KEY(account_id,key_generation,credential_id),
  FOREIGN KEY(account_id,key_generation,credential_id)
    REFERENCES vault_owner_key_wrap(account_id,key_generation,credential_id) ON DELETE CASCADE
) STRICT;

CREATE TRIGGER vault_owner_login_wrap_no_update BEFORE UPDATE ON vault_owner_login_wrap
BEGIN SELECT RAISE(ABORT,'login wrapper is immutable'); END;
