-- Credential addition is owner/session-bound, distinct from invitation enrollment.
CREATE TABLE owner_passkey_registration (
  transaction_id TEXT PRIMARY KEY CHECK(length(transaction_id)=43),
  account_id TEXT NOT NULL REFERENCES account_security(account_id),
  session_hash TEXT NOT NULL,
  challenge TEXT NOT NULL,
  user_handle TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  failures INTEGER NOT NULL DEFAULT 0 CHECK(failures BETWEEN 0 AND 5),
  credential_id TEXT,
  request_hash TEXT,
  consumed INTEGER NOT NULL DEFAULT 0 CHECK(consumed IN(0,1))
) STRICT;
CREATE INDEX owner_passkey_registration_expiry ON owner_passkey_registration(expires_at);

CREATE TABLE vault_passkey_transfer_audit (
  account_id TEXT NOT NULL REFERENCES account_security(account_id),
  operation_id TEXT NOT NULL,
  attribute_id TEXT NOT NULL,
  result_revision INTEGER NOT NULL,
  target_credential_id TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY(account_id,operation_id),
  FOREIGN KEY(account_id,operation_id) REFERENCES vault_attribute_mutation(account_id,operation_id) ON DELETE CASCADE
) STRICT;
