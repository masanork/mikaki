-- Local qualification only. This is not a production migration.
CREATE TABLE installation_pending (
  id TEXT PRIMARY KEY NOT NULL,
  owner TEXT NOT NULL,
  session_hash TEXT NOT NULL,
  credential_id TEXT NOT NULL,
  thumbprint TEXT NOT NULL,
  nonce TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  consumed INTEGER NOT NULL DEFAULT 0 CHECK(consumed IN (0,1)),
  CHECK(expires_at > created_at AND expires_at <= created_at + 120)
) STRICT;
CREATE TABLE installation_proof_use (
  thumbprint TEXT NOT NULL,
  jti_hash TEXT NOT NULL,
  retain_until INTEGER NOT NULL,
  PRIMARY KEY(thumbprint,jti_hash)
) STRICT;
CREATE TABLE installation_device (
  id TEXT PRIMARY KEY NOT NULL,
  owner TEXT NOT NULL,
  thumbprint TEXT NOT NULL UNIQUE,
  state TEXT NOT NULL CHECK(state IN ('active','revoked')),
  created_at INTEGER NOT NULL
) STRICT;
