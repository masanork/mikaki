-- Native app enrollment only. No raw Android certificates, device IDs or JWTs.
CREATE TABLE identity_attester_challenge (
  challenge_hash TEXT PRIMARY KEY NOT NULL,
  client_id TEXT NOT NULL,
  purpose TEXT NOT NULL CHECK(purpose IN ('client','holder')),
  policy_hash TEXT NOT NULL,
  client_binding TEXT,
  nonce_hash TEXT,
  expires_at INTEGER NOT NULL,
  used INTEGER NOT NULL DEFAULT 0 CHECK(used IN (0,1)),
  CHECK((purpose='client' AND client_binding IS NULL AND nonce_hash IS NULL)
     OR (purpose='holder' AND client_binding IS NOT NULL AND nonce_hash IS NOT NULL))
) STRICT;
CREATE INDEX identity_attester_challenge_expiry ON identity_attester_challenge(expires_at);
