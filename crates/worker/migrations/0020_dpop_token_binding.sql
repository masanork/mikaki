-- Existing unbound tokens remain Bearer. Newly DPoP-issued opaque tokens keep
-- their immutable RFC 7638 thumbprint for their whole lifetime.
ALTER TABLE token_issue ADD COLUMN dpop_jkt TEXT
  CHECK(dpop_jkt IS NULL OR length(dpop_jkt) = 43);
CREATE TRIGGER token_issue_dpop_binding_immutable BEFORE UPDATE OF dpop_jkt ON token_issue
WHEN NEW.dpop_jkt IS NOT OLD.dpop_jkt
BEGIN SELECT RAISE(ABORT, 'token DPoP binding is immutable'); END;

-- SHA-256 of jti bounds storage and keeps arbitrary client identifiers out of
-- the replay ledger. Acceptance is shared by token and resource endpoints.
CREATE TABLE dpop_proof_use (
  jkt TEXT NOT NULL CHECK(length(jkt) = 43),
  jti_hash TEXT NOT NULL CHECK(length(jti_hash) = 43),
  accepted_by TEXT NOT NULL UNIQUE CHECK(length(accepted_by) = 43),
  retain_until INTEGER NOT NULL CHECK(retain_until > 0),
  PRIMARY KEY(jkt, jti_hash)
) STRICT;
CREATE INDEX dpop_proof_use_expiry ON dpop_proof_use(retain_until);
