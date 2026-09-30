-- Preserve exact requested scope through the code. Token exchange rejects
-- Vault scopes until the separate Vault audience and DPoP issuance is wired.
DROP TRIGGER code_context_scope_immutable;
CREATE TABLE code_context_next (
  code_hash TEXT PRIMARY KEY NOT NULL REFERENCES authorization_code(code_hash),
  nonce TEXT CHECK(nonce IS NULL OR length(nonce) BETWEEN 1 AND 512),
  scope TEXT NOT NULL DEFAULT 'openid'
    CHECK(scope IN ('openid','openid profile','profile openid',
      'openid vault.read','vault.read openid'))
) STRICT;
INSERT INTO code_context_next(code_hash,nonce,scope)
  SELECT code_hash,nonce,scope FROM code_context;
DROP TABLE code_context;
ALTER TABLE code_context_next RENAME TO code_context;
CREATE TRIGGER code_context_scope_immutable BEFORE UPDATE OF scope ON code_context
BEGIN SELECT RAISE(ABORT, 'authorization scope is immutable'); END;
