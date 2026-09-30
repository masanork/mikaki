-- Authorization scope is immutable evidence carried from the browser request
-- through code exchange to UserInfo. Existing codes remain openid-only.
ALTER TABLE code_context ADD COLUMN scope TEXT NOT NULL DEFAULT 'openid'
  CHECK(scope IN ('openid','openid profile','profile openid'));
CREATE TRIGGER code_context_scope_immutable BEFORE UPDATE OF scope ON code_context
BEGIN SELECT RAISE(ABORT, 'authorization scope is immutable'); END;

-- One audit row is written immediately before releasing an RP claim. No
-- plaintext, ciphertext or token is stored in this audit.
CREATE TABLE vault_claim_disclosure_audit (
  id INTEGER PRIMARY KEY,
  account_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  claim TEXT NOT NULL CHECK(claim='name'),
  attribute_revision INTEGER NOT NULL CHECK(attribute_revision>0),
  release_version INTEGER NOT NULL CHECK(release_version>0),
  occurred_at INTEGER NOT NULL CHECK(occurred_at>0)
) STRICT;
CREATE TRIGGER vault_claim_disclosure_audit_no_update BEFORE UPDATE ON vault_claim_disclosure_audit
BEGIN SELECT RAISE(ABORT, 'claim disclosure audit is immutable'); END;
CREATE TRIGGER vault_claim_disclosure_audit_no_delete BEFORE DELETE ON vault_claim_disclosure_audit
BEGIN SELECT RAISE(ABORT, 'claim disclosure audit is immutable'); END;
