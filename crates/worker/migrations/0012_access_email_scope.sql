-- Preserve existing code contexts while adding the canonical Access scope.
-- Recreate the dependent view around the table replacement.
DROP VIEW identity_age_eligible;
CREATE TABLE code_context_access_migration (
  code_hash TEXT PRIMARY KEY NOT NULL REFERENCES authorization_code(code_hash),
  nonce TEXT CHECK(nonce IS NULL OR length(nonce) BETWEEN 1 AND 512),
  scope TEXT NOT NULL DEFAULT 'openid'
    CHECK(scope IN ('openid','openid profile','profile openid',
      'openid vault.read','vault.read openid','openid email profile'))
) STRICT;
INSERT INTO code_context_access_migration SELECT code_hash,nonce,scope FROM code_context;
DROP TABLE code_context;
ALTER TABLE code_context_access_migration RENAME TO code_context;
CREATE TRIGGER code_context_scope_immutable BEFORE UPDATE OF scope ON code_context
BEGIN SELECT RAISE(ABORT, 'authorization scope is immutable'); END;
ALTER TABLE token_issue ADD COLUMN access_email_revision INTEGER
  CHECK(access_email_revision IS NULL OR access_email_revision >= 1);
CREATE VIEW identity_age_eligible AS
SELECT q.*,ti.access_hash,ac.client_id,v.sub,d.document_json,d.policy_hash,
       min(ti.access_expires_at,v.expires_at,r.expires_at,d.valid_until) AS deadline
FROM identity_age_request q
JOIN token_issue ti ON ti.code_hash=q.code_hash
JOIN authorization_code ac ON ac.code_hash=ti.code_hash AND ac.consumed_by=ti.operation_id
JOIN code_context cc ON cc.code_hash=ac.code_hash
JOIN valid_client_session v ON v.client_id=ac.client_id AND v.sid=ac.sid
JOIN client c ON c.client_id=v.client_id
JOIN app_connection g ON g.account_id=v.account_id AND g.client_id=v.client_id
JOIN account_security a ON a.account_id=v.account_id
JOIN identity_claim_release r ON r.account_id=v.account_id AND r.client_id=v.client_id
JOIN identity_document d ON d.document_id=r.document_id AND d.account_id=r.account_id
WHERE ti.revoked=0 AND ti.access_expires_at>unixepoch()
  AND cc.scope IN ('openid profile','profile openid')
  AND c.active=1 AND c.revision=ac.client_revision AND c.revision=r.client_revision
  AND g.active=1 AND g.grant_version=r.connection_grant_version
  AND a.active=1 AND a.epoch=r.epoch AND a.epoch=d.epoch
  AND r.active=1 AND r.expires_at>unixepoch() AND r.version=q.release_version
  AND r.document_id=q.document_id AND d.revoked=0 AND d.valid_until>unixepoch()
  AND NOT EXISTS(SELECT 1 FROM json_each(q.fields_json) f
    WHERE NOT EXISTS(SELECT 1 FROM json_each(r.fields_json) consent WHERE consent.value=f.value));
