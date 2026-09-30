-- Opaque Vault tokens have a separate, immutable audience and grant binding.
-- Ordinary UserInfo tokens never acquire a row in this table.
CREATE TABLE vault_oauth_token_context (
  access_hash TEXT PRIMARY KEY NOT NULL REFERENCES token_issue(access_hash),
  grant_id TEXT NOT NULL REFERENCES vault_oauth_grant(grant_id),
  grant_version INTEGER NOT NULL CHECK(grant_version>0),
  resource TEXT NOT NULL CHECK(resource='https://mikaki.tossa.app/vault-api/'),
  attribute_id TEXT NOT NULL CHECK(attribute_id IN ('name','owner_note'))
) STRICT;
CREATE INDEX vault_oauth_token_grant ON vault_oauth_token_context(grant_id);
CREATE TRIGGER vault_oauth_token_context_active_insert BEFORE INSERT ON vault_oauth_token_context
WHEN NOT EXISTS (
  SELECT 1 FROM token_issue ti
  JOIN authorization_code ac ON ac.code_hash=ti.code_hash
  JOIN code_context cc ON cc.code_hash=ac.code_hash
  JOIN vault_oauth_code_context vc ON vc.code_hash=ac.code_hash
  JOIN vault_oauth_grant g ON g.grant_id=vc.grant_id
  JOIN valid_client_session s ON s.client_id=ac.client_id AND s.sid=ac.sid
  JOIN client c ON c.client_id=ac.client_id
  WHERE ti.access_hash=NEW.access_hash AND ti.revoked=0
    AND ti.dpop_jkt IS NOT NULL AND ti.access_expires_at>unixepoch()
    AND ac.consumed_by=ti.operation_id
    AND cc.scope IN ('openid vault.read','vault.read openid')
    AND vc.grant_id=NEW.grant_id AND vc.grant_version=NEW.grant_version
    AND vc.resource=NEW.resource AND vc.attribute_id=NEW.attribute_id
    AND g.version=NEW.grant_version AND g.revoked=0
    AND g.resource=NEW.resource AND g.attribute_id=NEW.attribute_id
    AND g.client_id=ac.client_id AND g.client_revision=ac.client_revision
    AND g.account_id=s.account_id AND g.expires_at>=ti.access_expires_at
    AND c.client_type='native' AND c.auth_method='none' AND c.active=1
    AND c.revision=ac.client_revision
)
BEGIN SELECT RAISE(ABORT,'vault token context preconditions failed'); END;
CREATE TRIGGER vault_oauth_token_context_immutable BEFORE UPDATE ON vault_oauth_token_context
BEGIN SELECT RAISE(ABORT,'vault token context is immutable'); END;
CREATE TRIGGER vault_oauth_token_context_no_delete BEFORE DELETE ON vault_oauth_token_context
BEGIN SELECT RAISE(ABORT,'vault token context cannot be deleted'); END;
