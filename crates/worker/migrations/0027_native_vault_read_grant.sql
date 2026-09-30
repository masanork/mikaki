-- Inert storage for the future explicit native Vault ciphertext-read consent.
-- No existing OIDC code or UserInfo token gets a row in these tables.
CREATE TABLE vault_oauth_consent (
  tx_id TEXT PRIMARY KEY NOT NULL CHECK(length(tx_id)=43),
  sso_secret_hash TEXT NOT NULL CHECK(length(sso_secret_hash)=43),
  sso_id TEXT NOT NULL REFERENCES sso_session(sso_id),
  account_id TEXT NOT NULL REFERENCES account_security(account_id),
  client_id TEXT NOT NULL REFERENCES client(client_id),
  client_revision INTEGER NOT NULL CHECK(client_revision>=0),
  authorization_url TEXT NOT NULL CHECK(length(authorization_url) BETWEEN 1 AND 8192),
  redirect_uri TEXT NOT NULL CHECK(length(redirect_uri) BETWEEN 1 AND 2048),
  state TEXT NOT NULL CHECK(length(state) BETWEEN 1 AND 512),
  attribute_id TEXT NOT NULL CHECK(attribute_id IN ('name','owner_note')),
  resource TEXT NOT NULL CHECK(resource='https://mikaki.tossa.app/vault-api/'),
  expires_at INTEGER NOT NULL CHECK(expires_at>0),
  decision TEXT NOT NULL DEFAULT 'pending'
    CHECK(decision IN ('pending','approved','denied','consumed')),
  created_at INTEGER NOT NULL CHECK(created_at>0 AND expires_at>created_at)
) STRICT;
CREATE INDEX vault_oauth_consent_session ON vault_oauth_consent(sso_secret_hash,expires_at);
CREATE TRIGGER vault_oauth_consent_active_insert BEFORE INSERT ON vault_oauth_consent
WHEN NEW.decision!='pending' OR NOT EXISTS (
  SELECT 1 FROM sso_session ss JOIN sso_context sx ON sx.sso_id=ss.sso_id
  JOIN account_security a ON a.account_id=ss.account_id
  JOIN credential cr ON cr.credential_id=ss.credential_id AND cr.account_id=ss.account_id
  JOIN client c ON c.client_id=NEW.client_id
  JOIN app_connection ac ON ac.account_id=ss.account_id AND ac.client_id=c.client_id
  JOIN client_redirect_uri r ON r.client_id=c.client_id
  WHERE ss.sso_id=NEW.sso_id AND ss.account_id=NEW.account_id
    AND sx.secret_hash=NEW.sso_secret_hash AND ss.revoked=0 AND ss.expires_at>unixepoch()
    AND a.active=1 AND a.epoch=ss.epoch AND cr.active=1 AND c.active=1
    AND ac.active=1
    AND c.client_type='native' AND c.auth_method='none'
    AND c.revision=NEW.client_revision
    AND r.redirect_uri=NEW.redirect_uri AND r.active=1
    AND NEW.expires_at>unixepoch() AND NEW.expires_at<=unixepoch()+300
    AND NEW.created_at<=unixepoch() AND NEW.created_at>unixepoch()-30
)
BEGIN SELECT RAISE(ABORT,'vault consent preconditions failed'); END;
CREATE TRIGGER vault_oauth_consent_transition BEFORE UPDATE ON vault_oauth_consent
WHEN NEW.tx_id IS NOT OLD.tx_id OR NEW.sso_secret_hash IS NOT OLD.sso_secret_hash
  OR NEW.sso_id IS NOT OLD.sso_id OR NEW.account_id IS NOT OLD.account_id
  OR NEW.client_id IS NOT OLD.client_id OR NEW.client_revision IS NOT OLD.client_revision
  OR NEW.authorization_url IS NOT OLD.authorization_url
  OR NEW.redirect_uri IS NOT OLD.redirect_uri
  OR NEW.state IS NOT OLD.state
  OR NEW.attribute_id IS NOT OLD.attribute_id OR NEW.resource IS NOT OLD.resource
  OR NEW.expires_at IS NOT OLD.expires_at OR NEW.created_at IS NOT OLD.created_at
  OR NOT ((OLD.decision='pending' AND NEW.decision IN ('approved','denied'))
    OR (OLD.decision='approved' AND NEW.decision='consumed'))
  OR NEW.expires_at<=unixepoch()
  OR NOT EXISTS (
    SELECT 1 FROM sso_session ss JOIN sso_context sx ON sx.sso_id=ss.sso_id
    JOIN account_security a ON a.account_id=ss.account_id
    JOIN credential cr ON cr.credential_id=ss.credential_id AND cr.account_id=ss.account_id
    JOIN client c ON c.client_id=NEW.client_id
    JOIN app_connection ac ON ac.account_id=ss.account_id AND ac.client_id=c.client_id
    WHERE ss.sso_id=NEW.sso_id AND ss.account_id=NEW.account_id
      AND sx.secret_hash=NEW.sso_secret_hash AND ss.revoked=0 AND ss.expires_at>unixepoch()
      AND a.active=1 AND a.epoch=ss.epoch AND cr.active=1 AND c.active=1
      AND ac.active=1
      AND c.client_type='native' AND c.auth_method='none'
      AND c.revision=NEW.client_revision
  )
BEGIN SELECT RAISE(ABORT,'vault consent transition failed'); END;
CREATE TRIGGER vault_oauth_consent_no_delete BEFORE DELETE ON vault_oauth_consent
BEGIN SELECT RAISE(ABORT,'vault consent audit cannot be deleted'); END;

CREATE TABLE vault_oauth_grant (
  grant_id TEXT PRIMARY KEY NOT NULL CHECK(length(grant_id)=43),
  consent_tx_id TEXT NOT NULL UNIQUE REFERENCES vault_oauth_consent(tx_id),
  account_id TEXT NOT NULL REFERENCES account_security(account_id),
  client_id TEXT NOT NULL REFERENCES client(client_id),
  client_revision INTEGER NOT NULL CHECK(client_revision>=0),
  attribute_id TEXT NOT NULL CHECK(attribute_id IN ('name','owner_note')),
  resource TEXT NOT NULL CHECK(resource='https://mikaki.tossa.app/vault-api/'),
  action TEXT NOT NULL CHECK(action='read_ciphertext'),
  version INTEGER NOT NULL CHECK(version>0),
  expires_at INTEGER NOT NULL CHECK(expires_at>0),
  revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1)),
  created_at INTEGER NOT NULL CHECK(created_at>0 AND expires_at>created_at)
) STRICT;
CREATE INDEX vault_oauth_grant_owner ON vault_oauth_grant(account_id,client_id,attribute_id);
CREATE TRIGGER vault_oauth_grant_active_insert BEFORE INSERT ON vault_oauth_grant
WHEN NOT EXISTS (
  SELECT 1 FROM vault_oauth_consent vc
  JOIN sso_session ss ON ss.sso_id=vc.sso_id AND ss.account_id=vc.account_id
  JOIN sso_context sx ON sx.sso_id=ss.sso_id
  JOIN account_security a ON a.account_id=vc.account_id
  JOIN credential cr ON cr.credential_id=ss.credential_id AND cr.account_id=ss.account_id
  JOIN client c ON c.client_id=vc.client_id
  JOIN app_connection ac ON ac.account_id=ss.account_id AND ac.client_id=c.client_id
  WHERE vc.tx_id=NEW.consent_tx_id AND vc.decision='consumed'
    AND vc.account_id=NEW.account_id AND vc.client_id=NEW.client_id
    AND vc.client_revision=NEW.client_revision
    AND vc.attribute_id=NEW.attribute_id AND vc.resource=NEW.resource
    AND vc.expires_at>unixepoch()
    AND vc.created_at<=NEW.created_at
    AND sx.secret_hash=vc.sso_secret_hash AND ss.revoked=0
    AND ss.expires_at>unixepoch() AND a.epoch=ss.epoch
    AND a.account_id=NEW.account_id AND a.active=1 AND cr.active=1
    AND ac.active=1
    AND c.active=1 AND c.client_type='native' AND c.auth_method='none'
    AND c.revision=NEW.client_revision
    AND NEW.expires_at>unixepoch() AND NEW.expires_at<=unixepoch()+3600
    AND NEW.created_at<=unixepoch() AND NEW.created_at>unixepoch()-300
)
BEGIN SELECT RAISE(ABORT,'vault grant preconditions failed'); END;
CREATE TRIGGER vault_oauth_grant_identity_immutable BEFORE UPDATE ON vault_oauth_grant
WHEN NEW.grant_id IS NOT OLD.grant_id
  OR NEW.consent_tx_id IS NOT OLD.consent_tx_id
  OR NEW.account_id IS NOT OLD.account_id
  OR NEW.client_id IS NOT OLD.client_id
  OR NEW.client_revision IS NOT OLD.client_revision
  OR NEW.attribute_id IS NOT OLD.attribute_id
  OR NEW.resource IS NOT OLD.resource
  OR NEW.action IS NOT OLD.action
  OR NEW.created_at IS NOT OLD.created_at
  OR NEW.expires_at>OLD.expires_at
  OR NEW.version<=OLD.version
  OR (OLD.revoked=1 AND NEW.revoked=0)
BEGIN SELECT RAISE(ABORT,'vault grant identity or revision changed'); END;
CREATE TRIGGER vault_oauth_grant_no_delete BEFORE DELETE ON vault_oauth_grant
BEGIN SELECT RAISE(ABORT,'vault grant audit cannot be deleted'); END;
CREATE TRIGGER vault_oauth_grant_client_change_revoke AFTER UPDATE ON client
BEGIN
  UPDATE vault_oauth_grant SET revoked=1,version=version+1
  WHERE client_id=NEW.client_id AND revoked=0;
END;

-- Inserted only in the same transaction that consumes explicit owner consent
-- and issues the matching authorization code. A token without this context is
-- never a Vault token, regardless of its OIDC scope or UserInfo eligibility.
CREATE TABLE vault_oauth_code_context (
  code_hash TEXT PRIMARY KEY NOT NULL REFERENCES authorization_code(code_hash),
  grant_id TEXT NOT NULL REFERENCES vault_oauth_grant(grant_id),
  grant_version INTEGER NOT NULL CHECK(grant_version>0),
  resource TEXT NOT NULL CHECK(resource='https://mikaki.tossa.app/vault-api/'),
  attribute_id TEXT NOT NULL CHECK(attribute_id IN ('name','owner_note'))
) STRICT;
CREATE INDEX vault_oauth_code_grant ON vault_oauth_code_context(grant_id);
CREATE TRIGGER vault_oauth_code_context_active_insert BEFORE INSERT ON vault_oauth_code_context
WHEN NOT EXISTS (
  SELECT 1 FROM vault_oauth_grant g
  JOIN authorization_code ac ON ac.code_hash=NEW.code_hash AND ac.client_id=g.client_id
  JOIN client_session cs ON cs.client_id=ac.client_id AND cs.sid=ac.sid
    AND cs.account_id=g.account_id
  WHERE g.grant_id=NEW.grant_id AND g.revoked=0 AND g.version=NEW.grant_version
    AND g.client_revision=ac.client_revision
    AND g.attribute_id=NEW.attribute_id AND g.resource=NEW.resource
    AND g.expires_at>unixepoch() AND ac.expires_at>unixepoch()
    AND ac.consumed_by IS NULL
)
BEGIN SELECT RAISE(ABORT,'vault code context preconditions failed'); END;
CREATE TRIGGER vault_oauth_code_context_immutable BEFORE UPDATE ON vault_oauth_code_context
BEGIN SELECT RAISE(ABORT,'vault code context is immutable'); END;
CREATE TRIGGER vault_oauth_code_context_no_delete BEFORE DELETE ON vault_oauth_code_context
BEGIN SELECT RAISE(ABORT,'vault code context cannot be deleted'); END;
