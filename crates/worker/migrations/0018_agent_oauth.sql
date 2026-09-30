-- A separate public-client AS; no OIDC login tokens or implicit Vault grants.
CREATE TABLE agent_oauth_client (
  client_id TEXT PRIMARY KEY,
  client_name TEXT NOT NULL,
  redirect_uris TEXT NOT NULL CHECK(json_valid(redirect_uris)),
  active INTEGER NOT NULL DEFAULT 1 CHECK(active IN(0,1))
) STRICT;
CREATE TRIGGER agent_oauth_client_immutable BEFORE UPDATE ON agent_oauth_client
WHEN OLD.active=0 OR NEW.client_id!=OLD.client_id OR NEW.client_name!=OLD.client_name
  OR NEW.redirect_uris!=OLD.redirect_uris OR NEW.active!=0
BEGIN SELECT RAISE(ABORT,'client registration is immutable; disable and replace'); END;
CREATE TRIGGER agent_oauth_client_no_delete BEFORE DELETE ON agent_oauth_client
BEGIN SELECT RAISE(ABORT,'client tombstone must be retained'); END;

CREATE TABLE agent_oauth_request (
  request_id TEXT PRIMARY KEY,
  client_id TEXT NOT NULL REFERENCES agent_oauth_client(client_id),
  redirect_uri TEXT NOT NULL,
  resource TEXT NOT NULL,
  scopes TEXT NOT NULL CHECK(json_valid(scopes)),
  state TEXT NOT NULL,
  challenge TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  owner_account TEXT,
  owner_secret TEXT,
  grant_id TEXT REFERENCES agent_grant(grant_id),
  grant_revision INTEGER,
  decision TEXT CHECK(decision IN('approved','denied')),
  code_hash TEXT UNIQUE,
  code_expires_at INTEGER,
  redeemed_at INTEGER,
  CHECK(expires_at=created_at+600),
  CHECK((owner_account IS NULL)=(owner_secret IS NULL)),
  CHECK((decision='approved' AND grant_id IS NOT NULL AND grant_revision IS NOT NULL
    AND code_hash IS NOT NULL AND code_expires_at IS NOT NULL)
    OR (decision IS NULL AND grant_id IS NULL AND grant_revision IS NULL AND code_hash IS NULL
      AND code_expires_at IS NULL AND redeemed_at IS NULL)
    OR (decision='denied' AND grant_id IS NULL AND code_hash IS NULL AND redeemed_at IS NULL))
) STRICT;
CREATE INDEX agent_oauth_pending ON agent_oauth_request(client_id,expires_at);
CREATE TABLE agent_oauth_token (
  token_hash TEXT PRIMARY KEY,
  request_id TEXT NOT NULL UNIQUE REFERENCES agent_oauth_request(request_id) ON DELETE CASCADE,
  client_id TEXT NOT NULL REFERENCES agent_oauth_client(client_id),
  grant_id TEXT NOT NULL REFERENCES agent_grant(grant_id),
  grant_revision INTEGER NOT NULL,
  resource TEXT NOT NULL,
  scopes TEXT NOT NULL CHECK(json_valid(scopes)),
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN(0,1)),
  CHECK(expires_at>created_at AND expires_at<=created_at+3600)
) STRICT;
CREATE TRIGGER agent_oauth_approval_audit AFTER UPDATE OF decision ON agent_oauth_request
WHEN OLD.decision IS NULL AND NEW.decision='approved'
BEGIN INSERT INTO agent_audit VALUES('oauth-consent:' || NEW.request_id,NEW.grant_id,
  'oauth-consent','approved',NULL,unixepoch()); END;
CREATE TRIGGER agent_oauth_token_audit AFTER INSERT ON agent_oauth_token
BEGIN INSERT INTO agent_audit VALUES('oauth-token:' || NEW.request_id,NEW.grant_id,
  'oauth-token','issued',NULL,unixepoch()); END;
CREATE TRIGGER agent_oauth_revoke_audit AFTER UPDATE OF revoked ON agent_oauth_token
WHEN OLD.revoked=0 AND NEW.revoked=1
BEGIN INSERT INTO agent_audit VALUES('oauth-revoke:' || NEW.request_id,NEW.grant_id,
  'oauth-token','revoked',NULL,unixepoch()); END;
CREATE TABLE agent_oauth_guard (
  operation TEXT PRIMARY KEY,
  valid INTEGER NOT NULL CHECK(valid=1)
) STRICT;
