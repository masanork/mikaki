-- Bind an agent request's owner-login continuation to the configured owner origin.
ALTER TABLE agent_oauth_request ADD COLUMN owner_origin TEXT NOT NULL DEFAULT '';
CREATE TABLE owner_login_transaction (
  tx_id TEXT PRIMARY KEY NOT NULL CHECK(length(tx_id)=43),
  browser_hash TEXT NOT NULL CHECK(length(browser_hash)=43),
  request_id TEXT NOT NULL REFERENCES agent_oauth_request(request_id) ON DELETE CASCADE,
  authorization_url TEXT NOT NULL,
  challenge TEXT NOT NULL CHECK(length(challenge)=43),
  expires_at INTEGER NOT NULL,
  consumed INTEGER NOT NULL DEFAULT 0 CHECK(consumed IN(0,1)),
  failures INTEGER NOT NULL DEFAULT 0 CHECK(failures BETWEEN 0 AND 5)
) STRICT;
CREATE INDEX owner_login_request ON owner_login_transaction(request_id,expires_at);
