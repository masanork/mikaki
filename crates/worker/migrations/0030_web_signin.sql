-- First-party browser sign-in: no RP grant and no agent authorization.
CREATE TABLE web_login_transaction (
  tx_id TEXT PRIMARY KEY NOT NULL CHECK(length(tx_id)=43),
  browser_hash TEXT NOT NULL CHECK(length(browser_hash)=43),
  authorization_url TEXT NOT NULL,
  challenge TEXT NOT NULL CHECK(length(challenge)=43),
  expires_at INTEGER NOT NULL,
  consumed INTEGER NOT NULL DEFAULT 0 CHECK(consumed IN(0,1)),
  failures INTEGER NOT NULL DEFAULT 0 CHECK(failures BETWEEN 0 AND 5)
) STRICT;
CREATE INDEX web_login_expiry ON web_login_transaction(expires_at);
