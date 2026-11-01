-- W3C Device Bound Session Credentials (DBSC) storage.
CREATE TABLE IF NOT EXISTS dbsc_session (
  session_id TEXT PRIMARY KEY NOT NULL CHECK(length(session_id) BETWEEN 1 AND 128),
  sso_id TEXT NOT NULL REFERENCES sso_session(sso_id) ON DELETE CASCADE,
  public_key_sec1 BLOB NOT NULL CHECK(length(public_key_sec1) = 65),
  public_key_jwk TEXT NOT NULL CHECK(length(public_key_jwk) BETWEEN 1 AND 2048),
  created_at INTEGER NOT NULL CHECK(created_at > 0),
  last_refreshed_at INTEGER NOT NULL CHECK(last_refreshed_at >= created_at),
  cookie_expires_at INTEGER NOT NULL CHECK(cookie_expires_at >= created_at)
) STRICT;

CREATE INDEX IF NOT EXISTS idx_dbsc_session_sso ON dbsc_session(sso_id);

CREATE TABLE IF NOT EXISTS dbsc_challenge (
  challenge TEXT PRIMARY KEY NOT NULL CHECK(length(challenge) BETWEEN 16 AND 128),
  session_id TEXT,
  expires_at INTEGER NOT NULL CHECK(expires_at > 0)
) STRICT;

CREATE INDEX IF NOT EXISTS idx_dbsc_challenge_exp ON dbsc_challenge(expires_at);
