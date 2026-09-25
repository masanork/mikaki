CREATE TABLE logout_tombstone (
  sid TEXT PRIMARY KEY,
  expires_at INTEGER NOT NULL
);
CREATE INDEX logout_tombstone_expiry ON logout_tombstone(expires_at);
