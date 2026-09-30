-- Pushed requests are private, bounded, client/key-revision bound and consumed
-- only in the transaction that issues an authorization code.
CREATE TABLE par_request (
  request_uri TEXT PRIMARY KEY NOT NULL CHECK(length(request_uri) BETWEEN 50 AND 256),
  client_id TEXT NOT NULL REFERENCES client(client_id),
  client_revision INTEGER NOT NULL CHECK(client_revision >= 0),
  key_id TEXT NOT NULL CHECK(length(key_id) BETWEEN 1 AND 128),
  key_revision INTEGER NOT NULL CHECK(key_revision >= 0),
  request_query TEXT NOT NULL CHECK(length(request_query) BETWEEN 1 AND 8192),
  dpop_jkt TEXT CHECK(dpop_jkt IS NULL OR length(dpop_jkt) = 43),
  expires_at INTEGER NOT NULL CHECK(expires_at > 0),
  consumed_by TEXT UNIQUE REFERENCES authorization_code(code_hash) ON DELETE SET NULL,
  FOREIGN KEY(client_id,key_id) REFERENCES client_key(client_id,kid)
) STRICT;
CREATE INDEX par_request_expiry ON par_request(expires_at);

ALTER TABLE authorization_code ADD COLUMN dpop_jkt TEXT
  CHECK(dpop_jkt IS NULL OR length(dpop_jkt) = 43);
CREATE TRIGGER authorization_code_dpop_binding_immutable BEFORE UPDATE OF dpop_jkt ON authorization_code
WHEN OLD.dpop_jkt IS NOT NULL AND NEW.dpop_jkt IS NOT OLD.dpop_jkt
BEGIN SELECT RAISE(ABORT, 'authorization-code DPoP binding is immutable'); END;
