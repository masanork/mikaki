-- Pushed requests contain only authorization parameters, never card attributes or grant secrets.
CREATE TABLE identity_wallet_par (
  request_hash TEXT PRIMARY KEY NOT NULL,
  client_id TEXT NOT NULL,
  client_policy_hash TEXT NOT NULL,
  request_json TEXT NOT NULL CHECK(json_valid(request_json)),
  expires_at INTEGER NOT NULL,
  used INTEGER NOT NULL DEFAULT 0 CHECK(used IN (0,1))
) STRICT;
CREATE INDEX identity_wallet_par_expiry ON identity_wallet_par(expires_at);
ALTER TABLE identity_wallet_grant ADD COLUMN par_hash TEXT;
ALTER TABLE identity_wallet_grant ADD COLUMN dpop_jkt TEXT;
CREATE TRIGGER identity_wallet_par_guard BEFORE INSERT ON identity_wallet_grant
WHEN NEW.par_hash IS NOT NULL
BEGIN
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1 FROM identity_wallet_par p WHERE p.request_hash=NEW.par_hash
      AND p.client_id=NEW.client_id AND p.client_policy_hash=NEW.client_policy_hash
      AND p.used=0 AND p.expires_at>unixepoch()
  ) THEN RAISE(ABORT,'identity PAR preconditions failed') END;
END;
CREATE TRIGGER identity_wallet_par_consume AFTER INSERT ON identity_wallet_grant
WHEN NEW.par_hash IS NOT NULL
BEGIN
  UPDATE identity_wallet_par SET used=1,request_json='{}' WHERE request_hash=NEW.par_hash;
END;
