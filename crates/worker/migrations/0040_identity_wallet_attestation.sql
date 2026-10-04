-- Only authenticated instance-key thumbprints; never retain the attestation JWT.
ALTER TABLE identity_wallet_par ADD client_binding TEXT;
ALTER TABLE identity_wallet_grant ADD client_binding TEXT;
CREATE TABLE identity_wallet_attestation_replay (
  replay_hash TEXT PRIMARY KEY NOT NULL,
  expires_at INTEGER NOT NULL
) STRICT;
CREATE INDEX identity_wallet_attestation_replay_expiry ON identity_wallet_attestation_replay(expires_at);
CREATE TRIGGER identity_wallet_attestation_copy AFTER INSERT ON identity_wallet_grant
WHEN NEW.par_hash IS NOT NULL
BEGIN
  UPDATE identity_wallet_grant SET client_binding=(SELECT client_binding FROM identity_wallet_par WHERE request_hash=NEW.par_hash) WHERE grant_id=NEW.grant_id;
END;
