-- Retain only trusted callback routing after scrubbing consumed authorization data.
ALTER TABLE identity_wallet_par ADD COLUMN redirect_uri TEXT;
ALTER TABLE identity_wallet_par ADD COLUMN wallet_state TEXT;
UPDATE identity_wallet_par SET redirect_uri=json_extract(request_json,'$.redirect_uri'),
  wallet_state=json_extract(request_json,'$.state') WHERE used=0;
DROP TRIGGER identity_wallet_par_consume;
CREATE TRIGGER identity_wallet_par_consume AFTER UPDATE OF state ON identity_wallet_grant
WHEN OLD.state='pending' AND NEW.state IN ('offered','denied') AND NEW.par_hash IS NOT NULL
BEGIN
  UPDATE identity_wallet_par SET used=1,request_json='{}' WHERE request_hash=NEW.par_hash;
END;
