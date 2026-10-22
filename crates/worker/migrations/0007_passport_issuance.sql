-- Ephemeral passport issuance only. No raw DG1/SOD or persistent identity linkage.
CREATE TABLE identity_passport_transaction (
  tx_id TEXT PRIMARY KEY NOT NULL,
  poll_hash TEXT UNIQUE NOT NULL,
  holder_json TEXT NOT NULL CHECK(json_valid(holder_json)),
  projection_json TEXT NOT NULL CHECK(json_valid(projection_json)),
  evidence_hash TEXT NOT NULL,
  policy_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  evidence_until INTEGER NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('pending','approved','offered','token','issued','denied')),
  account_id TEXT REFERENCES account_security(account_id) ON DELETE CASCADE,
  epoch INTEGER,
  session_hash TEXT,
  csrf_hash TEXT,
  offer_hash TEXT UNIQUE,
  access_hash TEXT UNIQUE,
  token_expires_at INTEGER,
  proof_nonce_hash TEXT,
  haip INTEGER NOT NULL DEFAULT 0 CHECK(haip IN (0,1)),
  client_id TEXT,
  client_policy_hash TEXT,
  client_binding TEXT,
  dpop_jkt TEXT,
  redirect_uri TEXT,
  wallet_state TEXT,
  code_challenge TEXT,
  par_hash TEXT UNIQUE,
  code_hash TEXT UNIQUE,
  redeemed_code_hash TEXT UNIQUE
) STRICT;
CREATE INDEX identity_passport_expiry ON identity_passport_transaction(expires_at);
CREATE TRIGGER identity_passport_issue_guard BEFORE UPDATE OF state ON identity_passport_transaction
WHEN NEW.state='issued' AND OLD.state='token'
BEGIN
  SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM identity_nonce WHERE nonce_hash=NEW.proof_nonce_hash AND used=0 AND expires_at>unixepoch()) THEN RAISE(ABORT,'passport_nonce_unavailable') END;
  SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM account_security a WHERE a.account_id=NEW.account_id AND a.active=1 AND a.epoch=NEW.epoch) OR NEW.expires_at<=unixepoch() OR NEW.token_expires_at IS NULL OR NEW.token_expires_at<=unixepoch() THEN RAISE(ABORT,'passport_owner_unavailable') END;
END;
CREATE TRIGGER identity_passport_haip_approval BEFORE UPDATE OF state ON identity_passport_transaction
WHEN OLD.state='pending' AND NEW.state IN ('offered','denied') AND NEW.haip=1
BEGIN
  SELECT CASE WHEN NOT EXISTS(
    SELECT 1 FROM identity_wallet_par p JOIN sso_context sx ON sx.secret_hash=NEW.session_hash
    JOIN sso_session ss ON ss.sso_id=sx.sso_id JOIN account_security a ON a.account_id=ss.account_id
    JOIN credential c ON c.credential_id=ss.credential_id AND c.account_id=ss.account_id
    WHERE p.request_hash=NEW.par_hash AND p.client_id=NEW.client_id AND p.client_policy_hash=NEW.client_policy_hash
      AND p.client_binding IS NEW.client_binding AND p.client_binding IS NOT NULL AND p.used=0 AND p.expires_at>unixepoch()
      AND ss.account_id=NEW.account_id AND a.active=1 AND a.epoch=ss.epoch AND NEW.epoch=a.epoch
      AND ss.revoked=0 AND ss.expires_at>unixepoch() AND c.active=1
  ) THEN RAISE(ABORT,'passport_haip_approval_unavailable') END;
END;
CREATE TRIGGER identity_passport_haip_par_consume AFTER UPDATE OF state ON identity_passport_transaction
WHEN OLD.state='pending' AND NEW.state IN ('offered','denied') AND NEW.haip=1
BEGIN
  UPDATE identity_wallet_par SET used=1,request_json='{}' WHERE request_hash=NEW.par_hash;
END;
CREATE TRIGGER identity_passport_consume_nonce AFTER UPDATE OF state ON identity_passport_transaction
WHEN NEW.state='issued' AND OLD.state='token'
BEGIN
  UPDATE identity_nonce SET used=1 WHERE nonce_hash=NEW.proof_nonce_hash;
END;
CREATE TRIGGER identity_passport_scrub AFTER UPDATE OF state ON identity_passport_transaction
WHEN NEW.state IN ('issued','denied')
BEGIN
  UPDATE identity_passport_transaction SET projection_json='{}',holder_json='{}',evidence_hash='',poll_hash=tx_id,offer_hash=NULL,access_hash=NULL,csrf_hash=NULL,session_hash=NULL,client_binding=NULL,dpop_jkt=NULL,wallet_state=NULL,code_hash=NULL,redeemed_code_hash=NULL,code_challenge=NULL WHERE tx_id=NEW.tx_id;
END;
