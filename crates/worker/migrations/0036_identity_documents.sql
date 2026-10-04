-- Consent-bound static document attributes; raw EFs, PINs, photos and domicile are never stored.
CREATE TABLE identity_transaction (
  tx_id TEXT PRIMARY KEY NOT NULL,
  poll_hash TEXT UNIQUE NOT NULL,
  holder_json TEXT NOT NULL CHECK(json_valid(holder_json)),
  document_json TEXT NOT NULL CHECK(json_valid(document_json)),
  policy_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('pending','approved','denied','offered','token','issued')),
  account_id TEXT REFERENCES account_security(account_id),
  epoch INTEGER,
  session_hash TEXT,
  csrf_hash TEXT,
  offer_hash TEXT UNIQUE,
  access_hash TEXT UNIQUE,
  token_expires_at INTEGER,
  proof_nonce_hash TEXT
) STRICT;
CREATE INDEX identity_transaction_expiry ON identity_transaction(expires_at);
CREATE TABLE identity_document (
  document_id TEXT PRIMARY KEY NOT NULL REFERENCES identity_transaction(tx_id),
  account_id TEXT NOT NULL REFERENCES account_security(account_id),
  epoch INTEGER NOT NULL,
  document_json TEXT NOT NULL CHECK(json_valid(document_json)),
  policy_hash TEXT NOT NULL,
  linked_at INTEGER NOT NULL,
  valid_until INTEGER NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1))
) STRICT;
CREATE INDEX identity_document_owner ON identity_document(account_id);
CREATE TABLE identity_nonce (
  nonce_hash TEXT PRIMARY KEY NOT NULL,
  expires_at INTEGER NOT NULL,
  used INTEGER NOT NULL DEFAULT 0 CHECK(used IN (0,1))
) STRICT;
CREATE TRIGGER identity_approve_guard BEFORE UPDATE OF state ON identity_transaction
WHEN NEW.state='approved' AND OLD.state='pending'
BEGIN
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1 FROM sso_context sx JOIN sso_session ss ON ss.sso_id=sx.sso_id
    JOIN account_security a ON a.account_id=ss.account_id
    JOIN credential c ON c.credential_id=ss.credential_id AND c.account_id=ss.account_id
    WHERE sx.secret_hash=NEW.session_hash AND ss.account_id=NEW.account_id
      AND a.active=1 AND a.epoch=ss.epoch AND NEW.epoch=a.epoch
      AND ss.revoked=0 AND ss.expires_at>unixepoch() AND c.active=1
  ) THEN RAISE(ABORT,'identity approval preconditions failed') END;
END;
CREATE TRIGGER identity_link AFTER UPDATE OF state ON identity_transaction
WHEN NEW.state='approved' AND OLD.state='pending'
BEGIN
  INSERT INTO identity_document(document_id,account_id,epoch,document_json,policy_hash,linked_at,valid_until)
  VALUES(NEW.tx_id,NEW.account_id,NEW.epoch,NEW.document_json,NEW.policy_hash,unixepoch(),unixepoch()+86400);
END;
CREATE TRIGGER identity_issue_guard BEFORE UPDATE OF state ON identity_transaction
WHEN NEW.state='issued'
BEGIN
  SELECT CASE WHEN OLD.state!='token' OR NOT EXISTS (
    SELECT 1 FROM identity_nonce n WHERE n.nonce_hash=NEW.proof_nonce_hash
      AND n.used=0 AND n.expires_at>unixepoch()
  ) OR NOT EXISTS (
    SELECT 1 FROM identity_document d JOIN account_security a ON a.account_id=d.account_id
    WHERE d.document_id=NEW.tx_id AND d.revoked=0 AND d.valid_until>unixepoch()
      AND a.active=1 AND a.epoch=d.epoch AND a.epoch=NEW.epoch
  ) THEN RAISE(ABORT,'identity issuance preconditions failed') END;
END;
CREATE TRIGGER identity_consume_nonce AFTER UPDATE OF state ON identity_transaction
WHEN NEW.state='issued'
BEGIN
  UPDATE identity_nonce SET used=1 WHERE nonce_hash=NEW.proof_nonce_hash;
END;

CREATE TRIGGER identity_erase AFTER UPDATE OF revoked ON identity_document
WHEN NEW.revoked=1
BEGIN
  UPDATE identity_transaction SET document_json='{}',poll_hash=tx_id,offer_hash=NULL,access_hash=NULL,csrf_hash=NULL
  WHERE tx_id=NEW.document_id;
END;
