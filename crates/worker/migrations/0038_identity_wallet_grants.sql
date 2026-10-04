-- Independent wallet issuance: no copied identity attributes or private holder keys.
CREATE TABLE identity_wallet_grant (
  grant_id TEXT PRIMARY KEY NOT NULL,
  document_id TEXT REFERENCES identity_document(document_id),
  account_id TEXT NOT NULL REFERENCES account_security(account_id),
  epoch INTEGER NOT NULL,
  session_hash TEXT NOT NULL,
  csrf_hash TEXT,
  client_id TEXT NOT NULL,
  client_policy_hash TEXT NOT NULL,
  policy_hash TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  wallet_state TEXT,
  code_challenge TEXT NOT NULL,
  configuration TEXT NOT NULL CHECK(configuration IN ('linked_document','linked_document_mdoc')),
  state TEXT NOT NULL CHECK(state IN ('pending','offered','denied','token','issued')),
  expires_at INTEGER NOT NULL,
  code_hash TEXT UNIQUE,
  access_hash TEXT UNIQUE,
  token_expires_at INTEGER,
  holder_json TEXT CHECK(holder_json IS NULL OR json_valid(holder_json)),
  proof_nonce_hash TEXT
) STRICT;
CREATE INDEX identity_wallet_grant_expiry ON identity_wallet_grant(expires_at);
CREATE INDEX identity_wallet_grant_document ON identity_wallet_grant(document_id);
CREATE TRIGGER identity_wallet_approval_guard BEFORE UPDATE OF state ON identity_wallet_grant
WHEN NEW.state IN ('offered','denied')
BEGIN
  SELECT CASE WHEN OLD.state!='pending' OR NOT EXISTS (
    SELECT 1 FROM sso_context sx JOIN sso_session ss ON ss.sso_id=sx.sso_id
    JOIN account_security a ON a.account_id=ss.account_id
    JOIN credential c ON c.credential_id=ss.credential_id AND c.account_id=ss.account_id
    WHERE sx.secret_hash=NEW.session_hash AND ss.account_id=NEW.account_id
      AND a.active=1 AND a.epoch=ss.epoch AND NEW.epoch=a.epoch
      AND ss.revoked=0 AND ss.expires_at>unixepoch() AND c.active=1
  ) THEN RAISE(ABORT,'identity wallet approval preconditions failed') END;
END;
CREATE TRIGGER identity_wallet_issue_guard BEFORE UPDATE OF state ON identity_wallet_grant
WHEN NEW.state='issued'
BEGIN
  SELECT CASE WHEN OLD.state!='token' OR NEW.holder_json IS NULL OR NOT EXISTS (
    SELECT 1 FROM identity_nonce n WHERE n.nonce_hash=NEW.proof_nonce_hash
      AND n.used=0 AND n.expires_at>unixepoch()
  ) OR NOT EXISTS (
    SELECT 1 FROM identity_document d JOIN account_security a ON a.account_id=d.account_id
    WHERE d.document_id=NEW.document_id AND d.account_id=NEW.account_id
      AND d.revoked=0 AND d.valid_until>unixepoch() AND d.policy_hash=NEW.policy_hash
      AND a.active=1 AND a.epoch=d.epoch AND a.epoch=NEW.epoch
  ) THEN RAISE(ABORT,'identity wallet issuance preconditions failed') END;
END;
CREATE TRIGGER identity_wallet_consume_nonce AFTER UPDATE OF state ON identity_wallet_grant
WHEN NEW.state='issued'
BEGIN
  UPDATE identity_nonce SET used=1 WHERE nonce_hash=NEW.proof_nonce_hash;
END;
CREATE TRIGGER identity_wallet_erase AFTER UPDATE OF revoked ON identity_document
WHEN NEW.revoked=1
BEGIN
  DELETE FROM identity_wallet_grant WHERE document_id=NEW.document_id;
END;

CREATE TRIGGER identity_wallet_account_change AFTER UPDATE ON account_security
WHEN NEW.active!=OLD.active OR NEW.epoch!=OLD.epoch
BEGIN
  DELETE FROM identity_wallet_grant WHERE account_id=NEW.account_id;
END;
