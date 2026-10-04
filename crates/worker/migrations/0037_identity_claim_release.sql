-- Explicit owner-approved disclosure to one RP; profile scope alone releases nothing.
CREATE TABLE identity_claim_release (
  account_id TEXT NOT NULL REFERENCES account_security(account_id),
  client_id TEXT NOT NULL REFERENCES client(client_id),
  document_id TEXT NOT NULL REFERENCES identity_document(document_id),
  epoch INTEGER NOT NULL,
  client_revision INTEGER NOT NULL,
  connection_grant_version INTEGER NOT NULL,
  fields_json TEXT NOT NULL CHECK(json_valid(fields_json) AND json_type(fields_json)='array'),
  expires_at INTEGER NOT NULL,
  version INTEGER NOT NULL CHECK(version>0),
  active INTEGER NOT NULL CHECK(active IN (0,1)),
  PRIMARY KEY(account_id,client_id)
) STRICT;
CREATE TRIGGER identity_release_erase AFTER UPDATE OF revoked ON identity_document
WHEN NEW.revoked=1
BEGIN
  UPDATE identity_claim_release SET active=0,fields_json='[]',version=version+1 WHERE document_id=NEW.document_id;
END;
CREATE TRIGGER identity_release_client_change AFTER UPDATE ON client
BEGIN
  UPDATE identity_claim_release SET active=0,fields_json='[]',version=version+1
  WHERE client_id=NEW.client_id AND active=1;
END;
CREATE TRIGGER identity_release_connection_change AFTER UPDATE ON app_connection
BEGIN
  UPDATE identity_claim_release SET active=0,fields_json='[]',version=version+1
  WHERE account_id=NEW.account_id AND client_id=NEW.client_id AND active=1;
END;
CREATE TRIGGER identity_release_account_change AFTER UPDATE OF active,epoch ON account_security
WHEN NEW.active!=OLD.active OR NEW.epoch!=OLD.epoch
BEGIN
  UPDATE identity_claim_release SET active=0,fields_json='[]',version=version+1
  WHERE account_id=NEW.account_id AND active=1;
END;
