-- Separate, explicit disclosure to a decrypting agent service. No Vault owner keys.
CREATE TABLE agent_recipient_key (
  key_id TEXT PRIMARY KEY,
  state TEXT NOT NULL CHECK(state IN('active','disabled'))
);
CREATE TRIGGER agent_recipient_no_restore BEFORE UPDATE ON agent_recipient_key
WHEN OLD.state='disabled' OR NEW.key_id!=OLD.key_id
BEGIN SELECT RAISE(ABORT,'recipient key cannot be restored or replaced'); END;
CREATE TRIGGER agent_recipient_no_delete BEFORE DELETE ON agent_recipient_key
BEGIN SELECT RAISE(ABORT,'recipient key tombstone must be retained'); END;
CREATE TABLE agent_grant (
  grant_id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES account_security(account_id),
  owner_epoch INTEGER NOT NULL,
  credential_id TEXT NOT NULL REFERENCES credential(credential_id),
  delegate TEXT NOT NULL,
  provider TEXT NOT NULL,
  resource TEXT NOT NULL,
  source_revision INTEGER NOT NULL,
  recipient_key_id TEXT NOT NULL,
  operations TEXT NOT NULL,
  document_ids TEXT NOT NULL,
  encrypted_snapshot TEXT,
  token_hash TEXT NOT NULL UNIQUE,
  request_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1)),
  revision INTEGER NOT NULL DEFAULT 1 CHECK(revision > 0),
  CHECK(expires_at > created_at AND expires_at <= created_at + 86400)
);
CREATE INDEX agent_grant_owner ON agent_grant(account_id,created_at);
CREATE TABLE agent_audit (
  event_id TEXT PRIMARY KEY,
  grant_id TEXT NOT NULL REFERENCES agent_grant(grant_id),
  operation TEXT NOT NULL,
  outcome TEXT NOT NULL,
  document_id TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX agent_audit_recent ON agent_audit(grant_id,created_at);
CREATE TABLE agent_proposal (
  proposal_id TEXT PRIMARY KEY,
  grant_id TEXT NOT NULL REFERENCES agent_grant(grant_id),
  request_hash TEXT NOT NULL,
  document_id TEXT NOT NULL,
  title TEXT NOT NULL,
  text TEXT,
  expires_at INTEGER NOT NULL,
  state TEXT NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','approved','executed','rejected')),
  approved_revision INTEGER,
  result_id TEXT UNIQUE,
  created_at INTEGER NOT NULL
);
-- Agent-created drafts stay outside the encrypted owner Vault and cannot publish/send.
CREATE TABLE agent_draft (
  draft_id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES account_security(account_id),
  proposal_id TEXT NOT NULL UNIQUE REFERENCES agent_proposal(proposal_id),
  title TEXT NOT NULL,
  text TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

-- Security/source changes irreversibly stop old grants, even if a credential is re-enabled.
CREATE TRIGGER agent_grant_account_stop AFTER UPDATE OF active,epoch ON account_security
WHEN NEW.active=0 OR NEW.epoch!=OLD.epoch
BEGIN
  UPDATE agent_grant SET revoked=1,revision=revision+1,encrypted_snapshot=NULL
  WHERE account_id=NEW.account_id AND revoked=0 AND (NEW.active=0 OR owner_epoch!=NEW.epoch);
END;
CREATE TRIGGER agent_grant_credential_stop AFTER UPDATE OF active ON credential
WHEN NEW.active=0
BEGIN
  UPDATE agent_grant SET revoked=1,revision=revision+1,encrypted_snapshot=NULL
  WHERE credential_id=NEW.credential_id AND revoked=0;
END;
CREATE TRIGGER agent_grant_source_change AFTER UPDATE OF revision,deleted ON vault_attribute_head
WHEN NEW.attribute_id='name' AND (NEW.revision!=OLD.revision OR NEW.deleted=1)
BEGIN
  UPDATE agent_grant SET revoked=1,revision=revision+1,encrypted_snapshot=NULL
  WHERE account_id=NEW.account_id AND revoked=0 AND (source_revision!=NEW.revision OR NEW.deleted=1);
END;
CREATE TRIGGER agent_grant_revoked AFTER UPDATE OF revoked ON agent_grant
WHEN OLD.revoked=0 AND NEW.revoked=1
BEGIN
  INSERT INTO agent_audit VALUES('invalidate:' || NEW.grant_id || ':' || NEW.revision,
    NEW.grant_id,'invalidate','revoked',NULL,unixepoch());
  UPDATE agent_proposal SET text=NULL,state='rejected'
  WHERE grant_id=NEW.grant_id AND state IN('pending','approved');
END;
CREATE TRIGGER agent_recipient_stop AFTER UPDATE OF state ON agent_recipient_key
WHEN NEW.state='disabled'
BEGIN
  UPDATE agent_grant SET revoked=1,revision=revision+1,encrypted_snapshot=NULL
  WHERE recipient_key_id=NEW.key_id AND revoked=0;
END;
