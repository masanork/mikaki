-- A separate, explicit capability. Existing snapshot/draft grants gain no new rights.
CREATE TABLE agent_attribute_capability (
  grant_id TEXT PRIMARY KEY REFERENCES agent_grant(grant_id) ON DELETE CASCADE,
  attribute_id TEXT NOT NULL CHECK(attribute_id='owner_note'),
  base_revision INTEGER NOT NULL CHECK(base_revision>=0),
  grant_revision INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL CHECK(expires_at>created_at AND expires_at<=created_at+3600)
);
CREATE TRIGGER agent_attribute_capability_immutable BEFORE UPDATE ON agent_attribute_capability
BEGIN SELECT RAISE(ABORT,'capability must be reissued on a new grant'); END;
CREATE TABLE agent_attribute_proposal (
  proposal_id TEXT PRIMARY KEY,
  grant_id TEXT NOT NULL REFERENCES agent_grant(grant_id),
  grant_revision INTEGER NOT NULL,
  request_hash TEXT NOT NULL,
  attribute_id TEXT NOT NULL CHECK(attribute_id='owner_note'),
  base_revision INTEGER NOT NULL CHECK(base_revision>=0),
  payload TEXT,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  state TEXT NOT NULL DEFAULT 'pending' CHECK(state IN('pending','approved','rejected','invalid')),
  CHECK(expires_at>created_at AND expires_at<=created_at+3600)
);
CREATE INDEX agent_attribute_proposal_grant ON agent_attribute_proposal(grant_id,created_at);
CREATE TRIGGER agent_attribute_proposal_immutable BEFORE UPDATE ON agent_attribute_proposal
WHEN NEW.proposal_id!=OLD.proposal_id OR NEW.grant_id!=OLD.grant_id
 OR NEW.grant_revision!=OLD.grant_revision OR NEW.request_hash!=OLD.request_hash
 OR NEW.attribute_id!=OLD.attribute_id OR NEW.base_revision!=OLD.base_revision
 OR NEW.expires_at!=OLD.expires_at OR NEW.created_at!=OLD.created_at
 OR (NEW.payload IS NOT OLD.payload AND NEW.payload IS NOT NULL)
 OR (NEW.state!=OLD.state AND NOT(
   (OLD.state='pending' AND NEW.state IN('approved','rejected','invalid'))
   OR (OLD.state='approved' AND NEW.state='invalid')))
BEGIN SELECT RAISE(ABORT,'invalid attribute proposal transition'); END;
CREATE TRIGGER agent_attribute_proposal_decision_audit AFTER UPDATE OF state ON agent_attribute_proposal
WHEN NEW.state!=OLD.state
BEGIN
  INSERT INTO agent_audit VALUES('attribute:' || NEW.proposal_id || ':' || NEW.state,
    NEW.grant_id,'attribute-decision',NEW.state,NEW.attribute_id,unixepoch());
END;
CREATE TRIGGER agent_attribute_proposal_grant_stop AFTER UPDATE OF revoked ON agent_grant
WHEN NEW.revoked=1
BEGIN
  UPDATE agent_attribute_proposal SET state='invalid',payload=NULL
    WHERE grant_id=NEW.grant_id AND state IN('pending','approved');
END;
CREATE TRIGGER agent_attribute_proposal_target_update AFTER UPDATE OF revision,deleted ON vault_attribute_head
WHEN NEW.attribute_id='owner_note' AND (NEW.revision!=OLD.revision OR NEW.deleted!=OLD.deleted)
BEGIN
  UPDATE agent_attribute_proposal SET state='invalid',payload=NULL
    WHERE grant_id IN(SELECT grant_id FROM agent_grant WHERE account_id=NEW.account_id)
    AND state IN('pending','approved') AND base_revision!=NEW.revision;
END;
CREATE TRIGGER agent_attribute_proposal_target_insert AFTER INSERT ON vault_attribute_head
WHEN NEW.attribute_id='owner_note'
BEGIN
  UPDATE agent_attribute_proposal SET state='invalid',payload=NULL
    WHERE grant_id IN(SELECT grant_id FROM agent_grant WHERE account_id=NEW.account_id)
    AND state IN('pending','approved') AND base_revision!=NEW.revision;
END;
