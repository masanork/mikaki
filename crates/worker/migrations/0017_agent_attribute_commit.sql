-- Preserve proposals from 0016 while making the encrypted commit a durable terminal state.
DROP TRIGGER agent_attribute_proposal_immutable;
DROP TRIGGER agent_attribute_proposal_decision_audit;
DROP TRIGGER agent_attribute_proposal_grant_stop;
DROP TRIGGER agent_attribute_proposal_target_update;
DROP TRIGGER agent_attribute_proposal_target_insert;
CREATE TABLE agent_attribute_proposal_v2 (
  proposal_id TEXT PRIMARY KEY,
  grant_id TEXT NOT NULL REFERENCES agent_grant(grant_id),
  grant_revision INTEGER NOT NULL,
  request_hash TEXT NOT NULL,
  attribute_id TEXT NOT NULL CHECK(attribute_id='owner_note'),
  base_revision INTEGER NOT NULL CHECK(base_revision>=0),
  payload TEXT,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  state TEXT NOT NULL DEFAULT 'pending' CHECK(state IN('pending','approved','rejected','invalid','committed')),
  CHECK(expires_at>created_at AND expires_at<=created_at+3600)
);
INSERT INTO agent_attribute_proposal_v2 SELECT * FROM agent_attribute_proposal;
DROP TABLE agent_attribute_proposal;
ALTER TABLE agent_attribute_proposal_v2 RENAME TO agent_attribute_proposal;
CREATE INDEX agent_attribute_proposal_grant ON agent_attribute_proposal(grant_id,created_at);
CREATE TRIGGER agent_attribute_proposal_immutable BEFORE UPDATE ON agent_attribute_proposal
WHEN NEW.proposal_id!=OLD.proposal_id OR NEW.grant_id!=OLD.grant_id
 OR NEW.grant_revision!=OLD.grant_revision OR NEW.request_hash!=OLD.request_hash
 OR NEW.attribute_id!=OLD.attribute_id OR NEW.base_revision!=OLD.base_revision
 OR NEW.expires_at!=OLD.expires_at OR NEW.created_at!=OLD.created_at
 OR (NEW.payload IS NOT OLD.payload AND NEW.payload IS NOT NULL)
 OR (NEW.state!=OLD.state AND NOT(
   (OLD.state='pending' AND NEW.state IN('approved','rejected','invalid'))
   OR (OLD.state='approved' AND NEW.state IN('invalid','committed'))))
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

CREATE TABLE agent_attribute_commit (
  proposal_id TEXT PRIMARY KEY REFERENCES agent_attribute_proposal(proposal_id) ON DELETE CASCADE,
  account_id TEXT NOT NULL REFERENCES account_security(account_id),
  operation_id TEXT NOT NULL,
  candidate TEXT NOT NULL,
  candidate_sha256 TEXT NOT NULL,
  origin TEXT NOT NULL,
  prepared_at INTEGER NOT NULL,
  result_revision INTEGER,
  UNIQUE(account_id,operation_id)
) STRICT;
CREATE TRIGGER agent_attribute_commit_immutable BEFORE UPDATE ON agent_attribute_commit
WHEN NEW.proposal_id!=OLD.proposal_id OR NEW.account_id!=OLD.account_id
 OR NEW.operation_id!=OLD.operation_id OR NEW.candidate!=OLD.candidate
 OR NEW.candidate_sha256!=OLD.candidate_sha256 OR NEW.origin!=OLD.origin
 OR NEW.prepared_at!=OLD.prepared_at OR OLD.result_revision IS NOT NULL
 OR NOT EXISTS(SELECT 1 FROM vault_attribute_mutation m JOIN agent_attribute_proposal p
   ON p.proposal_id=NEW.proposal_id WHERE m.account_id=NEW.account_id
   AND m.operation_id=NEW.operation_id AND m.attribute_id=p.attribute_id
   AND m.result_revision=NEW.result_revision AND m.deleted=0
   AND NEW.result_revision=p.base_revision+1 AND p.state='committed')
BEGIN SELECT RAISE(ABORT,'invalid approved commit result'); END;
-- A failed final assertion rolls proposal consumption, head, ledger and audit back together.
CREATE TABLE agent_attribute_commit_guard (
  operation_id TEXT PRIMARY KEY,
  valid INTEGER NOT NULL CHECK(valid=1)
) STRICT;
