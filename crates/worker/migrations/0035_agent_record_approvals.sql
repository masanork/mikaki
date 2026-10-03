-- Separate v2 owner-note targets. This never upgrades an existing v1 capability.
ALTER TABLE agent_attribute_capability ADD COLUMN storage_version INTEGER NOT NULL DEFAULT 1 CHECK(storage_version IN(1,2));
ALTER TABLE agent_attribute_capability ADD COLUMN target_origin TEXT;
ALTER TABLE agent_attribute_capability ADD COLUMN target_vault_id TEXT;
ALTER TABLE agent_attribute_capability ADD COLUMN target_collection_id TEXT;
ALTER TABLE agent_attribute_capability ADD COLUMN target_record_id TEXT;
ALTER TABLE agent_attribute_capability ADD COLUMN target_kind TEXT;
ALTER TABLE agent_attribute_capability ADD COLUMN target_ciphertext_sha256 TEXT;
ALTER TABLE agent_attribute_capability ADD COLUMN target_deleted INTEGER;
ALTER TABLE agent_attribute_capability ADD COLUMN target_key_generation INTEGER;
ALTER TABLE agent_attribute_capability ADD COLUMN target_owner_key_revision INTEGER;
ALTER TABLE agent_attribute_proposal ADD COLUMN storage_version INTEGER NOT NULL DEFAULT 1 CHECK(storage_version IN(1,2));
ALTER TABLE agent_attribute_proposal ADD COLUMN target_origin TEXT;
ALTER TABLE agent_attribute_proposal ADD COLUMN target_vault_id TEXT;
ALTER TABLE agent_attribute_proposal ADD COLUMN target_collection_id TEXT;
ALTER TABLE agent_attribute_proposal ADD COLUMN target_record_id TEXT;
ALTER TABLE agent_attribute_proposal ADD COLUMN target_kind TEXT;
ALTER TABLE agent_attribute_proposal ADD COLUMN target_ciphertext_sha256 TEXT;
ALTER TABLE agent_attribute_proposal ADD COLUMN target_deleted INTEGER;
ALTER TABLE agent_attribute_proposal ADD COLUMN target_key_generation INTEGER;
ALTER TABLE agent_attribute_proposal ADD COLUMN target_owner_key_revision INTEGER;
ALTER TABLE agent_attribute_commit ADD COLUMN storage_version INTEGER NOT NULL DEFAULT 1 CHECK(storage_version IN(1,2));
-- The prepared commit's immutable proposal FK binds the complete frozen target
-- and authority. Candidate bytes/digest/operation/origin remain immutable too.
DROP TRIGGER agent_attribute_capability_v1_only;
DROP TRIGGER agent_attribute_proposal_v1_only;
CREATE TRIGGER agent_attribute_capability_source BEFORE INSERT ON agent_attribute_capability
WHEN COALESCE((
 (NEW.storage_version=1 AND EXISTS(SELECT 1 FROM agent_grant g WHERE g.grant_id=NEW.grant_id AND g.storage_version=1)
  AND NEW.target_origin IS NULL AND NEW.target_vault_id IS NULL AND NEW.target_collection_id IS NULL
  AND NEW.target_record_id IS NULL AND NEW.target_kind IS NULL AND NEW.target_ciphertext_sha256 IS NULL
  AND NEW.target_deleted IS NULL AND NEW.target_key_generation IS NULL AND NEW.target_owner_key_revision IS NULL)
 OR (NEW.storage_version=2 AND EXISTS(SELECT 1 FROM agent_grant g WHERE g.grant_id=NEW.grant_id AND g.storage_version=2)
  AND NEW.target_origin IS NOT NULL AND length(NEW.target_origin)>8 AND substr(NEW.target_origin,1,8)='https://'
  AND NEW.target_vault_id IS NOT NULL AND length(NEW.target_vault_id) BETWEEN 1 AND 128
  AND NEW.target_vault_id NOT GLOB '*[^A-Za-z0-9_-]*'
  AND NEW.target_collection_id='personal' AND NEW.target_record_id='owner_note' AND NEW.target_kind='owner_note'
  AND typeof(NEW.base_revision)='integer' AND NEW.base_revision BETWEEN 0 AND 9007199254740990
  AND typeof(NEW.target_deleted)='integer' AND NEW.target_deleted IN(0,1)
  AND typeof(NEW.target_key_generation)='integer' AND NEW.target_key_generation BETWEEN 1 AND 9007199254740991
  AND typeof(NEW.target_owner_key_revision)='integer' AND NEW.target_owner_key_revision BETWEEN 1 AND 9007199254740991
  AND ((NEW.base_revision=0 AND NEW.target_deleted=0 AND NEW.target_ciphertext_sha256 IS NULL)
    OR (NEW.base_revision>0 AND ((NEW.target_deleted=1 AND NEW.target_ciphertext_sha256 IS NULL)
      OR (NEW.target_deleted=0 AND NEW.target_ciphertext_sha256 IS NOT NULL
       AND length(NEW.target_ciphertext_sha256)=43 AND NEW.target_ciphertext_sha256 NOT GLOB '*[^A-Za-z0-9_-]*')))))
),0)=0
BEGIN SELECT RAISE(ABORT,'invalid record capability target'); END;
CREATE TRIGGER agent_attribute_proposal_target_shape BEFORE INSERT ON agent_attribute_proposal
WHEN COALESCE((
 (NEW.storage_version=1 AND EXISTS(SELECT 1 FROM agent_grant g WHERE g.grant_id=NEW.grant_id AND g.storage_version=1)
  AND NEW.target_origin IS NULL AND NEW.target_vault_id IS NULL AND NEW.target_collection_id IS NULL
  AND NEW.target_record_id IS NULL AND NEW.target_kind IS NULL AND NEW.target_ciphertext_sha256 IS NULL
  AND NEW.target_deleted IS NULL AND NEW.target_key_generation IS NULL AND NEW.target_owner_key_revision IS NULL)
 OR (NEW.storage_version=2 AND NEW.state='pending' AND NEW.payload IS NOT NULL
  AND EXISTS(SELECT 1 FROM agent_attribute_capability c JOIN agent_grant g ON g.grant_id=c.grant_id
   WHERE c.grant_id=NEW.grant_id AND g.storage_version=2
   AND c.storage_version=NEW.storage_version AND c.attribute_id=NEW.attribute_id AND c.base_revision=NEW.base_revision
   AND c.grant_revision=NEW.grant_revision AND c.expires_at>=NEW.expires_at
   AND c.target_origin IS NEW.target_origin AND c.target_vault_id IS NEW.target_vault_id
   AND c.target_collection_id IS NEW.target_collection_id AND c.target_record_id IS NEW.target_record_id
   AND c.target_kind IS NEW.target_kind AND c.target_ciphertext_sha256 IS NEW.target_ciphertext_sha256
   AND c.target_deleted IS NEW.target_deleted AND c.target_key_generation IS NEW.target_key_generation
   AND c.target_owner_key_revision IS NEW.target_owner_key_revision))
),0)=0
BEGIN SELECT RAISE(ABORT,'record proposal target requires exact capability'); END;
CREATE TRIGGER agent_attribute_proposal_record_immutable BEFORE UPDATE ON agent_attribute_proposal
WHEN NEW.storage_version IS NOT OLD.storage_version OR NEW.target_origin IS NOT OLD.target_origin
 OR NEW.target_vault_id IS NOT OLD.target_vault_id OR NEW.target_collection_id IS NOT OLD.target_collection_id
 OR NEW.target_record_id IS NOT OLD.target_record_id OR NEW.target_kind IS NOT OLD.target_kind
 OR NEW.target_ciphertext_sha256 IS NOT OLD.target_ciphertext_sha256 OR NEW.target_deleted IS NOT OLD.target_deleted
 OR NEW.target_key_generation IS NOT OLD.target_key_generation OR NEW.target_owner_key_revision IS NOT OLD.target_owner_key_revision
BEGIN SELECT RAISE(ABORT,'record proposal target is immutable'); END;

-- Old attribute edits must not invalidate same-named v2 target capabilities.
DROP TRIGGER agent_attribute_proposal_target_update;
DROP TRIGGER agent_attribute_proposal_target_insert;
CREATE TRIGGER agent_attribute_proposal_target_update AFTER UPDATE OF revision,deleted ON vault_attribute_head
WHEN NEW.attribute_id='owner_note' AND (NEW.revision!=OLD.revision OR NEW.deleted!=OLD.deleted)
BEGIN
 UPDATE agent_attribute_proposal SET state='invalid',payload=NULL
 WHERE storage_version=1 AND grant_id IN(SELECT grant_id FROM agent_grant WHERE account_id=NEW.account_id)
   AND state IN('pending','approved') AND base_revision!=NEW.revision;
END;
CREATE TRIGGER agent_attribute_proposal_target_insert AFTER INSERT ON vault_attribute_head
WHEN NEW.attribute_id='owner_note'
BEGIN
 UPDATE agent_attribute_proposal SET state='invalid',payload=NULL
 WHERE storage_version=1 AND grant_id IN(SELECT grant_id FROM agent_grant WHERE account_id=NEW.account_id)
   AND state IN('pending','approved') AND base_revision!=NEW.revision;
END;
CREATE TRIGGER agent_attribute_proposal_record_update AFTER UPDATE ON vault_owner_record_head
BEGIN
 UPDATE agent_attribute_proposal SET state='invalid',payload=NULL
 WHERE storage_version=2 AND grant_id IN(SELECT grant_id FROM agent_grant WHERE account_id=OLD.account_id)
   AND target_vault_id=OLD.vault_id AND target_collection_id=OLD.collection_id AND target_record_id=OLD.record_id
   AND state IN('pending','approved') AND (base_revision!=NEW.revision OR target_deleted!=NEW.deleted
     OR target_ciphertext_sha256 IS NOT NEW.ciphertext_sha256 OR target_kind IS NOT NEW.kind
     OR target_vault_id IS NOT NEW.vault_id OR target_collection_id IS NOT NEW.collection_id OR target_record_id IS NOT NEW.record_id
     OR OLD.account_id IS NOT NEW.account_id OR NEW.format_version!=2 OR target_key_generation!=NEW.key_generation);
END;
CREATE TRIGGER agent_attribute_proposal_record_insert AFTER INSERT ON vault_owner_record_head
BEGIN
 UPDATE agent_attribute_proposal SET state='invalid',payload=NULL
 WHERE storage_version=2 AND grant_id IN(SELECT grant_id FROM agent_grant WHERE account_id=NEW.account_id)
   AND target_vault_id=NEW.vault_id AND target_collection_id=NEW.collection_id AND target_record_id=NEW.record_id
   AND state IN('pending','approved') AND (base_revision!=NEW.revision OR target_deleted!=NEW.deleted
     OR target_ciphertext_sha256 IS NOT NEW.ciphertext_sha256 OR target_kind IS NOT NEW.kind
     OR NEW.format_version!=2 OR target_key_generation!=NEW.key_generation);
END;
CREATE TRIGGER agent_attribute_proposal_record_delete AFTER DELETE ON vault_owner_record_head
BEGIN
 UPDATE agent_attribute_proposal SET state='invalid',payload=NULL
 WHERE storage_version=2 AND grant_id IN(SELECT grant_id FROM agent_grant WHERE account_id=OLD.account_id)
   AND target_vault_id=OLD.vault_id AND target_collection_id=OLD.collection_id AND target_record_id=OLD.record_id
   AND state IN('pending','approved');
END;
DROP TRIGGER agent_attribute_commit_immutable;
CREATE TRIGGER agent_attribute_commit_source BEFORE INSERT ON agent_attribute_commit
WHEN NEW.result_revision IS NOT NULL OR NOT EXISTS(
 SELECT 1 FROM agent_attribute_proposal p JOIN agent_grant g ON g.grant_id=p.grant_id
 WHERE p.proposal_id=NEW.proposal_id AND p.storage_version=NEW.storage_version
 AND g.storage_version=NEW.storage_version AND g.account_id=NEW.account_id
 AND p.state='approved' AND p.payload IS NOT NULL
 AND (NEW.storage_version=1 OR (p.target_origin=NEW.origin AND json_valid(NEW.candidate)
   AND json_extract(NEW.candidate,'$.format_version')=2
   AND json_extract(NEW.candidate,'$.vault_id')=p.target_vault_id
   AND json_extract(NEW.candidate,'$.kind')=p.target_kind
   AND json_extract(NEW.candidate,'$.revision')=p.base_revision+1
   AND json_extract(NEW.candidate,'$.key_generation')=p.target_key_generation
   AND json_extract(NEW.candidate,'$.owner_key_revision')=p.target_owner_key_revision)))
BEGIN SELECT RAISE(ABORT,'prepared commit source mismatch'); END;
CREATE TRIGGER agent_attribute_commit_immutable BEFORE UPDATE ON agent_attribute_commit
WHEN NEW.proposal_id!=OLD.proposal_id OR NEW.account_id!=OLD.account_id
 OR NEW.operation_id!=OLD.operation_id OR NEW.candidate!=OLD.candidate
 OR NEW.candidate_sha256!=OLD.candidate_sha256 OR NEW.origin!=OLD.origin
 OR NEW.prepared_at!=OLD.prepared_at OR NEW.storage_version!=OLD.storage_version OR OLD.result_revision IS NOT NULL
 OR NOT EXISTS(SELECT 1 FROM agent_attribute_proposal p WHERE p.proposal_id=NEW.proposal_id
   AND p.storage_version=NEW.storage_version AND NEW.result_revision=p.base_revision+1 AND p.state='committed'
   AND ((NEW.storage_version=1 AND EXISTS(SELECT 1 FROM vault_attribute_mutation m
     WHERE m.account_id=NEW.account_id AND m.operation_id=NEW.operation_id AND m.attribute_id=p.attribute_id
     AND m.result_revision=NEW.result_revision AND m.deleted=0))
   OR (NEW.storage_version=2 AND EXISTS(SELECT 1 FROM vault_owner_record_mutation m
     WHERE m.account_id=NEW.account_id AND m.operation_id=NEW.operation_id AND m.result_revision=NEW.result_revision AND m.deleted=0
     AND NEW.origin=p.target_origin AND json_extract(NEW.candidate,'$.vault_id')=p.target_vault_id
     AND json_extract(NEW.candidate,'$.revision')=NEW.result_revision
     AND json_extract(NEW.candidate,'$.kind')=p.target_kind
     AND json_extract(NEW.candidate,'$.key_generation')=p.target_key_generation
     AND json_extract(NEW.candidate,'$.owner_key_revision')=p.target_owner_key_revision))))
BEGIN SELECT RAISE(ABORT,'invalid approved commit result'); END;
