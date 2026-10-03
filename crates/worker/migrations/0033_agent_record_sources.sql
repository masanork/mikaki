-- Explicit single-record v2 disclosure. Existing grants remain format-1 attributes.
-- No recipient is provisioned and no existing grant gains record/proposal authority.
ALTER TABLE agent_grant ADD COLUMN storage_version INTEGER NOT NULL DEFAULT 1 CHECK(storage_version IN(1,2));
ALTER TABLE agent_grant ADD COLUMN source_origin TEXT;
ALTER TABLE agent_grant ADD COLUMN source_vault_id TEXT;
ALTER TABLE agent_grant ADD COLUMN source_collection_id TEXT;
ALTER TABLE agent_grant ADD COLUMN source_record_id TEXT;
ALTER TABLE agent_grant ADD COLUMN source_kind TEXT;
ALTER TABLE agent_grant ADD COLUMN source_ciphertext_sha256 TEXT;
ALTER TABLE agent_grant ADD COLUMN source_key_generation INTEGER;
ALTER TABLE agent_grant ADD COLUMN source_owner_key_revision INTEGER;

CREATE TRIGGER agent_grant_source_shape BEFORE INSERT ON agent_grant
WHEN COALESCE((
  (NEW.storage_version=1 AND NEW.source_origin IS NULL AND NEW.source_vault_id IS NULL
    AND NEW.source_collection_id IS NULL AND NEW.source_record_id IS NULL AND NEW.source_kind IS NULL
    AND NEW.source_ciphertext_sha256 IS NULL AND NEW.source_key_generation IS NULL
    AND NEW.source_owner_key_revision IS NULL)
  OR (NEW.storage_version=2 AND NEW.source_origin IS NOT NULL AND NEW.source_vault_id IS NOT NULL
    AND NEW.source_collection_id='personal' AND NEW.source_record_id IN('name','owner_note')
    AND NEW.source_kind=NEW.source_record_id AND NEW.source_ciphertext_sha256 IS NOT NULL
    AND length(NEW.source_ciphertext_sha256)=43
    AND typeof(NEW.source_key_generation)='integer' AND NEW.source_key_generation BETWEEN 1 AND 9007199254740991
    AND typeof(NEW.source_owner_key_revision)='integer' AND NEW.source_owner_key_revision BETWEEN 1 AND 9007199254740991
    AND typeof(NEW.source_revision)='integer' AND NEW.source_revision BETWEEN 1 AND 9007199254740991
    AND json_valid(NEW.document_ids) AND json_array_length(NEW.document_ids)=1
    AND json_extract(NEW.document_ids,'$[0]')=NEW.source_record_id)
),0)=0
BEGIN SELECT RAISE(ABORT,'invalid agent source'); END;

CREATE TRIGGER agent_grant_source_immutable BEFORE UPDATE ON agent_grant
WHEN NEW.storage_version IS NOT OLD.storage_version OR NEW.account_id IS NOT OLD.account_id
  OR NEW.document_ids IS NOT OLD.document_ids
  OR NEW.source_revision IS NOT OLD.source_revision OR NEW.source_origin IS NOT OLD.source_origin
  OR NEW.source_vault_id IS NOT OLD.source_vault_id OR NEW.source_collection_id IS NOT OLD.source_collection_id
  OR NEW.source_record_id IS NOT OLD.source_record_id OR NEW.source_kind IS NOT OLD.source_kind
  OR NEW.source_ciphertext_sha256 IS NOT OLD.source_ciphertext_sha256
  OR NEW.source_key_generation IS NOT OLD.source_key_generation
  OR NEW.source_owner_key_revision IS NOT OLD.source_owner_key_revision
  OR (NEW.encrypted_snapshot IS NOT OLD.encrypted_snapshot AND NEW.encrypted_snapshot IS NOT NULL)
  OR (OLD.revoked=1 AND NEW.revoked!=1)
BEGIN SELECT RAISE(ABORT,'agent source is immutable and cannot be restored'); END;

CREATE TRIGGER agent_grant_snapshot_clear AFTER UPDATE OF revoked ON agent_grant
WHEN NEW.revoked=1 AND NEW.encrypted_snapshot IS NOT NULL
BEGIN
  UPDATE agent_grant SET encrypted_snapshot=NULL WHERE grant_id=NEW.grant_id;
END;

-- Legacy name changes cannot invalidate an unrelated v2 name/note grant.
DROP TRIGGER agent_grant_source_change;
CREATE TRIGGER agent_grant_source_change AFTER UPDATE OF revision,deleted ON vault_attribute_head
WHEN NEW.attribute_id='name' AND (NEW.revision!=OLD.revision OR NEW.deleted=1)
BEGIN
  UPDATE agent_grant SET revoked=1,revision=revision+1,encrypted_snapshot=NULL
  WHERE storage_version=1 AND account_id=NEW.account_id AND revoked=0
    AND (source_revision!=NEW.revision OR NEW.deleted=1);
END;
CREATE TRIGGER agent_grant_attribute_delete AFTER DELETE ON vault_attribute_head
WHEN OLD.attribute_id='name'
BEGIN
  UPDATE agent_grant SET revoked=1,revision=revision+1,encrypted_snapshot=NULL
  WHERE storage_version=1 AND account_id=OLD.account_id AND revoked=0;
END;

CREATE TRIGGER agent_grant_record_change AFTER UPDATE ON vault_owner_record_head
WHEN NEW.account_id IS NOT OLD.account_id OR NEW.vault_id IS NOT OLD.vault_id
  OR NEW.collection_id IS NOT OLD.collection_id OR NEW.record_id IS NOT OLD.record_id
  OR NEW.kind IS NOT OLD.kind OR NEW.revision IS NOT OLD.revision
  OR NEW.ciphertext_sha256 IS NOT OLD.ciphertext_sha256 OR NEW.key_generation IS NOT OLD.key_generation
  OR NEW.format_version IS NOT OLD.format_version OR NEW.deleted=1
BEGIN
  UPDATE agent_grant SET revoked=1,revision=revision+1,encrypted_snapshot=NULL
  WHERE storage_version=2 AND account_id=OLD.account_id AND source_vault_id=OLD.vault_id
    AND source_collection_id=OLD.collection_id AND source_record_id=OLD.record_id AND revoked=0;
END;
CREATE TRIGGER agent_grant_record_delete AFTER DELETE ON vault_owner_record_head
BEGIN
  UPDATE agent_grant SET revoked=1,revision=revision+1,encrypted_snapshot=NULL
  WHERE storage_version=2 AND account_id=OLD.account_id AND source_vault_id=OLD.vault_id
    AND source_collection_id=OLD.collection_id AND source_record_id=OLD.record_id AND revoked=0;
END;
CREATE TRIGGER agent_grant_owner_key_change AFTER UPDATE ON vault_owner_key_head
WHEN NEW.account_id IS NOT OLD.account_id OR NEW.vault_id IS NOT OLD.vault_id
  OR NEW.origin IS NOT OLD.origin OR NEW.key_generation IS NOT OLD.key_generation
  OR NEW.revision IS NOT OLD.revision OR NEW.format_version IS NOT OLD.format_version
  OR NEW.suite IS NOT OLD.suite
BEGIN
  UPDATE agent_grant SET revoked=1,revision=revision+1,encrypted_snapshot=NULL
  WHERE storage_version=2 AND account_id=OLD.account_id AND source_vault_id=OLD.vault_id AND revoked=0;
END;
CREATE TRIGGER agent_grant_owner_key_delete AFTER DELETE ON vault_owner_key_head
BEGIN
  UPDATE agent_grant SET revoked=1,revision=revision+1,encrypted_snapshot=NULL
  WHERE storage_version=2 AND account_id=OLD.account_id AND source_vault_id=OLD.vault_id AND revoked=0;
END;

-- Legacy typed-attribute capabilities are never a capability to mutate v2 records.
CREATE TRIGGER agent_attribute_capability_v1_only BEFORE INSERT ON agent_attribute_capability
WHEN NOT EXISTS(SELECT 1 FROM agent_grant WHERE grant_id=NEW.grant_id AND storage_version=1)
BEGIN SELECT RAISE(ABORT,'legacy attribute capability requires a v1 grant'); END;
CREATE TRIGGER agent_attribute_proposal_v1_only BEFORE INSERT ON agent_attribute_proposal
WHEN NOT EXISTS(SELECT 1 FROM agent_grant WHERE grant_id=NEW.grant_id AND storage_version=1)
BEGIN SELECT RAISE(ABORT,'legacy attribute proposal requires a v1 grant'); END;
