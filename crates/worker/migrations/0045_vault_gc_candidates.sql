-- Record an upload before R2 PUT so a failed head commit is recoverable.
CREATE TABLE vault_gc_candidate (
  object_key TEXT PRIMARY KEY NOT NULL,
  eligible_at INTEGER NOT NULL,
  state TEXT NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','deleting'))
) STRICT;
CREATE INDEX vault_gc_candidate_due ON vault_gc_candidate(eligible_at,object_key);

-- Claiming a candidate for deletion and checking references are atomic in D1.
-- A claimed object cannot become a head while its R2 deletion is in flight.
CREATE TRIGGER vault_gc_head_insert_guard BEFORE INSERT ON vault_attribute_head
WHEN EXISTS(SELECT 1 FROM vault_gc_candidate WHERE object_key=NEW.object_key AND state='deleting')
BEGIN SELECT RAISE(ABORT,'vault_object_retired'); END;
CREATE TRIGGER vault_gc_head_update_guard BEFORE UPDATE OF object_key ON vault_attribute_head
WHEN EXISTS(SELECT 1 FROM vault_gc_candidate WHERE object_key=NEW.object_key AND state='deleting')
BEGIN SELECT RAISE(ABORT,'vault_object_retired'); END;

CREATE TRIGGER vault_gc_head_insert AFTER INSERT ON vault_attribute_head
BEGIN
  DELETE FROM vault_gc_candidate WHERE object_key=NEW.object_key AND state='pending';
END;
CREATE TRIGGER vault_gc_head_update AFTER UPDATE OF object_key ON vault_attribute_head
BEGIN
  INSERT OR IGNORE INTO vault_gc_candidate(object_key,eligible_at)
    SELECT OLD.object_key,unixepoch()+86400
    WHERE OLD.object_key IS NOT NULL AND OLD.object_key IS NOT NEW.object_key;
  DELETE FROM vault_gc_candidate WHERE object_key=NEW.object_key AND state='pending';
END;
CREATE TRIGGER vault_gc_head_delete AFTER DELETE ON vault_attribute_head
BEGIN
  INSERT OR IGNORE INTO vault_gc_candidate(object_key,eligible_at)
    SELECT OLD.object_key,unixepoch()+86400 WHERE OLD.object_key IS NOT NULL;
END;

CREATE TRIGGER vault_gc_record_head_insert_guard BEFORE INSERT ON vault_owner_record_head
WHEN EXISTS(SELECT 1 FROM vault_gc_candidate WHERE object_key=NEW.object_key AND state='deleting')
BEGIN SELECT RAISE(ABORT,'vault_object_retired'); END;
CREATE TRIGGER vault_gc_record_head_update_guard BEFORE UPDATE OF object_key ON vault_owner_record_head
WHEN EXISTS(SELECT 1 FROM vault_gc_candidate WHERE object_key=NEW.object_key AND state='deleting')
BEGIN SELECT RAISE(ABORT,'vault_object_retired'); END;

CREATE TRIGGER vault_gc_record_head_insert AFTER INSERT ON vault_owner_record_head
BEGIN
  DELETE FROM vault_gc_candidate WHERE object_key=NEW.object_key AND state='pending';
END;
CREATE TRIGGER vault_gc_record_head_update AFTER UPDATE OF object_key ON vault_owner_record_head
BEGIN
  INSERT OR IGNORE INTO vault_gc_candidate(object_key,eligible_at)
    SELECT OLD.object_key,unixepoch()+86400
    WHERE OLD.object_key IS NOT NULL AND OLD.object_key IS NOT NEW.object_key;
  DELETE FROM vault_gc_candidate WHERE object_key=NEW.object_key AND state='pending';
END;
CREATE TRIGGER vault_gc_record_head_delete AFTER DELETE ON vault_owner_record_head
BEGIN
  INSERT OR IGNORE INTO vault_gc_candidate(object_key,eligible_at)
    SELECT OLD.object_key,unixepoch()+86400 WHERE OLD.object_key IS NOT NULL;
END;
