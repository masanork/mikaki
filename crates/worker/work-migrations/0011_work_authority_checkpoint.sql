-- Opt-in additive WORK schema after the fresh Owner Vault baseline.
-- Enroll only a quiescent reviewed authority; migration does not enroll/backfill.
CREATE TABLE work_authority_checkpoint (
 id INTEGER PRIMARY KEY CHECK(id=1),
 authority TEXT NOT NULL CHECK(length(authority) BETWEEN 1 AND 128),
 epoch TEXT NOT NULL CHECK(length(epoch)=64 AND epoch NOT GLOB '*[^a-f0-9]*'),
 sequence INTEGER NOT NULL CHECK(sequence BETWEEN 0 AND 9007199254740991),
 tip TEXT NOT NULL CHECK(length(tip)=64 AND tip NOT GLOB '*[^a-f0-9]*')
) STRICT;
CREATE TRIGGER work_authority_checkpoint_monotonic BEFORE UPDATE ON work_authority_checkpoint
WHEN NEW.id IS NOT OLD.id OR NEW.authority IS NOT OLD.authority OR NEW.epoch IS NOT OLD.epoch
 OR NEW.sequence!=OLD.sequence+1 OR NEW.tip IS OLD.tip
BEGIN SELECT RAISE(ABORT,'work_checkpoint_guard_failed'); END;
CREATE TRIGGER work_authority_checkpoint_retained BEFORE DELETE ON work_authority_checkpoint
BEGIN SELECT RAISE(ABORT,'retained authority checkpoint'); END;
