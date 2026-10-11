-- One retained workflow identity per approved preparation. No backfill or effects.
CREATE TABLE work_copy_job (
 preparation_id TEXT PRIMARY KEY NOT NULL REFERENCES work_copy_consent(preparation_id),
 review_digest TEXT NOT NULL CHECK(length(review_digest)=64 AND review_digest NOT GLOB '*[^0-9a-f]*'),
 state TEXT NOT NULL CHECK(state IN('queued','running','blocked','verified')),
 next_step INTEGER NOT NULL CHECK(next_step BETWEEN 0 AND 19),
 inflight INTEGER NOT NULL CHECK(inflight IN(0,1)),
 revision INTEGER NOT NULL CHECK(revision>=1),
 updated_at INTEGER NOT NULL DEFAULT(unixepoch()),
 CHECK((state='verified' AND next_step=19 AND inflight=0) OR (state!='verified' AND next_step<19))
) STRICT;
CREATE TRIGGER work_copy_job_insert BEFORE INSERT ON work_copy_job
WHEN NEW.state!='queued' OR NEW.next_step!=0 OR NEW.inflight!=0 OR NEW.revision!=1
 OR NOT EXISTS(SELECT 1 FROM work_copy_consent_current c JOIN work_preparation p ON p.operation_id=c.preparation_id
 WHERE c.preparation_id=NEW.preparation_id AND c.review_digest=NEW.review_digest AND p.state='reserved')
 OR NOT EXISTS(SELECT 1 FROM work_authority_frame f JOIN work_authority_checkpoint c ON c.id=f.id AND c.sequence=f.sequence AND c.tip=f.tip)
BEGIN SELECT RAISE(ABORT,'work_preparation_guard_failed'); END;
CREATE TRIGGER work_copy_job_update BEFORE UPDATE ON work_copy_job
WHEN NEW.preparation_id IS NOT OLD.preparation_id OR NEW.review_digest IS NOT OLD.review_digest
 OR NEW.revision!=OLD.revision+1 OR OLD.state IN('blocked','verified')
 OR NOT EXISTS(SELECT 1 FROM work_authority_frame f JOIN work_authority_checkpoint c ON c.id=f.id AND c.sequence=f.sequence AND c.tip=f.tip)
 OR NOT (
  (NEW.state='blocked' AND NEW.next_step=OLD.next_step AND NEW.inflight=OLD.inflight)
  OR (OLD.inflight=0 AND NEW.inflight=1 AND NEW.state='running' AND NEW.next_step=OLD.next_step
   AND EXISTS(SELECT 1 FROM work_copy_consent_current c WHERE c.preparation_id=OLD.preparation_id AND c.review_digest=OLD.review_digest))
  OR (OLD.inflight=1 AND NEW.inflight=0 AND NEW.next_step=OLD.next_step+1
   AND ((NEW.state='running' AND EXISTS(SELECT 1 FROM work_copy_consent_current c WHERE c.preparation_id=OLD.preparation_id AND c.review_digest=OLD.review_digest))
    OR (NEW.state='verified' AND NEW.next_step=19 AND EXISTS(SELECT 1 FROM work_preparation p WHERE p.operation_id=OLD.preparation_id AND p.state='verified'))))
 )
BEGIN SELECT RAISE(ABORT,'work_preparation_guard_failed'); END;
CREATE TRIGGER work_copy_job_retained BEFORE DELETE ON work_copy_job
BEGIN SELECT RAISE(ABORT,'retained copy job'); END;
