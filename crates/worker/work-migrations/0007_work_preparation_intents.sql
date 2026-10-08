-- Opt-in additive managed-work schema after Owner Vault migrations 0001 and 0002.
-- Pre-remote-I/O admission, fixed destinations and conservative unknown effects.
-- No backfill, repository mutation, credential issuance or product activation.
CREATE TABLE work_preparation_policy (
 id INTEGER PRIMARY KEY CHECK(id=1),
 retained_per_owner INTEGER NOT NULL CHECK(retained_per_owner BETWEEN 1 AND 128),
 retained_total INTEGER NOT NULL CHECK(retained_total BETWEEN 1 AND 4096),
 bytes_per_owner INTEGER NOT NULL CHECK(bytes_per_owner BETWEEN 1 AND 536870912),
 bytes_total INTEGER NOT NULL CHECK(bytes_total BETWEEN 1 AND 4294967296),
 creations_per_hour INTEGER NOT NULL CHECK(creations_per_hour BETWEEN 1 AND 128)
) STRICT;
INSERT INTO work_preparation_policy VALUES(1,16,256,67108864,536870912,16);
CREATE TABLE work_preparation (
 operation_id TEXT PRIMARY KEY NOT NULL CHECK(length(operation_id) BETWEEN 1 AND 128),
 digest TEXT UNIQUE NOT NULL CHECK(length(digest)=64),
 disclosure_digest TEXT UNIQUE NOT NULL REFERENCES work_disclosure(digest),
 owner_id TEXT NOT NULL REFERENCES account_security(account_id),
 owner_epoch INTEGER NOT NULL,
 policy_generation INTEGER NOT NULL,
 policy_projection TEXT NOT NULL REFERENCES runtime_policy_version(projection_revision),
 expires_at INTEGER NOT NULL,
 reserved_bytes INTEGER NOT NULL CHECK(reserved_bytes BETWEEN 0 AND 67239936),
 task_repository TEXT UNIQUE NOT NULL,
 task_namespace TEXT NOT NULL, task_name TEXT NOT NULL,
 snapshot_namespace TEXT NOT NULL, snapshot_name TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN('reserved','dispatched','verified','cleanup_pending','cleaned')),
 revision INTEGER NOT NULL CHECK(revision BETWEEN 1 AND 5),
 evidence TEXT CHECK(evidence IS NULL OR (length(evidence)<=2048 AND json_valid(evidence)
  AND json_extract(evidence,'$.version') IS 1 AND json_extract(evidence,'$.kind') IS 'preparation_evidence'
  AND json_extract(evidence,'$.data.preparation') IS digest)),
 cleanup_receipt TEXT CHECK(cleanup_receipt IS NULL OR (length(cleanup_receipt)=64 AND cleanup_receipt NOT GLOB '*[^0-9a-f]*')),
 body TEXT NOT NULL CHECK(length(body) BETWEEN 1 AND 8192 AND json_valid(body)
  AND json_extract(body,'$.version') IS 1 AND json_extract(body,'$.kind') IS 'preparation'
  AND json_extract(body,'$.data.digest') IS digest
  AND json_extract(body,'$.data.plan.operation_id') IS operation_id
  AND json_extract(body,'$.data.plan.binding.disclosure') IS disclosure_digest
  AND json_extract(body,'$.data.plan.binding.owner') IS owner_id
  AND json_extract(body,'$.data.plan.binding.owner_epoch') IS owner_epoch
  AND json_extract(body,'$.data.plan.binding.policy_revision') IS policy_generation
  AND json_extract(body,'$.data.plan.binding.policy_projection') IS policy_projection
  AND json_extract(body,'$.data.plan.binding.expires_at') IS expires_at
  AND json_extract(body,'$.data.plan.binding.reserved_bytes') IS reserved_bytes
  AND json_extract(body,'$.data.plan.task_repository') IS task_repository
  AND json_extract(body,'$.data.plan.task_namespace') IS task_namespace
  AND json_extract(body,'$.data.plan.task_name') IS task_name
  AND json_extract(body,'$.data.plan.snapshot_namespace') IS snapshot_namespace
  AND json_extract(body,'$.data.plan.snapshot_name') IS snapshot_name),
 UNIQUE(task_namespace,task_name), UNIQUE(snapshot_namespace,snapshot_name),
 CHECK((state='reserved' AND revision=1 AND evidence IS NULL AND cleanup_receipt IS NULL)
  OR (state='dispatched' AND revision=2 AND evidence IS NULL AND cleanup_receipt IS NULL)
  OR (state='verified' AND revision=3 AND evidence IS NOT NULL AND cleanup_receipt IS NULL)
  OR (state='cleanup_pending' AND revision IN(3,4) AND cleanup_receipt IS NULL)
  OR (state='cleaned' AND revision BETWEEN 2 AND 5))
) STRICT;
CREATE INDEX work_preparation_owner ON work_preparation(owner_id,state);
CREATE TABLE work_preparation_window (
 owner_id TEXT NOT NULL REFERENCES account_security(account_id), window_start INTEGER NOT NULL,
 attempts INTEGER NOT NULL CHECK(attempts>0), PRIMARY KEY(owner_id,window_start)
) STRICT;
CREATE INDEX work_preparation_window_expiry ON work_preparation_window(window_start);
CREATE TRIGGER work_preparation_window_capacity BEFORE INSERT ON work_preparation_window
WHEN NOT EXISTS(SELECT 1 FROM work_preparation_policy WHERE id=1)
 OR ((SELECT count(*) FROM work_preparation_window)>=10000 AND NOT EXISTS(
  SELECT 1 FROM work_preparation_window WHERE owner_id=NEW.owner_id AND window_start=NEW.window_start))
 OR EXISTS(SELECT 1 FROM work_preparation_window WHERE owner_id=NEW.owner_id AND window_start=NEW.window_start
  AND attempts>=(SELECT creations_per_hour FROM work_preparation_policy WHERE id=1))
BEGIN SELECT RAISE(ABORT,'work_resource_exhausted'); END;
CREATE TRIGGER work_preparation_window_update BEFORE UPDATE ON work_preparation_window
WHEN NEW.owner_id IS NOT OLD.owner_id OR NEW.window_start IS NOT OLD.window_start
 OR NEW.attempts!=OLD.attempts+1 OR NOT EXISTS(SELECT 1 FROM work_preparation_policy WHERE id=1)
 OR NEW.attempts>(SELECT creations_per_hour FROM work_preparation_policy WHERE id=1)
BEGIN SELECT RAISE(ABORT,'work_resource_exhausted'); END;
CREATE TRIGGER work_preparation_capacity BEFORE INSERT ON work_preparation
WHEN NOT EXISTS(SELECT 1 FROM work_preparation_policy WHERE id=1)
 OR NOT EXISTS(SELECT 1 FROM work_resource_policy WHERE id=1)
 OR (SELECT count(*) FROM work_preparation WHERE owner_id=NEW.owner_id)>=(SELECT retained_per_owner FROM work_preparation_policy WHERE id=1)
 OR (SELECT count(*) FROM work_preparation)>=(SELECT retained_total FROM work_preparation_policy WHERE id=1)
 OR NEW.reserved_bytes+(SELECT coalesce(sum(reserved_bytes),0) FROM work_preparation WHERE owner_id=NEW.owner_id AND state!='cleaned')>(SELECT bytes_per_owner FROM work_preparation_policy WHERE id=1)
 OR NEW.reserved_bytes+(SELECT coalesce(sum(reserved_bytes),0) FROM work_preparation WHERE state!='cleaned')>(SELECT bytes_total FROM work_preparation_policy WHERE id=1)
 OR (SELECT count(*) FROM work_audit WHERE owner_id=NEW.owner_id)>=(SELECT new_audits_per_owner FROM work_resource_policy WHERE id=1)
 OR (SELECT count(*) FROM work_audit)>=(SELECT new_audits_total FROM work_resource_policy WHERE id=1)
BEGIN SELECT RAISE(ABORT,'work_resource_exhausted'); END;
CREATE TRIGGER work_preparation_binding BEFORE INSERT ON work_preparation
WHEN NEW.state!='reserved' OR NEW.revision!=1 OR NOT EXISTS(
 SELECT 1 FROM work_disclosure d JOIN work_disclosure_source_current s ON s.digest=d.digest
 WHERE d.digest=NEW.disclosure_digest AND d.owner_id=NEW.owner_id AND d.owner_epoch=NEW.owner_epoch
 AND d.policy_generation=NEW.policy_generation AND d.policy_projection=NEW.policy_projection
 AND d.expires_at=NEW.expires_at AND d.expires_at>unixepoch()
 AND NEW.reserved_bytes=d.selected_bytes+json_extract(d.body,'$.data.data.code.object_bytes')
 AND json_extract(NEW.body,'$.data.plan.binding.snapshot_repository') IS json_extract(d.body,'$.data.data.snapshot.repository')
 AND NEW.task_repository!=json_extract(d.body,'$.data.data.snapshot.repository')
 AND json_array_length(json_extract(NEW.body,'$.data.plan.binding.source_ids'))=json_array_length(json_extract(d.body,'$.data.data.registered_sources'))
 AND NOT EXISTS(SELECT 1 FROM json_each(NEW.body,'$.data.plan.binding.source_ids') i
  WHERE i.value IS NOT json_extract(d.body,'$.data.data.registered_sources['||i.key||'].source_id') OR i.value=NEW.task_repository))
BEGIN SELECT RAISE(ABORT,'work_source_guard_failed'); END;
CREATE TRIGGER work_preparation_transition BEFORE UPDATE ON work_preparation
WHEN NEW.operation_id IS NOT OLD.operation_id OR NEW.digest IS NOT OLD.digest OR NEW.body IS NOT OLD.body
 OR NEW.disclosure_digest IS NOT OLD.disclosure_digest OR NEW.owner_id IS NOT OLD.owner_id
 OR NEW.owner_epoch IS NOT OLD.owner_epoch OR NEW.policy_generation IS NOT OLD.policy_generation
 OR NEW.policy_projection IS NOT OLD.policy_projection OR NEW.expires_at IS NOT OLD.expires_at
 OR NEW.reserved_bytes IS NOT OLD.reserved_bytes OR NEW.task_repository IS NOT OLD.task_repository
 OR NEW.task_namespace IS NOT OLD.task_namespace OR NEW.task_name IS NOT OLD.task_name
 OR NEW.snapshot_namespace IS NOT OLD.snapshot_namespace OR NEW.snapshot_name IS NOT OLD.snapshot_name
 OR NEW.revision!=OLD.revision+1
 OR (OLD.evidence IS NOT NULL AND NEW.evidence IS NOT OLD.evidence)
 OR NOT ((OLD.state='reserved' AND NEW.state IN('dispatched','cleaned') AND NEW.evidence IS NULL AND NEW.cleanup_receipt IS NULL)
  OR (OLD.state='dispatched' AND NEW.state='verified' AND NEW.evidence IS NOT NULL AND NEW.cleanup_receipt IS NULL)
  OR (OLD.state IN('dispatched','verified') AND NEW.state='cleanup_pending' AND NEW.evidence IS OLD.evidence AND NEW.cleanup_receipt IS NULL)
  OR (OLD.state='cleanup_pending' AND NEW.state='cleaned' AND NEW.evidence IS OLD.evidence AND NEW.cleanup_receipt IS NOT NULL))
BEGIN SELECT RAISE(ABORT,'invalid preparation transition'); END;
CREATE TRIGGER work_preparation_live BEFORE UPDATE ON work_preparation
WHEN NEW.state IN('dispatched','verified') AND (OLD.expires_at<=unixepoch()
 OR NOT EXISTS(SELECT 1 FROM work_disclosure_source_current WHERE digest=OLD.disclosure_digest)
 OR NOT EXISTS(SELECT 1 FROM work_preparation_policy WHERE id=1)
 OR NOT EXISTS(SELECT 1 FROM work_resource_policy WHERE id=1))
BEGIN SELECT RAISE(ABORT,'work_source_guard_failed'); END;
CREATE TRIGGER work_preparation_retention BEFORE DELETE ON work_preparation
BEGIN SELECT RAISE(ABORT,'retained preparation intent'); END;
-- Even an expired unbound disclosure is retained while allocation identity exists.
CREATE TRIGGER work_preparation_disclosure_retention BEFORE DELETE ON work_disclosure
WHEN EXISTS(SELECT 1 FROM work_preparation WHERE disclosure_digest=OLD.digest)
BEGIN SELECT RAISE(ABORT,'referenced preparation disclosure'); END;
