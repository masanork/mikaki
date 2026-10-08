-- No certification/backfill of legacy task/request rows. These associations
-- commit verified destinations once; cleanup preserves them as historical facts.
CREATE TABLE work_prepared_task (
 repository_id TEXT PRIMARY KEY NOT NULL REFERENCES work_task_repository(repository_id),
 preparation_id TEXT NOT NULL UNIQUE REFERENCES work_preparation(operation_id),
 preparation_digest TEXT NOT NULL UNIQUE,
 task_repo_id TEXT NOT NULL, snapshot_repo_id TEXT NOT NULL,
 payload_receipt TEXT NOT NULL, credential_receipt TEXT NOT NULL
) STRICT;
CREATE TABLE work_request_preparation (
 request_digest TEXT PRIMARY KEY NOT NULL REFERENCES work_request(digest),
 repository_id TEXT NOT NULL REFERENCES work_prepared_task(repository_id)
) STRICT;
CREATE INDEX work_request_preparation_task ON work_request_preparation(repository_id);

-- One task mapping per already bounded/charged preparation; new audit budgets
-- still apply. Safety revocations/cleanup keep their reserved append path.
CREATE TRIGGER work_prepared_task_capacity BEFORE INSERT ON work_prepared_task
WHEN NOT EXISTS(SELECT 1 FROM work_resource_policy WHERE id=1)
 OR NOT EXISTS(SELECT 1 FROM work_preparation_policy WHERE id=1)
 OR (SELECT count(*) FROM work_audit WHERE owner_id=(SELECT owner_id FROM work_preparation WHERE operation_id=NEW.preparation_id))
    >=(SELECT new_audits_per_owner FROM work_resource_policy WHERE id=1)
 OR (SELECT count(*) FROM work_audit)>=(SELECT new_audits_total FROM work_resource_policy WHERE id=1)
BEGIN SELECT RAISE(ABORT,'work_resource_exhausted'); END;

CREATE VIEW work_prepared_task_current AS
SELECT t.repository_id FROM work_prepared_task t
 JOIN work_task_repository task ON task.repository_id=t.repository_id AND task.revision=1
 JOIN work_preparation p ON p.operation_id=t.preparation_id
 JOIN work_disclosure_source_current d ON d.digest=p.disclosure_digest
 WHERE p.state='verified' AND p.expires_at>unixepoch();

CREATE TRIGGER work_prepared_task_binding BEFORE INSERT ON work_prepared_task
WHEN NOT EXISTS(
 SELECT 1 FROM work_preparation p
 JOIN work_disclosure_source_current current ON current.digest=p.disclosure_digest
 JOIN work_disclosure d ON d.digest=p.disclosure_digest
 JOIN work_task_repository t ON t.repository_id=p.task_repository
 WHERE p.operation_id=NEW.preparation_id AND p.state='verified' AND p.expires_at>unixepoch()
 AND p.digest=NEW.preparation_digest AND p.task_repository=NEW.repository_id
 AND NEW.task_repo_id!=NEW.snapshot_repo_id
 AND json_extract(p.evidence,'$.data.preparation') IS NEW.preparation_digest
 AND json_extract(p.evidence,'$.data.task_repo_id') IS NEW.task_repo_id
 AND json_extract(p.evidence,'$.data.snapshot_repo_id') IS NEW.snapshot_repo_id
 AND json_extract(p.evidence,'$.data.payload_receipt') IS NEW.payload_receipt
 AND json_extract(p.evidence,'$.data.credential_receipt') IS NEW.credential_receipt
 AND t.owner_id=p.owner_id AND t.revision=1 AND t.disclosure_digest=p.disclosure_digest
 AND t.recipient=json_extract(d.body,'$.data.data.recipient')
 AND t.workload=json_extract(d.body,'$.data.data.workload')
 AND t.code_repository=json_extract(d.body,'$.data.data.code.repository')
 AND t.base_commit=json_extract(d.body,'$.data.data.code.commit')
 AND EXISTS(SELECT 1 FROM work_resource_policy WHERE id=1)
 AND EXISTS(SELECT 1 FROM work_preparation_policy WHERE id=1)
 AND NOT EXISTS(SELECT 1 FROM work_prepared_task used JOIN work_preparation old ON old.operation_id=used.preparation_id
  WHERE (old.task_namespace=p.task_namespace AND used.task_repo_id=NEW.task_repo_id)
   OR (old.snapshot_namespace=p.task_namespace AND used.snapshot_repo_id=NEW.task_repo_id)
   OR (old.task_namespace=p.snapshot_namespace AND used.task_repo_id=NEW.snapshot_repo_id)
   OR (old.snapshot_namespace=p.snapshot_namespace AND used.snapshot_repo_id=NEW.snapshot_repo_id)))
BEGIN SELECT RAISE(ABORT,'work_preparation_guard_failed'); END;

CREATE TRIGGER work_request_preparation_binding BEFORE INSERT ON work_request_preparation
WHEN NOT EXISTS(
 SELECT 1 FROM work_request w
 JOIN work_request_disclosure rd ON rd.request_digest=w.digest
 JOIN work_prepared_task t ON t.repository_id=NEW.repository_id
 JOIN work_task_repository task ON task.repository_id=t.repository_id
 JOIN work_prepared_task_current c ON c.repository_id=t.repository_id
 JOIN work_preparation p ON p.operation_id=t.preparation_id
 WHERE w.digest=NEW.request_digest AND json_extract(w.body,'$.data.input.task_repository')=t.repository_id
 AND json_extract(w.body,'$.data.input.disclosure_digest')=p.disclosure_digest
 AND json_extract(w.body,'$.data.input.recipient')=task.recipient
 AND json_extract(w.body,'$.data.input.workload')=task.workload
 AND json_extract(w.body,'$.data.input.code_repository')=task.code_repository
 AND json_extract(w.body,'$.data.input.base_commit')=task.base_commit
 AND json_extract(w.body,'$.data.input.adoption_repository')!=json_extract(p.body,'$.data.plan.binding.snapshot_repository')
 AND rd.disclosure_digest=p.disclosure_digest AND w.owner_id=p.owner_id
 AND w.owner_epoch=p.owner_epoch AND w.policy_generation=p.policy_generation AND w.policy_projection=p.policy_projection
 AND w.expires_at<=p.expires_at AND w.expires_at>unixepoch()
 AND NOT EXISTS(SELECT 1 FROM work_request_preparation old
  JOIN work_request previous ON previous.digest=old.request_digest
  WHERE old.repository_id=t.repository_id AND (previous.owner_id!=w.owner_id OR previous.request_id!=w.request_id)))
BEGIN SELECT RAISE(ABORT,'work_preparation_guard_failed'); END;

CREATE TRIGGER work_prepared_task_no_update BEFORE UPDATE ON work_prepared_task
BEGIN SELECT RAISE(ABORT,'work prepared task is immutable'); END;
CREATE TRIGGER work_prepared_task_no_delete BEFORE DELETE ON work_prepared_task
BEGIN SELECT RAISE(ABORT,'work prepared task is retained'); END;
CREATE TRIGGER work_request_preparation_no_update BEFORE UPDATE ON work_request_preparation
BEGIN SELECT RAISE(ABORT,'work request preparation is immutable'); END;
CREATE TRIGGER work_request_preparation_no_delete BEFORE DELETE ON work_request_preparation
BEGIN SELECT RAISE(ABORT,'work request preparation is retained'); END;
CREATE TRIGGER work_prepared_task_metadata BEFORE UPDATE ON work_task_repository
WHEN EXISTS(SELECT 1 FROM work_prepared_task WHERE repository_id=OLD.repository_id)
 AND (NEW.disclosure_digest IS NOT OLD.disclosure_digest OR NEW.recipient IS NOT OLD.recipient
 OR NEW.workload IS NOT OLD.workload OR NEW.code_repository IS NOT OLD.code_repository OR NEW.base_commit IS NOT OLD.base_commit)
BEGIN SELECT RAISE(ABORT,'work prepared task metadata is immutable'); END;

CREATE TRIGGER work_preparation_invalidates AFTER UPDATE OF state ON work_preparation
WHEN OLD.state='verified' AND NEW.state!='verified'
BEGIN UPDATE work_grant SET revision=2,revoked=1 WHERE revoked=0 AND request_digest IN
 (SELECT r.request_digest FROM work_request_preparation r JOIN work_prepared_task t ON t.repository_id=r.repository_id
  WHERE t.preparation_id=NEW.operation_id); END;

-- Legacy evidence keeps its old SQL shape for qualification/inspection. Product
-- Rust treats an unprepared task as retained-only; it cannot issue new authority.
-- Prepared tasks always require the exact association, including direct SQL races.
DROP VIEW work_live_request;
CREATE VIEW work_live_request AS
SELECT w.* FROM work_request w
 JOIN work_request_head h ON h.digest=w.digest
 JOIN account_security a ON a.account_id=w.owner_id AND a.active=1 AND a.epoch=w.owner_epoch
 JOIN runtime_policy_active p ON p.id=1 AND p.generation=w.policy_generation AND p.projection_revision=w.policy_projection
 JOIN work_task_repository t ON t.repository_id=json_extract(w.body,'$.data.input.task_repository') AND t.owner_id=w.owner_id
  AND t.disclosure_digest=json_extract(w.body,'$.data.input.disclosure_digest')
  AND t.recipient=json_extract(w.body,'$.data.input.recipient') AND t.workload=json_extract(w.body,'$.data.input.workload')
  AND t.code_repository=json_extract(w.body,'$.data.input.code_repository') AND t.base_commit=json_extract(w.body,'$.data.input.base_commit')
 WHERE w.expires_at>unixepoch() AND
 (NOT EXISTS(SELECT 1 FROM work_prepared_task WHERE repository_id=t.repository_id)
 OR EXISTS(SELECT 1 FROM work_request_preparation r JOIN work_prepared_task_current c ON c.repository_id=r.repository_id
  WHERE r.request_digest=w.digest AND r.repository_id=t.repository_id));
