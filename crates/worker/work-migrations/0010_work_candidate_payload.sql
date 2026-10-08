-- Private Git payload retention, not a backfill or a remote cleanup capability.
CREATE TABLE work_candidate_payload_policy (
 id INTEGER PRIMARY KEY CHECK(id=1),
 bytes_per_owner INTEGER NOT NULL CHECK(bytes_per_owner BETWEEN 1 AND 1073741824),
 bytes_total INTEGER NOT NULL CHECK(bytes_total BETWEEN 1 AND 17179869184)
) STRICT;
INSERT INTO work_candidate_payload_policy VALUES(1,67108864,1073741824);
CREATE TABLE work_candidate_payload (
 candidate_digest TEXT PRIMARY KEY NOT NULL REFERENCES work_candidate(digest),
 preparation_id TEXT NOT NULL REFERENCES work_preparation(operation_id),
 owner_id TEXT NOT NULL REFERENCES account_security(account_id),
 digest TEXT UNIQUE NOT NULL CHECK(length(digest)=64 AND digest NOT GLOB '*[^a-f0-9]*'),
 object_key TEXT UNIQUE NOT NULL, bundle_bytes INTEGER NOT NULL CHECK(bundle_bytes BETWEEN 1 AND 8388608),
 state TEXT NOT NULL CHECK(state IN('reserved','retained')), revision INTEGER NOT NULL,
 body TEXT NOT NULL CHECK(length(body)<=4096 AND json_valid(body)
  AND json_extract(body,'$.version') IS 1 AND json_extract(body,'$.kind') IS 'candidate_payload'
  AND json_extract(body,'$.data.digest') IS digest AND json_extract(body,'$.data.data.candidate') IS candidate_digest
  AND json_extract(body,'$.data.data.preparation_id') IS preparation_id AND json_extract(body,'$.data.data.owner') IS owner_id
  AND json_extract(body,'$.data.data.bundle_bytes') IS bundle_bytes
  AND json_extract(body,'$.data.data.format') IS 'git-bundle-v2-sha1'),
 CHECK((state='reserved' AND revision=1) OR (state='retained' AND revision=2))
) STRICT;
CREATE INDEX work_candidate_payload_preparation ON work_candidate_payload(preparation_id,candidate_digest);
CREATE INDEX work_candidate_payload_owner ON work_candidate_payload(owner_id);
CREATE TRIGGER work_candidate_payload_binding BEFORE INSERT ON work_candidate_payload
WHEN NEW.state!='reserved' OR NEW.revision!=1 OR NOT EXISTS(
 SELECT 1 FROM work_candidate c JOIN work_request w ON w.digest=c.request_digest
 JOIN work_request_preparation rp ON rp.request_digest=w.digest
 JOIN work_prepared_task t ON t.repository_id=rp.repository_id
 JOIN work_preparation p ON p.operation_id=t.preparation_id
 WHERE c.digest=NEW.candidate_digest AND c.owner_id=NEW.owner_id AND p.owner_id=NEW.owner_id
 AND p.operation_id=NEW.preparation_id AND p.state IN('verified','cleanup_pending')
 AND json_extract(NEW.body,'$.data.data.request') IS c.request_digest
 AND json_extract(NEW.body,'$.data.data.preparation_digest') IS p.digest
 AND json_extract(NEW.body,'$.data.data.task_repo_id') IS t.task_repo_id
 AND json_extract(NEW.body,'$.data.data.commit') IS json_extract(c.body,'$.data.commit')
 AND json_extract(NEW.body,'$.data.data.tree') IS json_extract(c.body,'$.data.tree')
 AND json_extract(NEW.body,'$.data.data.base_commit') IS json_extract(w.body,'$.data.input.base_commit')
 AND NEW.object_key IS 'work-candidate/v1/'||p.digest||'/'||c.digest||'/'||json_extract(NEW.body,'$.data.data.bundle_digest')||'.bundle')
BEGIN SELECT RAISE(ABORT,'work_preparation_guard_failed'); END;
CREATE TRIGGER work_candidate_payload_capacity BEFORE INSERT ON work_candidate_payload
WHEN NOT EXISTS(SELECT 1 FROM work_candidate_payload_policy WHERE id=1)
 OR NEW.bundle_bytes+(SELECT coalesce(sum(bundle_bytes),0) FROM work_candidate_payload WHERE owner_id=NEW.owner_id)>(SELECT bytes_per_owner FROM work_candidate_payload_policy WHERE id=1)
 OR NEW.bundle_bytes+(SELECT coalesce(sum(bundle_bytes),0) FROM work_candidate_payload)>(SELECT bytes_total FROM work_candidate_payload_policy WHERE id=1)
BEGIN SELECT RAISE(ABORT,'work_resource_exhausted'); END;
CREATE TRIGGER work_candidate_payload_immutable BEFORE UPDATE ON work_candidate_payload
WHEN NEW.body IS NOT OLD.body OR NEW.candidate_digest IS NOT OLD.candidate_digest OR NEW.preparation_id IS NOT OLD.preparation_id
 OR NEW.owner_id IS NOT OLD.owner_id OR NEW.digest IS NOT OLD.digest OR NEW.object_key IS NOT OLD.object_key
 OR NEW.bundle_bytes IS NOT OLD.bundle_bytes OR OLD.state!='reserved' OR NEW.state!='retained' OR NEW.revision!=2
BEGIN SELECT RAISE(ABORT,'invalid candidate payload transition'); END;
CREATE TRIGGER work_candidate_payload_retained BEFORE DELETE ON work_candidate_payload
BEGIN SELECT RAISE(ABORT,'retained candidate payload'); END;
-- Fix the maximum closure read set before adding product candidates. Legacy
-- metadata remains untouched; oversized historical sets need an export profile.
CREATE TRIGGER work_candidate_payload_set_capacity BEFORE INSERT ON work_candidate
WHEN EXISTS(SELECT 1 FROM work_request_preparation WHERE request_digest=NEW.request_digest)
 AND (SELECT count(*) FROM work_candidate c JOIN work_request_preparation old ON old.request_digest=c.request_digest
  JOIN work_request_preparation incoming ON incoming.request_digest=NEW.request_digest
  WHERE old.repository_id=incoming.repository_id)>=16
BEGIN SELECT RAISE(ABORT,'work_resource_exhausted'); END;
CREATE TRIGGER work_preparation_candidate_payload_close BEFORE UPDATE ON work_preparation
WHEN NEW.state='cleaned' AND EXISTS(
 SELECT 1 FROM work_candidate c JOIN work_request_preparation rp ON rp.request_digest=c.request_digest
 JOIN work_prepared_task t ON t.repository_id=rp.repository_id
 LEFT JOIN work_candidate_payload archive ON archive.candidate_digest=c.digest AND archive.preparation_id=NEW.operation_id AND archive.state='retained'
 WHERE t.preparation_id=NEW.operation_id AND archive.candidate_digest IS NULL)
BEGIN SELECT RAISE(ABORT,'work_preparation_guard_failed'); END;
