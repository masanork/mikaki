-- Opt-in additive managed-work schema after Owner Vault migrations 0001 and 0002.
-- Bounded managed-work admission. Safety revocations/outcomes never need a new slot.
CREATE TABLE work_resource_policy (
 id INTEGER PRIMARY KEY CHECK(id=1),
 disclosures_per_owner INTEGER NOT NULL CHECK(disclosures_per_owner BETWEEN 1 AND 128),
 disclosures_total INTEGER NOT NULL CHECK(disclosures_total BETWEEN 1 AND 4096),
 disclosure_bytes_per_owner INTEGER NOT NULL CHECK(disclosure_bytes_per_owner BETWEEN 1 AND 16777216),
 disclosure_bytes_total INTEGER NOT NULL CHECK(disclosure_bytes_total BETWEEN 1 AND 268435456),
 disclosure_reviews_per_hour INTEGER NOT NULL CHECK(disclosure_reviews_per_hour BETWEEN 1 AND 128),
 requests_per_owner INTEGER NOT NULL CHECK(requests_per_owner BETWEEN 1 AND 1024),
 grants_per_owner INTEGER NOT NULL CHECK(grants_per_owner BETWEEN 1 AND 1024),
 runs_per_owner INTEGER NOT NULL CHECK(runs_per_owner BETWEEN 1 AND 2048),
 candidates_per_owner INTEGER NOT NULL CHECK(candidates_per_owner BETWEEN 1 AND 4096),
 approvals_per_owner INTEGER NOT NULL CHECK(approvals_per_owner BETWEEN 1 AND 4096),
 objects_total INTEGER NOT NULL CHECK(objects_total BETWEEN 1 AND 100000),
 new_audits_per_owner INTEGER NOT NULL CHECK(new_audits_per_owner BETWEEN 1 AND 100000),
 new_audits_total INTEGER NOT NULL CHECK(new_audits_total BETWEEN 1 AND 1000000),
 orphan_retention_seconds INTEGER NOT NULL CHECK(orphan_retention_seconds BETWEEN 86400 AND 2592000)
) STRICT;
INSERT INTO work_resource_policy VALUES(1,32,2048,1048576,67108864,32,128,128,256,512,512,20000,10000,200000,86400);
CREATE TABLE work_disclosure (
 digest TEXT PRIMARY KEY NOT NULL CHECK(length(digest)=64),
 owner_id TEXT NOT NULL REFERENCES account_security(account_id),
 owner_epoch INTEGER NOT NULL CHECK(owner_epoch BETWEEN 0 AND 9007199254740991),
 policy_generation INTEGER NOT NULL CHECK(policy_generation BETWEEN 1 AND 9007199254740991),
 policy_projection TEXT NOT NULL REFERENCES runtime_policy_version(projection_revision),
 expires_at INTEGER NOT NULL, selected_bytes INTEGER NOT NULL CHECK(selected_bytes BETWEEN 0 AND 131072),
 body TEXT NOT NULL CHECK(length(body) BETWEEN 1 AND 32768 AND json_valid(body)
  AND json_extract(body,'$.version') IS 1 AND json_extract(body,'$.kind') IS 'disclosure'
  AND json_extract(body,'$.data.digest') IS digest AND json_extract(body,'$.data.data.owner') IS owner_id
  AND json_extract(body,'$.data.data.owner_epoch') IS owner_epoch AND json_extract(body,'$.data.data.policy_revision') IS policy_generation
  AND json_extract(body,'$.data.data.expires_at') IS expires_at AND json_extract(body,'$.data.data.selected_bytes') IS selected_bytes),
 UNIQUE(digest,owner_id)
) STRICT;
CREATE INDEX work_disclosure_owner ON work_disclosure(owner_id,expires_at);
CREATE INDEX work_disclosure_expiry ON work_disclosure(expires_at);
CREATE TABLE work_request_disclosure (
 request_digest TEXT PRIMARY KEY NOT NULL REFERENCES work_request(digest),
 disclosure_digest TEXT NOT NULL,
 owner_id TEXT NOT NULL,
 FOREIGN KEY(disclosure_digest,owner_id) REFERENCES work_disclosure(digest,owner_id)
) STRICT;
CREATE INDEX work_request_disclosure_manifest ON work_request_disclosure(disclosure_digest);
CREATE TABLE work_disclosure_window (
 owner_id TEXT NOT NULL REFERENCES account_security(account_id), window_start INTEGER NOT NULL,
 attempts INTEGER NOT NULL CHECK(attempts>0), PRIMARY KEY(owner_id,window_start)
) STRICT;
CREATE INDEX work_disclosure_window_expiry ON work_disclosure_window(window_start);
CREATE TRIGGER work_disclosure_window_capacity BEFORE INSERT ON work_disclosure_window
WHEN NOT EXISTS(SELECT 1 FROM work_resource_policy WHERE id=1)
 OR ((SELECT count(*) FROM work_disclosure_window)>=10000 AND NOT EXISTS(
  SELECT 1 FROM work_disclosure_window WHERE owner_id=NEW.owner_id AND window_start=NEW.window_start))
 OR EXISTS(SELECT 1 FROM work_disclosure_window WHERE owner_id=NEW.owner_id AND window_start=NEW.window_start
  AND attempts>=(SELECT disclosure_reviews_per_hour FROM work_resource_policy WHERE id=1))
BEGIN SELECT RAISE(ABORT,'work_resource_exhausted'); END;
CREATE TRIGGER work_disclosure_window_update BEFORE UPDATE ON work_disclosure_window
WHEN NEW.owner_id IS NOT OLD.owner_id OR NEW.window_start IS NOT OLD.window_start
 OR NEW.attempts!=OLD.attempts+1 OR NOT EXISTS(SELECT 1 FROM work_resource_policy WHERE id=1)
 OR NEW.attempts>(SELECT disclosure_reviews_per_hour FROM work_resource_policy WHERE id=1)
BEGIN SELECT RAISE(ABORT,'work_resource_exhausted'); END;
CREATE INDEX work_request_owner ON work_request(owner_id,expires_at);
CREATE INDEX work_run_request ON work_run(request_digest);
CREATE INDEX work_candidate_owner ON work_candidate(owner_id);
CREATE INDEX work_approval_owner ON work_code_approval(owner_id);
CREATE TRIGGER work_disclosure_no_update BEFORE UPDATE ON work_disclosure
BEGIN SELECT RAISE(ABORT,'immutable work disclosure'); END;
CREATE TRIGGER work_disclosure_retention BEFORE DELETE ON work_disclosure
WHEN NOT EXISTS(SELECT 1 FROM work_resource_policy WHERE id=1)
 OR OLD.expires_at>unixepoch()-(SELECT orphan_retention_seconds FROM work_resource_policy WHERE id=1)
 OR EXISTS(SELECT 1 FROM work_request_disclosure WHERE disclosure_digest=OLD.digest)
BEGIN SELECT RAISE(ABORT,'referenced or retained work disclosure'); END;
CREATE TRIGGER work_request_disclosure_no_update BEFORE UPDATE ON work_request_disclosure
BEGIN SELECT RAISE(ABORT,'immutable work disclosure binding'); END;
CREATE TRIGGER work_request_disclosure_no_delete BEFORE DELETE ON work_request_disclosure
BEGIN SELECT RAISE(ABORT,'retained work disclosure binding'); END;
CREATE TRIGGER work_request_disclosure_binding BEFORE INSERT ON work_request_disclosure
WHEN NOT EXISTS(
 SELECT 1 FROM work_request w JOIN work_disclosure d ON d.digest=NEW.disclosure_digest AND d.owner_id=w.owner_id
 JOIN runtime_policy_active p ON p.id=1 AND p.generation=d.policy_generation AND p.projection_revision=d.policy_projection
 JOIN account_security a ON a.account_id=w.owner_id AND a.active=1 AND a.epoch=d.owner_epoch
 WHERE w.digest=NEW.request_digest AND w.owner_id=NEW.owner_id
 AND d.owner_epoch=w.owner_epoch AND d.policy_generation=w.policy_generation AND d.policy_projection=w.policy_projection
 AND d.expires_at>=w.expires_at AND d.expires_at>unixepoch()
 AND json_extract(w.body,'$.data.input.disclosure_digest')=d.digest
 AND json_extract(w.body,'$.data.input.code_repository')=json_extract(d.body,'$.data.data.code.repository')
 AND json_extract(w.body,'$.data.input.base_commit')=json_extract(d.body,'$.data.data.code.commit')
 AND json_extract(w.body,'$.data.input.recipient')=json_extract(d.body,'$.data.data.recipient')
 AND json_extract(w.body,'$.data.input.workload')=json_extract(d.body,'$.data.data.workload')
 AND json_extract(d.body,'$.data.data.snapshot.repository')!=json_extract(w.body,'$.data.input.task_repository')
 AND json_extract(d.body,'$.data.data.snapshot.repository')!=json_extract(w.body,'$.data.input.adoption_repository'))
BEGIN SELECT RAISE(ABORT,'work disclosure binding mismatch'); END;
CREATE TRIGGER work_disclosure_capacity BEFORE INSERT ON work_disclosure
WHEN NOT EXISTS(SELECT 1 FROM work_resource_policy WHERE id=1)
 OR (SELECT count(*) FROM work_disclosure WHERE owner_id=NEW.owner_id)>=(SELECT disclosures_per_owner FROM work_resource_policy WHERE id=1)
 OR (SELECT count(*) FROM work_disclosure)>=(SELECT disclosures_total FROM work_resource_policy WHERE id=1)
 OR NEW.selected_bytes+(SELECT coalesce(sum(selected_bytes),0) FROM work_disclosure WHERE owner_id=NEW.owner_id)>(SELECT disclosure_bytes_per_owner FROM work_resource_policy WHERE id=1)
 OR NEW.selected_bytes+(SELECT coalesce(sum(selected_bytes),0) FROM work_disclosure)>(SELECT disclosure_bytes_total FROM work_resource_policy WHERE id=1)
 OR (SELECT count(*) FROM work_audit WHERE owner_id=NEW.owner_id)>=(SELECT new_audits_per_owner FROM work_resource_policy WHERE id=1)
 OR (SELECT count(*) FROM work_audit)>=(SELECT new_audits_total FROM work_resource_policy WHERE id=1)
BEGIN SELECT RAISE(ABORT,'work_resource_exhausted'); END;
CREATE TRIGGER work_request_capacity BEFORE INSERT ON work_request
WHEN NOT EXISTS(SELECT 1 FROM work_resource_policy WHERE id=1)
 OR (SELECT count(*) FROM work_request WHERE owner_id=NEW.owner_id)>=(SELECT requests_per_owner FROM work_resource_policy WHERE id=1)
 OR (SELECT count(*) FROM work_request)+(SELECT count(*) FROM work_grant)+(SELECT count(*) FROM work_run)+(SELECT count(*) FROM work_candidate)+(SELECT count(*) FROM work_code_approval)>=(SELECT objects_total FROM work_resource_policy WHERE id=1)
 OR (SELECT count(*) FROM work_audit WHERE owner_id=NEW.owner_id)>=(SELECT new_audits_per_owner FROM work_resource_policy WHERE id=1)
 OR (SELECT count(*) FROM work_audit)>=(SELECT new_audits_total FROM work_resource_policy WHERE id=1)
BEGIN SELECT RAISE(ABORT,'work_resource_exhausted'); END;
CREATE TRIGGER work_grant_capacity BEFORE INSERT ON work_grant
WHEN NOT EXISTS(SELECT 1 FROM work_resource_policy WHERE id=1)
 OR (SELECT count(*) FROM work_grant g JOIN work_request w ON w.digest=g.request_digest WHERE w.owner_id=(SELECT owner_id FROM work_request WHERE digest=NEW.request_digest))>=(SELECT grants_per_owner FROM work_resource_policy WHERE id=1)
 OR (SELECT count(*) FROM work_request)+(SELECT count(*) FROM work_grant)+(SELECT count(*) FROM work_run)+(SELECT count(*) FROM work_candidate)+(SELECT count(*) FROM work_code_approval)>=(SELECT objects_total FROM work_resource_policy WHERE id=1)
 OR (SELECT count(*) FROM work_audit WHERE owner_id=(SELECT owner_id FROM work_request WHERE digest=NEW.request_digest))>=(SELECT new_audits_per_owner FROM work_resource_policy WHERE id=1)
 OR (SELECT count(*) FROM work_audit)>=(SELECT new_audits_total FROM work_resource_policy WHERE id=1)
BEGIN SELECT RAISE(ABORT,'work_resource_exhausted'); END;
CREATE TRIGGER work_run_capacity BEFORE INSERT ON work_run
WHEN NOT EXISTS(SELECT 1 FROM work_resource_policy WHERE id=1)
 OR (SELECT count(*) FROM work_run r JOIN work_request w ON w.digest=r.request_digest WHERE w.owner_id=(SELECT owner_id FROM work_request WHERE digest=NEW.request_digest))>=(SELECT runs_per_owner FROM work_resource_policy WHERE id=1)
 OR (SELECT count(*) FROM work_request)+(SELECT count(*) FROM work_grant)+(SELECT count(*) FROM work_run)+(SELECT count(*) FROM work_candidate)+(SELECT count(*) FROM work_code_approval)>=(SELECT objects_total FROM work_resource_policy WHERE id=1)
 OR (SELECT count(*) FROM work_audit WHERE owner_id=(SELECT owner_id FROM work_request WHERE digest=NEW.request_digest))>=(SELECT new_audits_per_owner FROM work_resource_policy WHERE id=1)
 OR (SELECT count(*) FROM work_audit)>=(SELECT new_audits_total FROM work_resource_policy WHERE id=1)
BEGIN SELECT RAISE(ABORT,'work_resource_exhausted'); END;
CREATE TRIGGER work_candidate_capacity BEFORE INSERT ON work_candidate
WHEN NOT EXISTS(SELECT 1 FROM work_resource_policy WHERE id=1)
 OR (SELECT count(*) FROM work_candidate WHERE owner_id=NEW.owner_id)>=(SELECT candidates_per_owner FROM work_resource_policy WHERE id=1)
 OR (SELECT count(*) FROM work_request)+(SELECT count(*) FROM work_grant)+(SELECT count(*) FROM work_run)+(SELECT count(*) FROM work_candidate)+(SELECT count(*) FROM work_code_approval)>=(SELECT objects_total FROM work_resource_policy WHERE id=1)
 OR (SELECT count(*) FROM work_audit WHERE owner_id=NEW.owner_id)>=(SELECT new_audits_per_owner FROM work_resource_policy WHERE id=1)
 OR (SELECT count(*) FROM work_audit)>=(SELECT new_audits_total FROM work_resource_policy WHERE id=1)
BEGIN SELECT RAISE(ABORT,'work_resource_exhausted'); END;
CREATE TRIGGER work_approval_capacity BEFORE INSERT ON work_code_approval
WHEN NOT EXISTS(SELECT 1 FROM work_resource_policy WHERE id=1)
 OR (SELECT count(*) FROM work_code_approval WHERE owner_id=NEW.owner_id)>=(SELECT approvals_per_owner FROM work_resource_policy WHERE id=1)
 OR (SELECT count(*) FROM work_request)+(SELECT count(*) FROM work_grant)+(SELECT count(*) FROM work_run)+(SELECT count(*) FROM work_candidate)+(SELECT count(*) FROM work_code_approval)>=(SELECT objects_total FROM work_resource_policy WHERE id=1)
 OR (SELECT count(*) FROM work_audit WHERE owner_id=NEW.owner_id)>=(SELECT new_audits_per_owner FROM work_resource_policy WHERE id=1)
 OR (SELECT count(*) FROM work_audit)>=(SELECT new_audits_total FROM work_resource_policy WHERE id=1)
BEGIN SELECT RAISE(ABORT,'work_resource_exhausted'); END;
