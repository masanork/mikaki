-- Opt-in additive managed-work schema after Owner Vault migrations 0001 and 0002.
-- Managed-work authority. No credential fields/disclosed file payloads or new OAuth endpoints.
-- Mutable state lives in these rows; immutable JSON is a versioned Rust record.
CREATE TABLE work_task_repository (
 repository_id TEXT PRIMARY KEY NOT NULL,
 owner_id TEXT NOT NULL REFERENCES account_security(account_id),
 revision INTEGER NOT NULL CHECK(revision BETWEEN 1 AND 9007199254740991),
 disclosure_digest TEXT NOT NULL CHECK(length(disclosure_digest)=64),
 recipient TEXT NOT NULL, workload TEXT NOT NULL, code_repository TEXT NOT NULL, base_commit TEXT NOT NULL
) STRICT;
CREATE TABLE work_code_target (
 repository_id TEXT NOT NULL, reference TEXT NOT NULL,
 owner_id TEXT NOT NULL REFERENCES account_security(account_id),
 head TEXT NOT NULL CHECK(length(head) IN(40,64)),
 revision INTEGER NOT NULL CHECK(revision BETWEEN 1 AND 9007199254740991),
 writable INTEGER NOT NULL CHECK(writable IN(0,1)),
 PRIMARY KEY(repository_id,reference)
) STRICT;
CREATE TABLE work_request (
 digest TEXT PRIMARY KEY NOT NULL CHECK(length(digest)=64),
 request_id TEXT NOT NULL, owner_id TEXT NOT NULL REFERENCES account_security(account_id),
 revision INTEGER NOT NULL CHECK(revision BETWEEN 1 AND 9007199254740991),
 owner_epoch INTEGER NOT NULL CHECK(owner_epoch BETWEEN 0 AND 9007199254740991),
 policy_generation INTEGER NOT NULL CHECK(policy_generation BETWEEN 1 AND 9007199254740991),
 policy_projection TEXT NOT NULL REFERENCES runtime_policy_version(projection_revision),
 expires_at INTEGER NOT NULL CHECK(expires_at BETWEEN 1 AND 9007199254740991),
 body TEXT NOT NULL CHECK(length(body) BETWEEN 1 AND 32768 AND json_valid(body)
  AND json_extract(body,'$.version') IS 1 AND json_extract(body,'$.kind') IS 'request'
  AND json_extract(body,'$.data.digest') IS digest AND json_extract(body,'$.data.owner') IS owner_id
  AND json_extract(body,'$.data.input.request_id') IS request_id AND json_extract(body,'$.data.input.revision') IS revision
  AND json_extract(body,'$.data.owner_epoch') IS owner_epoch AND json_extract(body,'$.data.policy_revision') IS policy_generation
  AND json_extract(body,'$.data.input.deadline') IS expires_at),
 UNIQUE(owner_id,request_id,revision,digest)
) STRICT;
CREATE TABLE work_request_head (
 owner_id TEXT NOT NULL, request_id TEXT NOT NULL, revision INTEGER NOT NULL, digest TEXT NOT NULL,
 PRIMARY KEY(owner_id,request_id),
 FOREIGN KEY(owner_id,request_id,revision,digest) REFERENCES work_request(owner_id,request_id,revision,digest)
) STRICT;
CREATE TABLE work_grant (
 grant_id TEXT PRIMARY KEY NOT NULL, request_digest TEXT NOT NULL REFERENCES work_request(digest),
 task_revision INTEGER NOT NULL CHECK(task_revision BETWEEN 1 AND 9007199254740991),
 expires_at INTEGER NOT NULL CHECK(expires_at BETWEEN 1 AND 9007199254740991),
 revision INTEGER NOT NULL DEFAULT 1, revoked INTEGER NOT NULL DEFAULT 0,
 body TEXT NOT NULL CHECK(length(body) BETWEEN 1 AND 32768 AND json_valid(body)
  AND json_extract(body,'$.version') IS 1 AND json_extract(body,'$.kind') IS 'grant'
  AND json_extract(body,'$.data.id') IS grant_id AND json_extract(body,'$.data.request') IS request_digest
  AND json_extract(body,'$.data.task_revision') IS task_revision AND json_extract(body,'$.data.expires_at') IS expires_at),
 CHECK((revision=1 AND revoked=0) OR (revision=2 AND revoked=1)),
 UNIQUE(grant_id,request_digest)
) STRICT;
CREATE TABLE work_run (
 run_id TEXT PRIMARY KEY NOT NULL, grant_id TEXT NOT NULL, request_digest TEXT NOT NULL,
 expires_at INTEGER NOT NULL CHECK(expires_at BETWEEN 1 AND 9007199254740991),
 revision INTEGER NOT NULL DEFAULT 1, revoked INTEGER NOT NULL DEFAULT 0,
 body TEXT NOT NULL CHECK(length(body) BETWEEN 1 AND 32768 AND json_valid(body)
  AND json_extract(body,'$.version') IS 1 AND json_extract(body,'$.kind') IS 'run'
  AND json_extract(body,'$.data.id') IS run_id AND json_extract(body,'$.data.grant') IS grant_id
  AND json_extract(body,'$.data.request') IS request_digest AND json_extract(body,'$.data.expires_at') IS expires_at),
 CHECK((revision=1 AND revoked=0) OR (revision=2 AND revoked=1)),
 FOREIGN KEY(grant_id,request_digest) REFERENCES work_grant(grant_id,request_digest),
 UNIQUE(run_id,grant_id,request_digest)
) STRICT;
CREATE TABLE work_candidate (
 digest TEXT PRIMARY KEY NOT NULL CHECK(length(digest)=64),
 request_digest TEXT NOT NULL REFERENCES work_request(digest),
 owner_id TEXT NOT NULL REFERENCES account_security(account_id), grant_id TEXT NOT NULL, run_id TEXT NOT NULL,
 body TEXT NOT NULL CHECK(length(body) BETWEEN 1 AND 32768 AND json_valid(body)
  AND json_extract(body,'$.version') IS 1 AND json_extract(body,'$.kind') IS 'candidate'
  AND json_extract(body,'$.data.digest') IS digest AND json_extract(body,'$.data.owner') IS owner_id
  AND json_extract(body,'$.data.request') IS request_digest
  AND json_extract(body,'$.data.producer.grant') IS grant_id AND json_extract(body,'$.data.producer.run') IS run_id),
 FOREIGN KEY(run_id,grant_id,request_digest) REFERENCES work_run(run_id,grant_id,request_digest),
 UNIQUE(digest,owner_id)
) STRICT;
CREATE TABLE work_code_approval (
 approval_id TEXT PRIMARY KEY NOT NULL, candidate_digest TEXT NOT NULL, owner_id TEXT NOT NULL,
 owner_epoch INTEGER NOT NULL CHECK(owner_epoch BETWEEN 0 AND 9007199254740991),
 policy_generation INTEGER NOT NULL CHECK(policy_generation BETWEEN 1 AND 9007199254740991),
 policy_projection TEXT NOT NULL REFERENCES runtime_policy_version(projection_revision),
 grant_id TEXT NOT NULL REFERENCES work_grant(grant_id), grant_revision INTEGER NOT NULL CHECK(grant_revision IN(1,2)),
 run_id TEXT NOT NULL REFERENCES work_run(run_id), run_revision INTEGER NOT NULL CHECK(run_revision IN(1,2)),
 target_revision INTEGER NOT NULL CHECK(target_revision BETWEEN 1 AND 9007199254740991),
 expires_at INTEGER NOT NULL CHECK(expires_at BETWEEN 1 AND 9007199254740991),
 revision INTEGER NOT NULL DEFAULT 1, revoked INTEGER NOT NULL DEFAULT 0,
 body TEXT NOT NULL CHECK(length(body) BETWEEN 1 AND 32768 AND json_valid(body)
  AND json_extract(body,'$.version') IS 1 AND json_extract(body,'$.kind') IS 'code_approval'
  AND json_extract(body,'$.data.id') IS approval_id AND json_extract(body,'$.data.candidate') IS candidate_digest
  AND json_extract(body,'$.data.owner') IS owner_id AND json_extract(body,'$.data.owner_epoch') IS owner_epoch
  AND json_extract(body,'$.data.policy_revision') IS policy_generation
  AND json_extract(body,'$.data.producer.grant') IS grant_id AND json_extract(body,'$.data.producer.grant_revision') IS grant_revision
  AND json_extract(body,'$.data.producer.run') IS run_id AND json_extract(body,'$.data.producer.run_revision') IS run_revision
  AND json_extract(body,'$.data.target_revision') IS target_revision AND json_extract(body,'$.data.expires_at') IS expires_at),
 CHECK((revision=1 AND revoked=0) OR (revision=2 AND revoked=1)),
 FOREIGN KEY(candidate_digest,owner_id) REFERENCES work_candidate(digest,owner_id)
) STRICT;
CREATE TABLE work_code_operation (
 operation_id TEXT PRIMARY KEY NOT NULL,
 -- The unique child consumes an approval once, including a later cancellation.
 approval_id TEXT NOT NULL UNIQUE REFERENCES work_code_approval(approval_id),
 owner_id TEXT NOT NULL REFERENCES account_security(account_id),
 state TEXT NOT NULL CHECK(state IN('prepared','dispatched','outcome_unknown','applied','rejected','cancelled')),
 revision INTEGER NOT NULL DEFAULT 1 CHECK(revision BETWEEN 1 AND 9007199254740991),
 receipt TEXT,
 body TEXT NOT NULL CHECK(length(body) BETWEEN 1 AND 32768 AND json_valid(body)
  AND json_extract(body,'$.version') IS 1 AND json_extract(body,'$.kind') IS 'code_operation'
  AND json_extract(body,'$.data.id') IS operation_id AND json_extract(body,'$.data.effect.approval') IS approval_id
  AND json_extract(body,'$.data.effect.owner') IS owner_id),
 CHECK((state IN('applied','rejected') AND receipt IS NOT NULL AND length(receipt) BETWEEN 1 AND 128)
  OR (state NOT IN('applied','rejected') AND receipt IS NULL))
) STRICT;
CREATE TABLE work_target_claim (
 repository_id TEXT NOT NULL, reference TEXT NOT NULL,
 operation_id TEXT NOT NULL UNIQUE REFERENCES work_code_operation(operation_id),
 PRIMARY KEY(repository_id,reference),
 FOREIGN KEY(repository_id,reference) REFERENCES work_code_target(repository_id,reference)
) STRICT;
CREATE TABLE work_transition_guard (
 guard_id TEXT PRIMARY KEY NOT NULL,
 passed INTEGER NOT NULL CONSTRAINT work_guard_passed CHECK(passed=1)
) STRICT;
CREATE TABLE work_audit (
 audit_id TEXT PRIMARY KEY NOT NULL, owner_id TEXT NOT NULL REFERENCES account_security(account_id),
 entity_type TEXT NOT NULL, entity_id TEXT NOT NULL, action TEXT NOT NULL,
 actor TEXT NOT NULL, revision INTEGER NOT NULL, occurred_at INTEGER NOT NULL DEFAULT(unixepoch()),
 from_state TEXT, to_state TEXT, receipt TEXT
) STRICT;
CREATE INDEX work_grant_request ON work_grant(request_digest,revoked);
CREATE INDEX work_run_grant ON work_run(grant_id,revoked);
CREATE INDEX work_candidate_producer ON work_candidate(grant_id,run_id);
CREATE INDEX work_approval_candidate ON work_code_approval(candidate_digest);
CREATE INDEX work_audit_entity ON work_audit(owner_id,entity_type,entity_id,occurred_at);

-- Derived revocations and resolver fences share the parent's transaction/audit
-- failure boundary. They never silently mutate authority without a trace.
CREATE TRIGGER work_grant_revocation_audit AFTER UPDATE ON work_grant
BEGIN INSERT INTO work_audit(audit_id,owner_id,entity_type,entity_id,action,actor,revision)
 SELECT 'grant-revoked:'||NEW.grant_id,owner_id,'grant',NEW.grant_id,'grant.revoked','op-work-authority',NEW.revision
 FROM work_request WHERE digest=NEW.request_digest; END;
CREATE TRIGGER work_target_revision_audit AFTER UPDATE ON work_code_target
BEGIN INSERT INTO work_audit(audit_id,owner_id,entity_type,entity_id,action,actor,revision)
 VALUES(json_array('target',NEW.repository_id,NEW.reference,NEW.revision),NEW.owner_id,'target',
 json_array(NEW.repository_id,NEW.reference),'target.refresh-or-fence','op-work-authority',NEW.revision); END;

CREATE TRIGGER work_task_revision BEFORE UPDATE ON work_task_repository
WHEN NEW.repository_id IS NOT OLD.repository_id OR NEW.owner_id IS NOT OLD.owner_id OR NEW.revision<=OLD.revision
BEGIN SELECT RAISE(ABORT,'work task revision must increase'); END;
CREATE TRIGGER work_target_revision BEFORE UPDATE ON work_code_target
WHEN NEW.repository_id IS NOT OLD.repository_id OR NEW.reference IS NOT OLD.reference OR NEW.owner_id IS NOT OLD.owner_id OR NEW.revision<=OLD.revision
BEGIN SELECT RAISE(ABORT,'work target revision must increase'); END;
CREATE TRIGGER work_head_revision BEFORE UPDATE ON work_request_head
WHEN NEW.owner_id IS NOT OLD.owner_id OR NEW.request_id IS NOT OLD.request_id OR NEW.revision!=OLD.revision+1
BEGIN SELECT RAISE(ABORT,'work request revision must advance once'); END;
CREATE TRIGGER work_head_invalidates AFTER UPDATE ON work_request_head
BEGIN UPDATE work_grant SET revision=2,revoked=1 WHERE request_digest=OLD.digest AND revoked=0; END;
CREATE TRIGGER work_task_invalidates AFTER UPDATE ON work_task_repository
BEGIN UPDATE work_grant SET revision=2,revoked=1 WHERE revoked=0 AND request_digest IN
 (SELECT digest FROM work_request WHERE json_extract(body,'$.data.input.task_repository')=NEW.repository_id); END;
CREATE TRIGGER work_operation_transition BEFORE UPDATE ON work_code_operation
WHEN NEW.operation_id IS NOT OLD.operation_id OR NEW.approval_id IS NOT OLD.approval_id OR NEW.owner_id IS NOT OLD.owner_id
 OR NEW.body IS NOT OLD.body OR NEW.revision!=OLD.revision+1
 OR NOT((OLD.state='prepared' AND NEW.state IN('dispatched','cancelled'))
  OR (OLD.state='dispatched' AND NEW.state IN('outcome_unknown','applied','rejected'))
  OR (OLD.state='outcome_unknown' AND NEW.state IN('applied','rejected')))
BEGIN SELECT RAISE(ABORT,'invalid work operation transition'); END;
CREATE TRIGGER work_claim_no_update BEFORE UPDATE ON work_target_claim
BEGIN SELECT RAISE(ABORT,'work target claim is immutable'); END;
CREATE TRIGGER work_claim_terminal BEFORE DELETE ON work_target_claim
WHEN NOT EXISTS(SELECT 1 FROM work_code_operation WHERE operation_id=OLD.operation_id AND state IN('applied','rejected'))
BEGIN SELECT RAISE(ABORT,'unresolved work target claim'); END;

CREATE VIEW work_live_request AS
SELECT w.* FROM work_request w
 JOIN work_request_head h ON h.digest=w.digest
 JOIN account_security a ON a.account_id=w.owner_id AND a.active=1 AND a.epoch=w.owner_epoch
 JOIN runtime_policy_active p ON p.id=1 AND p.generation=w.policy_generation AND p.projection_revision=w.policy_projection
 JOIN work_task_repository t ON t.repository_id=json_extract(w.body,'$.data.input.task_repository') AND t.owner_id=w.owner_id
  AND t.disclosure_digest=json_extract(w.body,'$.data.input.disclosure_digest')
  AND t.recipient=json_extract(w.body,'$.data.input.recipient') AND t.workload=json_extract(w.body,'$.data.input.workload')
  AND t.code_repository=json_extract(w.body,'$.data.input.code_repository') AND t.base_commit=json_extract(w.body,'$.data.input.base_commit')
 WHERE w.expires_at>unixepoch();
CREATE VIEW work_live_grant AS
SELECT g.* FROM work_grant g JOIN work_live_request w ON w.digest=g.request_digest
 JOIN work_task_repository t ON t.repository_id=json_extract(w.body,'$.data.input.task_repository') AND t.revision=g.task_revision
 WHERE g.revoked=0 AND g.expires_at>unixepoch();
CREATE VIEW work_live_run AS
SELECT r.* FROM work_run r JOIN work_live_grant g ON g.grant_id=r.grant_id AND g.request_digest=r.request_digest
 WHERE r.revoked=0 AND r.expires_at>unixepoch();
-- Human adoption deliberately does not require a live producer or current request head.
CREATE VIEW work_adoption_authority AS
SELECT ap.*, json_extract(c.body,'$.data.adoption_repository') AS repository_id,
 json_extract(c.body,'$.data.adoption_ref') AS reference, json_extract(c.body,'$.data.expected_head') AS expected_head,
 json_extract(c.body,'$.data.commit') AS candidate_commit
 FROM work_code_approval ap JOIN work_candidate c ON c.digest=ap.candidate_digest AND c.owner_id=ap.owner_id
 JOIN work_grant g ON g.grant_id=ap.grant_id AND g.grant_id=c.grant_id AND g.revision=ap.grant_revision
 JOIN work_run r ON r.run_id=ap.run_id AND r.run_id=c.run_id AND r.grant_id=g.grant_id AND r.revision=ap.run_revision
 JOIN account_security a ON a.account_id=ap.owner_id AND a.active=1 AND a.epoch=ap.owner_epoch
 JOIN runtime_policy_active p ON p.id=1 AND p.generation=ap.policy_generation AND p.projection_revision=ap.policy_projection
 JOIN work_code_target t ON t.repository_id=json_extract(c.body,'$.data.adoption_repository')
  AND t.reference=json_extract(c.body,'$.data.adoption_ref') AND t.owner_id=ap.owner_id AND t.writable=1
  AND t.head=json_extract(c.body,'$.data.expected_head') AND t.revision=ap.target_revision AND t.revision<9007199254740991
 WHERE ap.revoked=0 AND ap.expires_at>unixepoch();
CREATE VIEW work_ready_operation AS
SELECT o.* FROM work_code_operation o JOIN work_adoption_authority a ON a.approval_id=o.approval_id
 WHERE o.state='prepared'
 AND json_extract(o.body,'$.data.effect.approval_revision')=a.revision
 AND json_extract(o.body,'$.data.effect.owner')=a.owner_id AND json_extract(o.body,'$.data.effect.owner_epoch')=a.owner_epoch
 AND json_extract(o.body,'$.data.effect.policy_revision')=a.policy_generation
 AND json_extract(o.body,'$.data.effect.producer.grant')=a.grant_id AND json_extract(o.body,'$.data.effect.producer.grant_revision')=a.grant_revision
 AND json_extract(o.body,'$.data.effect.producer.run')=a.run_id AND json_extract(o.body,'$.data.effect.producer.run_revision')=a.run_revision
 AND json_extract(o.body,'$.data.effect.candidate')=a.candidate_digest AND json_extract(o.body,'$.data.effect.target_revision')=a.target_revision
 AND json_extract(o.body,'$.data.effect.repository')=a.repository_id AND json_extract(o.body,'$.data.effect.reference')=a.reference
 AND json_extract(o.body,'$.data.effect.expected_head')=a.expected_head AND json_extract(o.body,'$.data.effect.commit')=a.candidate_commit;

CREATE TRIGGER work_request_no_delete BEFORE DELETE ON work_request
BEGIN SELECT RAISE(ABORT,'work authority retention requires an explicit migration'); END;

CREATE TRIGGER work_candidate_no_delete BEFORE DELETE ON work_candidate
BEGIN SELECT RAISE(ABORT,'work authority retention requires an explicit migration'); END;

CREATE TRIGGER work_audit_no_delete BEFORE DELETE ON work_audit
BEGIN SELECT RAISE(ABORT,'work authority retention requires an explicit migration'); END;

CREATE TRIGGER work_request_head_no_delete BEFORE DELETE ON work_request_head
BEGIN SELECT RAISE(ABORT,'work authority retention requires an explicit migration'); END;

CREATE TRIGGER work_task_repository_no_delete BEFORE DELETE ON work_task_repository
BEGIN SELECT RAISE(ABORT,'work authority retention requires an explicit migration'); END;

CREATE TRIGGER work_code_target_no_delete BEFORE DELETE ON work_code_target
BEGIN SELECT RAISE(ABORT,'work authority retention requires an explicit migration'); END;

CREATE TRIGGER work_grant_no_delete BEFORE DELETE ON work_grant
BEGIN SELECT RAISE(ABORT,'work authority retention requires an explicit migration'); END;

CREATE TRIGGER work_run_no_delete BEFORE DELETE ON work_run
BEGIN SELECT RAISE(ABORT,'work authority retention requires an explicit migration'); END;

CREATE TRIGGER work_code_approval_no_delete BEFORE DELETE ON work_code_approval
BEGIN SELECT RAISE(ABORT,'work authority retention requires an explicit migration'); END;

CREATE TRIGGER work_code_operation_no_delete BEFORE DELETE ON work_code_operation
BEGIN SELECT RAISE(ABORT,'work authority retention requires an explicit migration'); END;
CREATE TRIGGER work_request_no_update BEFORE UPDATE ON work_request
BEGIN SELECT RAISE(ABORT,'immutable work authority record'); END;
CREATE TRIGGER work_candidate_no_update BEFORE UPDATE ON work_candidate
BEGIN SELECT RAISE(ABORT,'immutable work authority record'); END;
CREATE TRIGGER work_audit_no_update BEFORE UPDATE ON work_audit
BEGIN SELECT RAISE(ABORT,'immutable work authority record'); END;
CREATE TRIGGER work_grant_monotonic BEFORE UPDATE ON work_grant
WHEN NEW.body IS NOT OLD.body OR NEW.grant_id IS NOT OLD.grant_id OR NEW.request_digest IS NOT OLD.request_digest OR NEW.task_revision IS NOT OLD.task_revision OR NEW.expires_at IS NOT OLD.expires_at
 OR OLD.revoked=1 OR NEW.revoked!=1 OR NEW.revision!=OLD.revision+1
BEGIN SELECT RAISE(ABORT,'work authority cannot be changed or reactivated'); END;
CREATE TRIGGER work_run_monotonic BEFORE UPDATE ON work_run
WHEN NEW.body IS NOT OLD.body OR NEW.run_id IS NOT OLD.run_id OR NEW.grant_id IS NOT OLD.grant_id OR NEW.request_digest IS NOT OLD.request_digest OR NEW.expires_at IS NOT OLD.expires_at
 OR OLD.revoked=1 OR NEW.revoked!=1 OR NEW.revision!=OLD.revision+1
BEGIN SELECT RAISE(ABORT,'work authority cannot be changed or reactivated'); END;
CREATE TRIGGER work_code_approval_monotonic BEFORE UPDATE ON work_code_approval
WHEN NEW.body IS NOT OLD.body OR NEW.approval_id IS NOT OLD.approval_id OR NEW.candidate_digest IS NOT OLD.candidate_digest OR NEW.owner_id IS NOT OLD.owner_id OR NEW.owner_epoch IS NOT OLD.owner_epoch OR NEW.policy_generation IS NOT OLD.policy_generation OR NEW.policy_projection IS NOT OLD.policy_projection OR NEW.grant_id IS NOT OLD.grant_id OR NEW.grant_revision IS NOT OLD.grant_revision OR NEW.run_id IS NOT OLD.run_id OR NEW.run_revision IS NOT OLD.run_revision OR NEW.target_revision IS NOT OLD.target_revision OR NEW.expires_at IS NOT OLD.expires_at
 OR OLD.revoked=1 OR NEW.revoked!=1 OR NEW.revision!=OLD.revision+1
BEGIN SELECT RAISE(ABORT,'work authority cannot be changed or reactivated'); END;
