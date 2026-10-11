-- Opt-in additive managed-work schema after Owner Vault migrations 0001 and 0002.
-- Private OP service custody. No credentials/backfill, HTTP or remote issuance.
CREATE TABLE work_credential_policy (
 id INTEGER PRIMARY KEY CHECK(id=1),
 retained_per_owner INTEGER NOT NULL CHECK(retained_per_owner BETWEEN 1 AND 768),
 retained_total INTEGER NOT NULL CHECK(retained_total BETWEEN 1 AND 24576),
 bytes_per_owner INTEGER NOT NULL CHECK(bytes_per_owner BETWEEN 8192 AND 16777216),
 bytes_total INTEGER NOT NULL CHECK(bytes_total BETWEEN 8192 AND 268435456),
 key_versions INTEGER NOT NULL CHECK(key_versions BETWEEN 1 AND 64)
) STRICT;
INSERT INTO work_credential_policy VALUES(1,96,1536,1048576,16777216,32);
CREATE TABLE work_credential_key (
 version INTEGER PRIMARY KEY CHECK(version BETWEEN 1 AND 9007199254740991),
 fingerprint TEXT UNIQUE NOT NULL CHECK(length(fingerprint)=64 AND fingerprint NOT GLOB '*[^a-f0-9]*'),
 state TEXT NOT NULL CHECK(state IN('active','decrypt_only','retired'))
) STRICT;
CREATE UNIQUE INDEX work_credential_one_active_key ON work_credential_key(state) WHERE state='active';
CREATE TABLE work_credential_key_audit (
 event_id TEXT PRIMARY KEY NOT NULL, version INTEGER NOT NULL REFERENCES work_credential_key(version),
 state TEXT NOT NULL CHECK(state IN('active','decrypt_only','retired')), recorded_at INTEGER NOT NULL DEFAULT(unixepoch())
) STRICT;
CREATE TRIGGER work_credential_key_insert BEFORE INSERT ON work_credential_key
WHEN NEW.state!='active' OR NEW.version<=(SELECT coalesce(max(version),0) FROM work_credential_key)
 OR NOT EXISTS(SELECT 1 FROM work_credential_policy WHERE id=1)
 OR (SELECT count(*) FROM work_credential_key)>=(SELECT key_versions FROM work_credential_policy WHERE id=1)
BEGIN SELECT RAISE(ABORT,'work_resource_exhausted'); END;
CREATE TRIGGER work_credential_key_update BEFORE UPDATE ON work_credential_key
WHEN NEW.version IS NOT OLD.version OR NEW.fingerprint IS NOT OLD.fingerprint
 OR NOT ((OLD.state='active' AND NEW.state='decrypt_only') OR (OLD.state='decrypt_only' AND NEW.state='retired'))
 OR (NEW.state='retired' AND EXISTS(SELECT 1 FROM work_credential_attempt WHERE key_version=OLD.version AND envelope IS NOT NULL))
BEGIN SELECT RAISE(ABORT,'invalid credential key transition'); END;
CREATE TRIGGER work_credential_key_delete BEFORE DELETE ON work_credential_key BEGIN SELECT RAISE(ABORT,'retained credential key'); END;
CREATE TRIGGER work_credential_key_audit_update BEFORE UPDATE ON work_credential_key_audit BEGIN SELECT RAISE(ABORT,'immutable key audit'); END;
CREATE TRIGGER work_credential_key_audit_delete BEFORE DELETE ON work_credential_key_audit BEGIN SELECT RAISE(ABORT,'retained key audit'); END;

CREATE TABLE work_preparation_repository (
 preparation_id TEXT NOT NULL REFERENCES work_preparation(operation_id), role TEXT NOT NULL CHECK(role IN('task','snapshot')),
 namespace TEXT NOT NULL, name TEXT NOT NULL, repo_id TEXT NOT NULL CHECK(length(repo_id) BETWEEN 1 AND 128 AND repo_id NOT GLOB '*[^A-Za-z0-9_.:-]*'),
 PRIMARY KEY(preparation_id,role), UNIQUE(namespace,name), UNIQUE(namespace,repo_id)
) STRICT;
CREATE TRIGGER work_preparation_repository_binding BEFORE INSERT ON work_preparation_repository
WHEN NOT EXISTS(SELECT 1 FROM work_preparation p WHERE p.operation_id=NEW.preparation_id AND p.state IN('dispatched','cleanup_pending')
 AND NEW.namespace=CASE NEW.role WHEN 'task' THEN p.task_namespace ELSE p.snapshot_namespace END
 AND NEW.name=CASE NEW.role WHEN 'task' THEN p.task_name ELSE p.snapshot_name END)
 OR EXISTS(SELECT 1 FROM work_prepared_task t JOIN work_preparation p ON p.operation_id=t.preparation_id
 WHERE (p.task_namespace=NEW.namespace AND t.task_repo_id=NEW.repo_id)
 OR (p.snapshot_namespace=NEW.namespace AND t.snapshot_repo_id=NEW.repo_id))
BEGIN SELECT RAISE(ABORT,'work_preparation_guard_failed'); END;
CREATE TRIGGER work_preparation_repository_update BEFORE UPDATE ON work_preparation_repository BEGIN SELECT RAISE(ABORT,'immutable preparation repository'); END;
CREATE TRIGGER work_preparation_repository_delete BEFORE DELETE ON work_preparation_repository BEGIN SELECT RAISE(ABORT,'retained preparation repository'); END;

CREATE TABLE work_credential_attempt (
 attempt_id TEXT PRIMARY KEY NOT NULL CHECK(length(attempt_id) BETWEEN 1 AND 128 AND attempt_id NOT GLOB '*[^A-Za-z0-9_.:-]*'),
 digest TEXT UNIQUE NOT NULL CHECK(length(digest)=64),
 preparation_id TEXT NOT NULL REFERENCES work_preparation(operation_id), owner_id TEXT NOT NULL REFERENCES account_security(account_id),
 role TEXT NOT NULL CHECK(role IN('task','snapshot')), purpose TEXT NOT NULL CHECK(purpose IN('initial','upload','readback')),
 state TEXT NOT NULL CHECK(state IN('reserved','dispatched','captured','revocation_pending','closed')),
 revision INTEGER NOT NULL CHECK(revision BETWEEN 1 AND 5), reserved_bytes INTEGER NOT NULL CHECK(reserved_bytes=8192),
 dispatched INTEGER NOT NULL CHECK(dispatched IN(0,1)),
 observation TEXT CHECK(observation IS NULL OR (length(observation)<=2048 AND json_valid(observation)
  AND json_extract(observation,'$.version') IS 1 AND json_extract(observation,'$.kind') IS 'credential_observation'
  AND json_extract(observation,'$.data.attempt_digest') IS digest)),
 key_version INTEGER REFERENCES work_credential_key(version),
 nonce TEXT CHECK(nonce IS NULL OR (length(nonce)=16 AND nonce NOT GLOB '*[^A-Za-z0-9_-]*')),
 envelope TEXT CHECK(envelope IS NULL OR (length(envelope)<=8192 AND json_valid(envelope)
  AND json_extract(envelope,'$.version') IS 1 AND json_extract(envelope,'$.kind') IS 'credential_envelope'
  AND json_extract(envelope,'$.data.version') IS 1 AND json_extract(envelope,'$.data.key_version') IS key_version
  AND json_extract(envelope,'$.data.nonce') IS nonce)),
 confirmation TEXT CHECK(confirmation IS NULL OR confirmation IN('refused','expired','not_issued')),
 receipt TEXT CHECK(receipt IS NULL OR (length(receipt)=64 AND receipt NOT GLOB '*[^a-f0-9]*')),
 body TEXT NOT NULL CHECK(length(body)<=4096 AND json_valid(body)
  AND json_extract(body,'$.version') IS 1 AND json_extract(body,'$.kind') IS 'credential_attempt'
  AND json_extract(body,'$.data.digest') IS digest AND json_extract(body,'$.data.plan.id') IS attempt_id
  AND json_extract(body,'$.data.plan.preparation_id') IS preparation_id AND json_extract(body,'$.data.plan.owner_id') IS owner_id
  AND json_extract(body,'$.data.plan.role') IS role AND json_extract(body,'$.data.plan.purpose') IS purpose),
 UNIQUE(preparation_id,role,purpose),
 CHECK((state IN('reserved','dispatched') AND observation IS NULL AND envelope IS NULL AND key_version IS NULL AND confirmation IS NULL AND receipt IS NULL)
 OR (state='captured' AND dispatched=1 AND observation IS NOT NULL AND envelope IS NOT NULL AND key_version IS NOT NULL AND confirmation IS NULL AND receipt IS NULL)
 OR (state='revocation_pending' AND (observation IS NOT NULL OR (envelope IS NULL AND key_version IS NULL)) AND (observation IS NULL OR dispatched=1) AND (envelope IS NULL OR key_version IS NOT NULL) AND confirmation IS NULL AND receipt IS NULL)
 OR (state='closed' AND envelope IS NULL AND receipt IS NOT NULL AND confirmation IS NOT NULL AND ((confirmation='not_issued' AND observation IS NULL AND key_version IS NULL) OR (confirmation IN('refused','expired') AND observation IS NOT NULL AND dispatched=1)))),
 CHECK((key_version IS NULL AND nonce IS NULL) OR (key_version IS NOT NULL AND nonce IS NOT NULL))
) STRICT;
CREATE INDEX work_credential_owner ON work_credential_attempt(owner_id,state);
CREATE UNIQUE INDEX work_credential_nonce_unique ON work_credential_attempt(key_version,nonce) WHERE nonce IS NOT NULL;
CREATE TRIGGER work_credential_attempt_insert BEFORE INSERT ON work_credential_attempt
WHEN NEW.state!='reserved' OR NEW.revision!=1 OR NEW.dispatched!=0
 OR NOT EXISTS(SELECT 1 FROM work_preparation p JOIN work_disclosure_source_current d ON d.digest=p.disclosure_digest
 WHERE p.operation_id=NEW.preparation_id AND p.owner_id=NEW.owner_id AND p.state='dispatched' AND p.expires_at>unixepoch()
 AND json_extract(NEW.body,'$.data.plan.preparation_digest') IS p.digest AND json_extract(NEW.body,'$.data.plan.deadline') IS p.expires_at
 AND json_extract(NEW.body,'$.data.plan.namespace') IS CASE NEW.role WHEN 'task' THEN p.task_namespace ELSE p.snapshot_namespace END
 AND json_extract(NEW.body,'$.data.plan.name') IS CASE NEW.role WHEN 'task' THEN p.task_name ELSE p.snapshot_name END
 AND ((NEW.purpose='initial' AND json_extract(NEW.body,'$.data.plan.expected_repo_id') IS NULL)
 OR (NEW.purpose!='initial' AND EXISTS(SELECT 1 FROM work_preparation_repository r JOIN work_credential_attempt c
  ON c.preparation_id=r.preparation_id AND c.role=r.role AND c.purpose='initial' AND c.state='closed' AND c.confirmation IN('refused','expired')
  WHERE r.preparation_id=p.operation_id AND r.role=NEW.role AND r.repo_id IS json_extract(NEW.body,'$.data.plan.expected_repo_id')))))
 OR NOT EXISTS(SELECT 1 FROM work_credential_key WHERE state='active')
 OR NOT EXISTS(SELECT 1 FROM work_preparation_policy WHERE id=1)
BEGIN SELECT RAISE(ABORT,'work_preparation_guard_failed'); END;
CREATE TRIGGER work_credential_attempt_capacity BEFORE INSERT ON work_credential_attempt
WHEN NOT EXISTS(SELECT 1 FROM work_credential_policy WHERE id=1) OR NOT EXISTS(SELECT 1 FROM work_resource_policy WHERE id=1)
 OR (SELECT count(*) FROM work_credential_attempt WHERE owner_id=NEW.owner_id)>=(SELECT retained_per_owner FROM work_credential_policy WHERE id=1)
 OR (SELECT count(*) FROM work_credential_attempt)>=(SELECT retained_total FROM work_credential_policy WHERE id=1)
 OR NEW.reserved_bytes+(SELECT coalesce(sum(reserved_bytes),0) FROM work_credential_attempt WHERE owner_id=NEW.owner_id AND state!='closed')>(SELECT bytes_per_owner FROM work_credential_policy WHERE id=1)
 OR NEW.reserved_bytes+(SELECT coalesce(sum(reserved_bytes),0) FROM work_credential_attempt WHERE state!='closed')>(SELECT bytes_total FROM work_credential_policy WHERE id=1)
 OR (SELECT count(*) FROM work_audit WHERE owner_id=NEW.owner_id)>=(SELECT new_audits_per_owner FROM work_resource_policy WHERE id=1)
 OR (SELECT count(*) FROM work_audit)>=(SELECT new_audits_total FROM work_resource_policy WHERE id=1)
BEGIN SELECT RAISE(ABORT,'work_resource_exhausted'); END;
CREATE TRIGGER work_credential_attempt_transition BEFORE UPDATE ON work_credential_attempt
WHEN NEW.attempt_id IS NOT OLD.attempt_id OR NEW.digest IS NOT OLD.digest OR NEW.body IS NOT OLD.body
 OR NEW.preparation_id IS NOT OLD.preparation_id OR NEW.owner_id IS NOT OLD.owner_id OR NEW.role IS NOT OLD.role OR NEW.purpose IS NOT OLD.purpose
 OR NEW.reserved_bytes IS NOT OLD.reserved_bytes OR NEW.revision!=OLD.revision+1
 OR NOT (NEW.dispatched IS OLD.dispatched OR (OLD.state='reserved' AND NEW.state='dispatched' AND OLD.dispatched=0 AND NEW.dispatched=1))
 OR (OLD.observation IS NOT NULL AND NEW.observation IS NOT OLD.observation)
 OR (OLD.key_version IS NOT NULL AND NEW.key_version IS NOT OLD.key_version)
 OR (OLD.nonce IS NOT NULL AND NEW.nonce IS NOT OLD.nonce)
 OR (OLD.envelope IS NOT NULL AND NEW.envelope IS NOT OLD.envelope AND NEW.state!='closed')
 OR NOT ((OLD.state='reserved' AND NEW.state IN('dispatched','revocation_pending'))
  OR (OLD.state='dispatched' AND NEW.state IN('captured','revocation_pending'))
  OR (OLD.state='captured' AND NEW.state='revocation_pending')
  OR (OLD.state='revocation_pending' AND NEW.state='revocation_pending' AND OLD.observation IS NULL AND NEW.observation IS NOT NULL)
  OR (OLD.state='revocation_pending' AND NEW.state='closed'))
 OR (NEW.observation IS NOT NULL AND NOT EXISTS(SELECT 1 FROM work_preparation_repository r WHERE r.preparation_id=NEW.preparation_id AND r.role=NEW.role
  AND r.repo_id IS json_extract(NEW.observation,'$.data.repo_id')))
 OR (NEW.state='captured' AND json_extract(NEW.observation,'$.data.scope') IS NOT CASE NEW.purpose WHEN 'readback' THEN 'read' ELSE 'write' END)
 OR (OLD.envelope IS NULL AND NEW.envelope IS NOT NULL AND NOT EXISTS(SELECT 1 FROM work_credential_key WHERE version=NEW.key_version AND state='active'))
 OR (NEW.state IN('dispatched','captured') AND NOT EXISTS(SELECT 1 FROM work_preparation p JOIN work_disclosure_source_current d ON d.digest=p.disclosure_digest
  WHERE p.operation_id=NEW.preparation_id AND p.state='dispatched' AND p.expires_at>unixepoch()
   AND EXISTS(SELECT 1 FROM work_preparation_policy WHERE id=1)
   AND EXISTS(SELECT 1 FROM work_resource_policy WHERE id=1)))
 OR (NEW.state='dispatched' AND (NOT EXISTS(SELECT 1 FROM work_credential_policy WHERE id=1) OR NOT EXISTS(SELECT 1 FROM work_credential_key WHERE state='active')
  OR (SELECT count(*) FROM work_audit WHERE owner_id=NEW.owner_id)>=(SELECT new_audits_per_owner FROM work_resource_policy WHERE id=1)
  OR (SELECT count(*) FROM work_audit)>=(SELECT new_audits_total FROM work_resource_policy WHERE id=1)))
BEGIN SELECT RAISE(ABORT,'work_preparation_guard_failed'); END;
CREATE TRIGGER work_credential_attempt_delete BEFORE DELETE ON work_credential_attempt BEGIN SELECT RAISE(ABORT,'retained credential attempt'); END;

-- Cleanup records remain possible without owner login/source/creation policy.
CREATE TRIGGER work_preparation_credential_cleanup AFTER UPDATE ON work_preparation
WHEN NEW.state='cleanup_pending' AND OLD.state!=NEW.state BEGIN
 INSERT INTO work_audit(audit_id,owner_id,entity_type,entity_id,action,actor,revision,from_state,to_state)
 SELECT 'credential-cleanup:'||attempt_id||':'||(revision+1),owner_id,'credential',attempt_id,'credential.revoke','op-work-custody',revision+1,state,'revocation_pending'
 FROM work_credential_attempt WHERE preparation_id=NEW.operation_id AND state IN('reserved','dispatched','captured');
 UPDATE work_credential_attempt SET state='revocation_pending',revision=revision+1
 WHERE preparation_id=NEW.operation_id AND state IN('reserved','dispatched','captured');
END;
CREATE TRIGGER work_preparation_credential_close_guard BEFORE UPDATE ON work_preparation
WHEN NEW.state='cleaned' AND EXISTS(SELECT 1 FROM work_credential_attempt WHERE preparation_id=NEW.operation_id AND state!='closed')
BEGIN SELECT RAISE(ABORT,'work_preparation_guard_failed'); END;
CREATE TRIGGER work_preparation_credential_verify_guard BEFORE UPDATE ON work_preparation
WHEN NEW.state='verified' AND EXISTS(SELECT 1 FROM work_credential_attempt WHERE preparation_id=NEW.operation_id)
 AND ((SELECT count(*) FROM work_credential_attempt WHERE preparation_id=NEW.operation_id AND state='closed' AND confirmation IN('refused','expired'))!=6
 OR NOT EXISTS(SELECT 1 FROM work_preparation_repository r WHERE r.preparation_id=NEW.operation_id AND r.role='task' AND r.repo_id IS json_extract(NEW.evidence,'$.data.task_repo_id'))
 OR NOT EXISTS(SELECT 1 FROM work_preparation_repository r WHERE r.preparation_id=NEW.operation_id AND r.role='snapshot' AND r.repo_id IS json_extract(NEW.evidence,'$.data.snapshot_repo_id')))
BEGIN SELECT RAISE(ABORT,'work_preparation_guard_failed'); END;
CREATE TRIGGER work_prepared_task_custody_guard BEFORE INSERT ON work_prepared_task
WHEN EXISTS(SELECT 1 FROM work_preparation_repository r JOIN work_preparation p ON p.operation_id=NEW.preparation_id
 WHERE r.preparation_id!=p.operation_id AND ((r.namespace=p.task_namespace AND r.repo_id=NEW.task_repo_id)
 OR (r.namespace=p.snapshot_namespace AND r.repo_id=NEW.snapshot_repo_id)))
BEGIN SELECT RAISE(ABORT,'work_preparation_guard_failed'); END;
