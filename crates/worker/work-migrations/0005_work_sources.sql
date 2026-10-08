-- Operator-registered pinned Git receipts; no browser registration or plaintext.
CREATE TABLE work_source_version (
 source_id TEXT NOT NULL, source_revision INTEGER NOT NULL CHECK(source_revision BETWEEN 1 AND 9007199254740991),
 body TEXT NOT NULL CHECK(length(body) BETWEEN 1 AND 32768 AND json_valid(body)
  AND json_extract(body,'$.version') IS 1 AND json_extract(body,'$.kind') IS 'source'
  AND json_extract(body,'$.data.data.source_id') IS source_id AND json_extract(body,'$.data.data.source_revision') IS source_revision),
 PRIMARY KEY(source_id,source_revision)
) STRICT;
CREATE TABLE work_source_head (
 source_id TEXT PRIMARY KEY NOT NULL, source_revision INTEGER NOT NULL,
 active INTEGER NOT NULL CHECK(active IN(0,1)),
 FOREIGN KEY(source_id,source_revision) REFERENCES work_source_version(source_id,source_revision)
) STRICT;
CREATE TABLE work_source_access (
 owner_id TEXT NOT NULL REFERENCES account_security(account_id), source_id TEXT NOT NULL REFERENCES work_source_head(source_id),
 owner_epoch INTEGER NOT NULL CHECK(owner_epoch BETWEEN 0 AND 9007199254740991),
 access_revision INTEGER NOT NULL CHECK(access_revision BETWEEN 1 AND 9007199254740991),
 active INTEGER NOT NULL CHECK(active IN(0,1)), PRIMARY KEY(owner_id,source_id)
) STRICT;
CREATE INDEX work_source_access_active ON work_source_access(owner_id,active,source_id);
CREATE TABLE work_source_audit (
 sequence INTEGER PRIMARY KEY, event TEXT NOT NULL, source_id TEXT NOT NULL, owner_id TEXT,
 revision INTEGER NOT NULL, active INTEGER, occurred_at INTEGER NOT NULL DEFAULT(unixepoch())
) STRICT;
CREATE TRIGGER work_source_version_immutable BEFORE UPDATE ON work_source_version BEGIN SELECT RAISE(ABORT,'immutable source'); END;
CREATE TRIGGER work_source_version_retained BEFORE DELETE ON work_source_version BEGIN SELECT RAISE(ABORT,'retained source'); END;
CREATE TRIGGER work_source_version_capacity BEFORE INSERT ON work_source_version
WHEN (SELECT count(*) FROM work_source_version)>=1024
BEGIN SELECT RAISE(ABORT,'work_resource_exhausted'); END;
CREATE TRIGGER work_source_head_capacity BEFORE INSERT ON work_source_head
WHEN (SELECT count(*) FROM work_source_head)>=128
BEGIN SELECT RAISE(ABORT,'work_resource_exhausted'); END;
CREATE TRIGGER work_source_head_update BEFORE UPDATE ON work_source_head
WHEN NEW.source_id IS NOT OLD.source_id OR NEW.source_revision NOT IN(OLD.source_revision,OLD.source_revision+1)
 OR (NEW.source_revision=OLD.source_revision AND NEW.active=OLD.active)
 OR (NEW.source_revision=OLD.source_revision AND OLD.active=0 AND NEW.active=1)
 OR json_extract((SELECT body FROM work_source_version WHERE source_id=NEW.source_id AND source_revision=NEW.source_revision),'$.data.data.role')
    IS NOT json_extract((SELECT body FROM work_source_version WHERE source_id=OLD.source_id AND source_revision=OLD.source_revision),'$.data.data.role')
BEGIN SELECT RAISE(ABORT,'invalid source transition'); END;
CREATE TRIGGER work_source_head_retained BEFORE DELETE ON work_source_head BEGIN SELECT RAISE(ABORT,'retained source'); END;
CREATE TRIGGER work_source_access_capacity BEFORE INSERT ON work_source_access
WHEN (SELECT count(*) FROM work_source_access)>=4096 OR (SELECT count(*) FROM work_source_access WHERE owner_id=NEW.owner_id)>=32
BEGIN SELECT RAISE(ABORT,'work_resource_exhausted'); END;
CREATE TRIGGER work_source_access_insert BEFORE INSERT ON work_source_access
WHEN NEW.access_revision!=1 OR NOT EXISTS(SELECT 1 FROM account_security WHERE account_id=NEW.owner_id AND epoch=NEW.owner_epoch AND active=1)
BEGIN SELECT RAISE(ABORT,'invalid source access'); END;
CREATE TRIGGER work_source_access_update BEFORE UPDATE ON work_source_access
WHEN NEW.owner_id IS NOT OLD.owner_id OR NEW.source_id IS NOT OLD.source_id OR NEW.access_revision!=OLD.access_revision+1
 OR NEW.owner_epoch<OLD.owner_epoch
 OR (NEW.active=1 AND NOT EXISTS(SELECT 1 FROM account_security WHERE account_id=NEW.owner_id AND epoch=NEW.owner_epoch AND active=1))
 OR (NEW.owner_epoch!=OLD.owner_epoch AND NOT EXISTS(SELECT 1 FROM account_security WHERE account_id=NEW.owner_id AND epoch=NEW.owner_epoch))
BEGIN SELECT RAISE(ABORT,'invalid source access transition'); END;
CREATE TRIGGER work_source_access_retained BEFORE DELETE ON work_source_access BEGIN SELECT RAISE(ABORT,'retained source access'); END;
CREATE TRIGGER work_source_version_audit AFTER INSERT ON work_source_version BEGIN
 INSERT INTO work_source_audit(event,source_id,revision) VALUES('source.register',NEW.source_id,NEW.source_revision); END;
CREATE TRIGGER work_source_head_insert_audit AFTER INSERT ON work_source_head BEGIN
 INSERT INTO work_source_audit(event,source_id,revision,active) VALUES('source.head',NEW.source_id,NEW.source_revision,NEW.active); END;
CREATE TRIGGER work_source_head_update_audit AFTER UPDATE ON work_source_head BEGIN
 INSERT INTO work_source_audit(event,source_id,revision,active) VALUES('source.head',NEW.source_id,NEW.source_revision,NEW.active); END;
CREATE TRIGGER work_source_access_insert_audit AFTER INSERT ON work_source_access BEGIN
 INSERT INTO work_source_audit(event,source_id,owner_id,revision,active) VALUES('source.access',NEW.source_id,NEW.owner_id,NEW.access_revision,NEW.active); END;
CREATE TRIGGER work_source_access_update_audit AFTER UPDATE ON work_source_access BEGIN
 INSERT INTO work_source_audit(event,source_id,owner_id,revision,active) VALUES('source.access',NEW.source_id,NEW.owner_id,NEW.access_revision,NEW.active); END;
CREATE TRIGGER work_source_audit_immutable BEFORE UPDATE ON work_source_audit BEGIN SELECT RAISE(ABORT,'immutable source audit'); END;
CREATE TRIGGER work_source_audit_retained BEFORE DELETE ON work_source_audit BEGIN SELECT RAISE(ABORT,'retained source audit'); END;
