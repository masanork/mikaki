-- Opt-in only. Existing preparations receive no implicit/backfilled consent.
CREATE TABLE work_copy_consent (
 preparation_id TEXT PRIMARY KEY NOT NULL REFERENCES work_preparation(operation_id),
 review_digest TEXT NOT NULL CHECK(length(review_digest)=64 AND review_digest NOT GLOB '*[^0-9a-f]*'),
 preparation_digest TEXT NOT NULL REFERENCES work_preparation(digest),
 owner_id TEXT NOT NULL REFERENCES account_security(account_id),
 -- Historical consent must not prevent normal SSO/session garbage collection.
 session_hash TEXT NOT NULL CHECK(length(session_hash) BETWEEN 1 AND 128),
 artifacts_account TEXT NOT NULL CHECK(length(artifacts_account)=32 AND artifacts_account NOT GLOB '*[^0-9a-f]*'),
 expires_at INTEGER NOT NULL,
 approved_at INTEGER NOT NULL DEFAULT(unixepoch()),
 active INTEGER NOT NULL CHECK(active IN(0,1)),
 revision INTEGER NOT NULL CHECK((active=1 AND revision=1) OR (active=0 AND revision=2))
) STRICT;

CREATE VIEW work_copy_consent_current AS
SELECT c.* FROM work_copy_consent c
JOIN work_preparation p ON p.operation_id=c.preparation_id AND p.digest=c.preparation_digest
JOIN work_disclosure_source_current d ON d.digest=p.disclosure_digest
JOIN sso_context sx ON sx.secret_hash=c.session_hash
JOIN sso_session ss ON ss.sso_id=sx.sso_id AND ss.account_id=c.owner_id AND ss.epoch=p.owner_epoch
JOIN credential k ON k.credential_id=ss.credential_id AND k.account_id=ss.account_id AND k.active=1
JOIN account_security a ON a.account_id=c.owner_id AND a.active=1 AND a.epoch=p.owner_epoch
WHERE c.active=1 AND c.expires_at=p.expires_at AND c.expires_at>unixepoch()
 AND ss.revoked=0 AND ss.expires_at>=p.expires_at AND p.state IN('reserved','dispatched')
 AND EXISTS(SELECT 1 FROM work_preparation_policy WHERE id=1)
 AND EXISTS(SELECT 1 FROM work_resource_policy WHERE id=1);

CREATE TRIGGER work_copy_consent_binding BEFORE INSERT ON work_copy_consent
WHEN NEW.active!=1 OR NEW.revision!=1 OR NOT EXISTS(
 SELECT 1 FROM work_preparation p JOIN work_disclosure_source_current d ON d.digest=p.disclosure_digest
 JOIN sso_context sx ON sx.secret_hash=NEW.session_hash
 JOIN sso_session ss ON ss.sso_id=sx.sso_id AND ss.account_id=p.owner_id AND ss.epoch=p.owner_epoch
 JOIN credential k ON k.credential_id=ss.credential_id AND k.account_id=ss.account_id AND k.active=1
 JOIN account_security a ON a.account_id=p.owner_id AND a.active=1 AND a.epoch=p.owner_epoch
 WHERE p.operation_id=NEW.preparation_id AND p.digest=NEW.preparation_digest AND p.owner_id=NEW.owner_id
 AND p.state='reserved' AND p.revision=1 AND NEW.expires_at=p.expires_at AND p.expires_at>unixepoch()
 AND ss.revoked=0 AND ss.expires_at>=p.expires_at)
 OR NOT EXISTS(SELECT 1 FROM work_preparation_policy WHERE id=1)
 OR NOT EXISTS(SELECT 1 FROM work_resource_policy WHERE id=1)
BEGIN SELECT RAISE(ABORT,'work_preparation_guard_failed'); END;

CREATE TRIGGER work_copy_consent_frame BEFORE INSERT ON work_copy_consent
WHEN NOT EXISTS(SELECT 1 FROM work_authority_frame f JOIN work_authority_checkpoint c
 ON c.id=f.id AND c.sequence=f.sequence AND c.tip=f.tip)
BEGIN SELECT RAISE(ABORT,'work_checkpoint_guard_failed'); END;
CREATE TRIGGER work_copy_consent_update BEFORE UPDATE ON work_copy_consent
WHEN NEW.preparation_id IS NOT OLD.preparation_id OR NEW.review_digest IS NOT OLD.review_digest
 OR NEW.preparation_digest IS NOT OLD.preparation_digest OR NEW.owner_id IS NOT OLD.owner_id
 OR NEW.session_hash IS NOT OLD.session_hash OR NEW.artifacts_account IS NOT OLD.artifacts_account
 OR NEW.expires_at IS NOT OLD.expires_at OR NEW.approved_at IS NOT OLD.approved_at
 OR OLD.active!=1 OR NEW.active!=0 OR NEW.revision!=OLD.revision+1
 OR NOT EXISTS(SELECT 1 FROM work_authority_frame f JOIN work_authority_checkpoint c
 ON c.id=f.id AND c.sequence=f.sequence AND c.tip=f.tip)
BEGIN SELECT RAISE(ABORT,'work_preparation_guard_failed'); END;
CREATE TRIGGER work_copy_consent_retained BEFORE DELETE ON work_copy_consent
BEGIN SELECT RAISE(ABORT,'retained copy consent'); END;

-- Repeat consent at commit, including when a private adapter raced revocation.
CREATE TRIGGER work_preparation_copy_consent BEFORE UPDATE ON work_preparation
WHEN NEW.state='dispatched' AND NOT EXISTS(
 SELECT 1 FROM work_copy_consent_current WHERE preparation_id=OLD.operation_id)
BEGIN SELECT RAISE(ABORT,'work_preparation_guard_failed'); END;
CREATE TRIGGER work_credential_copy_consent BEFORE UPDATE ON work_credential_attempt
WHEN NEW.state='dispatched' AND OLD.state='reserved' AND NOT EXISTS(
 SELECT 1 FROM work_copy_consent_current WHERE preparation_id=OLD.preparation_id)
BEGIN SELECT RAISE(ABORT,'work_preparation_guard_failed'); END;
