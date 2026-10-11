-- Opt-in additive WORK schema after the fresh Owner Vault baseline.
-- Empty before enrollment; no backfill or automatic enrollment.
-- The deferred FK forces the frame to close in the SAME D1 transaction.
CREATE TABLE work_authority_frame_closure (id INTEGER PRIMARY KEY CHECK(id=1)) STRICT;
CREATE TRIGGER work_authority_frame_no_closure BEFORE INSERT ON work_authority_frame_closure
BEGIN SELECT RAISE(ABORT,'work_checkpoint_guard_failed'); END;
CREATE TABLE work_authority_frame (
 id INTEGER PRIMARY KEY CHECK(id=1),
 sequence INTEGER NOT NULL CHECK(sequence BETWEEN 1 AND 9007199254740991),
 tip TEXT NOT NULL CHECK(length(tip)=64 AND tip NOT GLOB '*[^a-f0-9]*'),
 closure INTEGER NOT NULL CHECK(closure=1)
   REFERENCES work_authority_frame_closure(id) DEFERRABLE INITIALLY DEFERRED
) STRICT;
CREATE TRIGGER work_authority_frame_current BEFORE INSERT ON work_authority_frame
WHEN NOT EXISTS(SELECT 1 FROM work_authority_checkpoint c
 WHERE c.id=1 AND c.sequence=NEW.sequence AND c.tip=NEW.tip)
BEGIN SELECT RAISE(ABORT,'work_checkpoint_guard_failed'); END;
CREATE TRIGGER work_authority_frame_immutable BEFORE UPDATE ON work_authority_frame
BEGIN SELECT RAISE(ABORT,'work_checkpoint_guard_failed'); END;

CREATE TRIGGER authority_frame_account_security_insert BEFORE INSERT ON account_security
WHEN EXISTS(SELECT 1 FROM work_authority_checkpoint WHERE id=1)
 AND NOT EXISTS(SELECT 1 FROM work_authority_frame f JOIN work_authority_checkpoint c
 ON c.id=f.id AND c.sequence=f.sequence AND c.tip=f.tip)
BEGIN SELECT RAISE(ABORT,'work_checkpoint_guard_failed'); END;

CREATE TRIGGER authority_frame_account_security_update BEFORE UPDATE ON account_security
WHEN EXISTS(SELECT 1 FROM work_authority_checkpoint WHERE id=1)
 AND NOT EXISTS(SELECT 1 FROM work_authority_frame f JOIN work_authority_checkpoint c
 ON c.id=f.id AND c.sequence=f.sequence AND c.tip=f.tip)
BEGIN SELECT RAISE(ABORT,'work_checkpoint_guard_failed'); END;

CREATE TRIGGER authority_frame_account_security_delete BEFORE DELETE ON account_security
WHEN EXISTS(SELECT 1 FROM work_authority_checkpoint WHERE id=1)
 AND NOT EXISTS(SELECT 1 FROM work_authority_frame f JOIN work_authority_checkpoint c
 ON c.id=f.id AND c.sequence=f.sequence AND c.tip=f.tip)
BEGIN SELECT RAISE(ABORT,'work_checkpoint_guard_failed'); END;

CREATE TRIGGER authority_frame_credential_insert BEFORE INSERT ON credential
WHEN EXISTS(SELECT 1 FROM work_authority_checkpoint WHERE id=1)
 AND NOT EXISTS(SELECT 1 FROM work_authority_frame f JOIN work_authority_checkpoint c
 ON c.id=f.id AND c.sequence=f.sequence AND c.tip=f.tip)
BEGIN SELECT RAISE(ABORT,'work_checkpoint_guard_failed'); END;

CREATE TRIGGER authority_frame_credential_update BEFORE UPDATE ON credential
WHEN EXISTS(SELECT 1 FROM work_authority_checkpoint WHERE id=1)
 AND NOT EXISTS(SELECT 1 FROM work_authority_frame f JOIN work_authority_checkpoint c
 ON c.id=f.id AND c.sequence=f.sequence AND c.tip=f.tip)
BEGIN SELECT RAISE(ABORT,'work_checkpoint_guard_failed'); END;

CREATE TRIGGER authority_frame_credential_delete BEFORE DELETE ON credential
WHEN EXISTS(SELECT 1 FROM work_authority_checkpoint WHERE id=1)
 AND NOT EXISTS(SELECT 1 FROM work_authority_frame f JOIN work_authority_checkpoint c
 ON c.id=f.id AND c.sequence=f.sequence AND c.tip=f.tip)
BEGIN SELECT RAISE(ABORT,'work_checkpoint_guard_failed'); END;

CREATE TRIGGER authority_frame_passkey_credential_insert BEFORE INSERT ON passkey_credential
WHEN EXISTS(SELECT 1 FROM work_authority_checkpoint WHERE id=1)
 AND NOT EXISTS(SELECT 1 FROM work_authority_frame f JOIN work_authority_checkpoint c
 ON c.id=f.id AND c.sequence=f.sequence AND c.tip=f.tip)
BEGIN SELECT RAISE(ABORT,'work_checkpoint_guard_failed'); END;

CREATE TRIGGER authority_frame_passkey_credential_update BEFORE UPDATE ON passkey_credential
WHEN EXISTS(SELECT 1 FROM work_authority_checkpoint WHERE id=1)
 AND NOT EXISTS(SELECT 1 FROM work_authority_frame f JOIN work_authority_checkpoint c
 ON c.id=f.id AND c.sequence=f.sequence AND c.tip=f.tip)
BEGIN SELECT RAISE(ABORT,'work_checkpoint_guard_failed'); END;

CREATE TRIGGER authority_frame_passkey_credential_delete BEFORE DELETE ON passkey_credential
WHEN EXISTS(SELECT 1 FROM work_authority_checkpoint WHERE id=1)
 AND NOT EXISTS(SELECT 1 FROM work_authority_frame f JOIN work_authority_checkpoint c
 ON c.id=f.id AND c.sequence=f.sequence AND c.tip=f.tip)
BEGIN SELECT RAISE(ABORT,'work_checkpoint_guard_failed'); END;

CREATE TRIGGER authority_frame_sso_session_insert BEFORE INSERT ON sso_session
WHEN EXISTS(SELECT 1 FROM work_authority_checkpoint WHERE id=1)
 AND NOT EXISTS(SELECT 1 FROM work_authority_frame f JOIN work_authority_checkpoint c
 ON c.id=f.id AND c.sequence=f.sequence AND c.tip=f.tip)
BEGIN SELECT RAISE(ABORT,'work_checkpoint_guard_failed'); END;

CREATE TRIGGER authority_frame_sso_session_update BEFORE UPDATE ON sso_session
WHEN EXISTS(SELECT 1 FROM work_authority_checkpoint WHERE id=1)
 AND NOT EXISTS(SELECT 1 FROM work_authority_frame f JOIN work_authority_checkpoint c
 ON c.id=f.id AND c.sequence=f.sequence AND c.tip=f.tip)
BEGIN SELECT RAISE(ABORT,'work_checkpoint_guard_failed'); END;

CREATE TRIGGER authority_frame_sso_session_delete BEFORE DELETE ON sso_session
WHEN EXISTS(SELECT 1 FROM work_authority_checkpoint WHERE id=1)
 AND NOT EXISTS(SELECT 1 FROM work_authority_frame f JOIN work_authority_checkpoint c
 ON c.id=f.id AND c.sequence=f.sequence AND c.tip=f.tip)
BEGIN SELECT RAISE(ABORT,'work_checkpoint_guard_failed'); END;

CREATE TRIGGER authority_frame_sso_context_insert BEFORE INSERT ON sso_context
WHEN EXISTS(SELECT 1 FROM work_authority_checkpoint WHERE id=1)
 AND NOT EXISTS(SELECT 1 FROM work_authority_frame f JOIN work_authority_checkpoint c
 ON c.id=f.id AND c.sequence=f.sequence AND c.tip=f.tip)
BEGIN SELECT RAISE(ABORT,'work_checkpoint_guard_failed'); END;

CREATE TRIGGER authority_frame_sso_context_update BEFORE UPDATE ON sso_context
WHEN EXISTS(SELECT 1 FROM work_authority_checkpoint WHERE id=1)
 AND NOT EXISTS(SELECT 1 FROM work_authority_frame f JOIN work_authority_checkpoint c
 ON c.id=f.id AND c.sequence=f.sequence AND c.tip=f.tip)
BEGIN SELECT RAISE(ABORT,'work_checkpoint_guard_failed'); END;

CREATE TRIGGER authority_frame_sso_context_delete BEFORE DELETE ON sso_context
WHEN EXISTS(SELECT 1 FROM work_authority_checkpoint WHERE id=1)
 AND NOT EXISTS(SELECT 1 FROM work_authority_frame f JOIN work_authority_checkpoint c
 ON c.id=f.id AND c.sequence=f.sequence AND c.tip=f.tip)
BEGIN SELECT RAISE(ABORT,'work_checkpoint_guard_failed'); END;

CREATE TRIGGER authority_frame_account_role_insert BEFORE INSERT ON account_role
WHEN EXISTS(SELECT 1 FROM work_authority_checkpoint WHERE id=1)
 AND NOT EXISTS(SELECT 1 FROM work_authority_frame f JOIN work_authority_checkpoint c
 ON c.id=f.id AND c.sequence=f.sequence AND c.tip=f.tip)
BEGIN SELECT RAISE(ABORT,'work_checkpoint_guard_failed'); END;

CREATE TRIGGER authority_frame_account_role_update BEFORE UPDATE ON account_role
WHEN EXISTS(SELECT 1 FROM work_authority_checkpoint WHERE id=1)
 AND NOT EXISTS(SELECT 1 FROM work_authority_frame f JOIN work_authority_checkpoint c
 ON c.id=f.id AND c.sequence=f.sequence AND c.tip=f.tip)
BEGIN SELECT RAISE(ABORT,'work_checkpoint_guard_failed'); END;

CREATE TRIGGER authority_frame_account_role_delete BEFORE DELETE ON account_role
WHEN EXISTS(SELECT 1 FROM work_authority_checkpoint WHERE id=1)
 AND NOT EXISTS(SELECT 1 FROM work_authority_frame f JOIN work_authority_checkpoint c
 ON c.id=f.id AND c.sequence=f.sequence AND c.tip=f.tip)
BEGIN SELECT RAISE(ABORT,'work_checkpoint_guard_failed'); END;

CREATE TRIGGER authority_frame_runtime_policy_active_insert BEFORE INSERT ON runtime_policy_active
WHEN EXISTS(SELECT 1 FROM work_authority_checkpoint WHERE id=1)
 AND NOT EXISTS(SELECT 1 FROM work_authority_frame f JOIN work_authority_checkpoint c
 ON c.id=f.id AND c.sequence=f.sequence AND c.tip=f.tip)
BEGIN SELECT RAISE(ABORT,'work_checkpoint_guard_failed'); END;

CREATE TRIGGER authority_frame_runtime_policy_active_update BEFORE UPDATE ON runtime_policy_active
WHEN EXISTS(SELECT 1 FROM work_authority_checkpoint WHERE id=1)
 AND NOT EXISTS(SELECT 1 FROM work_authority_frame f JOIN work_authority_checkpoint c
 ON c.id=f.id AND c.sequence=f.sequence AND c.tip=f.tip)
BEGIN SELECT RAISE(ABORT,'work_checkpoint_guard_failed'); END;

CREATE TRIGGER authority_frame_runtime_policy_active_delete BEFORE DELETE ON runtime_policy_active
WHEN EXISTS(SELECT 1 FROM work_authority_checkpoint WHERE id=1)
 AND NOT EXISTS(SELECT 1 FROM work_authority_frame f JOIN work_authority_checkpoint c
 ON c.id=f.id AND c.sequence=f.sequence AND c.tip=f.tip)
BEGIN SELECT RAISE(ABORT,'work_checkpoint_guard_failed'); END;

CREATE TRIGGER authority_frame_runtime_policy_version_insert BEFORE INSERT ON runtime_policy_version
WHEN EXISTS(SELECT 1 FROM work_authority_checkpoint WHERE id=1)
 AND NOT EXISTS(SELECT 1 FROM work_authority_frame f JOIN work_authority_checkpoint c
 ON c.id=f.id AND c.sequence=f.sequence AND c.tip=f.tip)
BEGIN SELECT RAISE(ABORT,'work_checkpoint_guard_failed'); END;

CREATE TRIGGER authority_frame_runtime_policy_version_update BEFORE UPDATE ON runtime_policy_version
WHEN EXISTS(SELECT 1 FROM work_authority_checkpoint WHERE id=1)
 AND NOT EXISTS(SELECT 1 FROM work_authority_frame f JOIN work_authority_checkpoint c
 ON c.id=f.id AND c.sequence=f.sequence AND c.tip=f.tip)
BEGIN SELECT RAISE(ABORT,'work_checkpoint_guard_failed'); END;

CREATE TRIGGER authority_frame_runtime_policy_version_delete BEFORE DELETE ON runtime_policy_version
WHEN EXISTS(SELECT 1 FROM work_authority_checkpoint WHERE id=1)
 AND NOT EXISTS(SELECT 1 FROM work_authority_frame f JOIN work_authority_checkpoint c
 ON c.id=f.id AND c.sequence=f.sequence AND c.tip=f.tip)
BEGIN SELECT RAISE(ABORT,'work_checkpoint_guard_failed'); END;

CREATE TRIGGER authority_frame_runtime_policy_audit_insert BEFORE INSERT ON runtime_policy_audit
WHEN EXISTS(SELECT 1 FROM work_authority_checkpoint WHERE id=1)
 AND NOT EXISTS(SELECT 1 FROM work_authority_frame f JOIN work_authority_checkpoint c
 ON c.id=f.id AND c.sequence=f.sequence AND c.tip=f.tip)
BEGIN SELECT RAISE(ABORT,'work_checkpoint_guard_failed'); END;

CREATE TRIGGER authority_frame_runtime_policy_audit_update BEFORE UPDATE ON runtime_policy_audit
WHEN EXISTS(SELECT 1 FROM work_authority_checkpoint WHERE id=1)
 AND NOT EXISTS(SELECT 1 FROM work_authority_frame f JOIN work_authority_checkpoint c
 ON c.id=f.id AND c.sequence=f.sequence AND c.tip=f.tip)
BEGIN SELECT RAISE(ABORT,'work_checkpoint_guard_failed'); END;

CREATE TRIGGER authority_frame_runtime_policy_audit_delete BEFORE DELETE ON runtime_policy_audit
WHEN EXISTS(SELECT 1 FROM work_authority_checkpoint WHERE id=1)
 AND NOT EXISTS(SELECT 1 FROM work_authority_frame f JOIN work_authority_checkpoint c
 ON c.id=f.id AND c.sequence=f.sequence AND c.tip=f.tip)
BEGIN SELECT RAISE(ABORT,'work_checkpoint_guard_failed'); END;

CREATE TABLE op_authority_audit (
 operation_id TEXT PRIMARY KEY NOT NULL CHECK(length(operation_id)=43),
 action TEXT NOT NULL CHECK(action IN ('revoke-account','revoke-session','disable-credential','activate-policy')),
 target TEXT NOT NULL CHECK(length(target) BETWEEN 1 AND 512),
 actor TEXT NOT NULL CHECK(length(actor) BETWEEN 1 AND 128),
 reason TEXT NOT NULL CHECK(length(reason) BETWEEN 1 AND 512),
 occurred_at INTEGER NOT NULL CHECK(occurred_at>0)
) STRICT;
CREATE TRIGGER op_authority_audit_frame BEFORE INSERT ON op_authority_audit
WHEN NOT EXISTS(SELECT 1 FROM work_authority_frame f JOIN work_authority_checkpoint c
 ON c.id=f.id AND c.sequence=f.sequence AND c.tip=f.tip)
BEGIN SELECT RAISE(ABORT,'work_checkpoint_guard_failed'); END;
CREATE TRIGGER op_authority_audit_immutable BEFORE UPDATE ON op_authority_audit
BEGIN SELECT RAISE(ABORT,'retained authority audit'); END;
CREATE TRIGGER op_authority_audit_retained BEFORE DELETE ON op_authority_audit
BEGIN SELECT RAISE(ABORT,'retained authority audit'); END;
