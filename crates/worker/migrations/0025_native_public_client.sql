-- Add an explicit native public-client registration without changing the
-- existing confidential registrations or their key material.
PRAGMA defer_foreign_keys = ON;
DROP VIEW valid_client_session;
DROP VIEW eligible_client_session;
DROP TRIGGER vault_claim_release_active_insert;
DROP TRIGGER vault_claim_release_active_update;

CREATE TABLE client_next (
  client_id TEXT PRIMARY KEY NOT NULL CHECK(length(client_id) BETWEEN 1 AND 128),
  revision INTEGER NOT NULL CHECK(revision >= 0),
  active INTEGER NOT NULL CHECK(active IN (0, 1)),
  client_type TEXT NOT NULL DEFAULT 'web' CHECK(client_type IN ('web', 'native')),
  auth_method TEXT NOT NULL DEFAULT 'private_key_jwt'
    CHECK(auth_method IN ('private_key_jwt', 'client_secret_basic', 'client_secret_post', 'none')),
  allow_missing_pkce INTEGER NOT NULL DEFAULT 0 CHECK(allow_missing_pkce IN (0, 1)),
  sector_identifier TEXT NOT NULL CHECK(length(sector_identifier) BETWEEN 1 AND 2048),
  CHECK(
    (client_type='native' AND auth_method='none' AND allow_missing_pkce=0) OR
    (client_type='web' AND auth_method!='none' AND
      (allow_missing_pkce=0 OR auth_method IN ('client_secret_basic','client_secret_post')))
  )
) STRICT;
INSERT INTO client_next
  SELECT client_id,revision,active,'web',auth_method,allow_missing_pkce,sector_identifier
  FROM client;
DROP TABLE client;
ALTER TABLE client_next RENAME TO client;
CREATE TRIGGER client_registration_revision BEFORE UPDATE ON client
WHEN NEW.revision <= OLD.revision
BEGIN SELECT RAISE(ABORT, 'client revision must increase'); END;
CREATE TRIGGER vault_claim_release_client_change_revoke AFTER UPDATE ON client
BEGIN
  UPDATE vault_claim_release SET status='revoked',version=version+1,
    updated_at=CAST(strftime('%s','now') AS INTEGER)
  WHERE client_id=NEW.client_id AND status='active';
END;

CREATE TRIGGER vault_claim_release_active_insert BEFORE INSERT ON vault_claim_release
WHEN NEW.status = 'active' AND NOT EXISTS (
  SELECT 1 FROM vault_claim_release_policy rp
  JOIN vault_share_policy sp ON sp.id=rp.id
  JOIN account_security a ON a.account_id=NEW.account_id
  JOIN client c ON c.client_id=NEW.client_id
  JOIN app_connection ac ON ac.account_id=NEW.account_id AND ac.client_id=NEW.client_id
  JOIN vault_attribute_grant g ON g.account_id=NEW.account_id
    AND g.attribute_id='name' AND g.recipient_service='userinfo'
    AND g.purpose='oidc.userinfo.name'
  JOIN vault_attribute_recipient_envelope e ON e.envelope_id=g.envelope_id
  JOIN vault_recipient_key k ON k.key_id=e.recipient_key_id
  JOIN vault_attribute_head h ON h.account_id=NEW.account_id AND h.attribute_id='name'
  WHERE rp.id=1 AND rp.enabled=1 AND sp.enabled=1 AND a.active=1
    AND c.active=1 AND c.auth_method='private_key_jwt' AND c.client_type='web'
    AND c.revision=NEW.client_revision
    AND ac.active=1 AND ac.grant_version=NEW.connection_grant_version
    AND g.status='active' AND g.version=NEW.system_grant_version
    AND g.attribute_revision=NEW.attribute_revision
    AND g.expires_at>=NEW.expires_at
    AND g.expires_at>CAST(strftime('%s','now') AS INTEGER)
    AND e.account_id=NEW.account_id AND e.attribute_revision=NEW.attribute_revision
    AND h.revision=NEW.attribute_revision AND h.deleted=0
    AND h.ciphertext_sha256=e.ciphertext_sha256
    AND k.state='active'
    AND NEW.expires_at>CAST(strftime('%s','now') AS INTEGER)
    AND NEW.expires_at<=CAST(strftime('%s','now') AS INTEGER)+rp.ttl_seconds
)
BEGIN SELECT RAISE(ABORT, 'claim release preconditions failed'); END;

CREATE TRIGGER vault_claim_release_active_update BEFORE UPDATE ON vault_claim_release
WHEN NEW.status = 'active' AND NOT EXISTS (
  SELECT 1 FROM vault_claim_release_policy rp
  JOIN vault_share_policy sp ON sp.id=rp.id
  JOIN account_security a ON a.account_id=NEW.account_id
  JOIN client c ON c.client_id=NEW.client_id
  JOIN app_connection ac ON ac.account_id=NEW.account_id AND ac.client_id=NEW.client_id
  JOIN vault_attribute_grant g ON g.account_id=NEW.account_id
    AND g.attribute_id='name' AND g.recipient_service='userinfo'
    AND g.purpose='oidc.userinfo.name'
  JOIN vault_attribute_recipient_envelope e ON e.envelope_id=g.envelope_id
  JOIN vault_recipient_key k ON k.key_id=e.recipient_key_id
  JOIN vault_attribute_head h ON h.account_id=NEW.account_id AND h.attribute_id='name'
  WHERE rp.id=1 AND rp.enabled=1 AND sp.enabled=1 AND a.active=1
    AND c.active=1 AND c.auth_method='private_key_jwt' AND c.client_type='web'
    AND c.revision=NEW.client_revision
    AND ac.active=1 AND ac.grant_version=NEW.connection_grant_version
    AND g.status='active' AND g.version=NEW.system_grant_version
    AND g.attribute_revision=NEW.attribute_revision
    AND g.expires_at>=NEW.expires_at
    AND g.expires_at>CAST(strftime('%s','now') AS INTEGER)
    AND e.account_id=NEW.account_id AND e.attribute_revision=NEW.attribute_revision
    AND h.revision=NEW.attribute_revision AND h.deleted=0
    AND h.ciphertext_sha256=e.ciphertext_sha256
    AND k.state='active'
    AND NEW.expires_at>CAST(strftime('%s','now') AS INTEGER)
    AND NEW.expires_at<=CAST(strftime('%s','now') AS INTEGER)+rp.ttl_seconds
)
BEGIN SELECT RAISE(ABORT, 'claim release preconditions failed'); END;

-- A 'none' row records a public token request bound to a registered client
-- and a PKCE-protected code. It is a reservation, not client authentication.
CREATE TABLE client_auth_use_next (
  accepted_by TEXT PRIMARY KEY NOT NULL CHECK(length(accepted_by) BETWEEN 1 AND 128),
  client_id TEXT NOT NULL REFERENCES client(client_id),
  method TEXT NOT NULL
    CHECK(method IN ('private_key_jwt', 'client_secret_basic', 'client_secret_post', 'none')),
  endpoint TEXT NOT NULL CHECK(length(endpoint) BETWEEN 1 AND 2048),
  credential_id TEXT NOT NULL CHECK(length(credential_id) <= 128),
  client_revision INTEGER NOT NULL CHECK(client_revision >= 0),
  credential_revision INTEGER NOT NULL CHECK(credential_revision >= 0),
  retain_until INTEGER NOT NULL CHECK(retain_until > 0),
  CHECK(method!='none' OR (credential_id='' AND credential_revision=0))
) STRICT;
INSERT INTO client_auth_use_next
  SELECT accepted_by,client_id,method,endpoint,credential_id,client_revision,
    credential_revision,retain_until FROM client_auth_use;
DROP TABLE client_auth_use;
ALTER TABLE client_auth_use_next RENAME TO client_auth_use;
CREATE INDEX client_auth_gc ON client_auth_use(retain_until);

CREATE VIEW eligible_client_session AS
SELECT cs.client_id, cs.sid, cs.sub, ss.expires_at, ss.account_id
FROM client_session cs
JOIN sso_session ss ON ss.sso_id = cs.sso_id AND ss.account_id = cs.account_id
JOIN account_security a ON a.account_id = ss.account_id
JOIN credential cr ON cr.credential_id = ss.credential_id AND cr.account_id = a.account_id
JOIN client c ON c.client_id = cs.client_id
JOIN app_connection g ON g.account_id = cs.account_id AND g.client_id = cs.client_id
WHERE a.active = 1 AND a.epoch = ss.epoch AND cr.active = 1
  AND c.active = 1 AND g.active = 1 AND g.grant_version = cs.grant_version
  AND ss.revoked = 0 AND cs.revoked = 0
  AND ss.expires_at > CAST(strftime('%s', 'now') AS INTEGER);

CREATE VIEW valid_client_session AS
SELECT v.* FROM eligible_client_session v
WHERE EXISTS (
  SELECT 1 FROM authorization_code ac JOIN token_issue ti ON ti.code_hash = ac.code_hash
  WHERE ac.client_id = v.client_id AND ac.sid = v.sid
    AND ac.consumed_by = ti.operation_id AND ac.consumed_at IS NOT NULL AND ti.revoked = 0
);

PRAGMA defer_foreign_keys = OFF;
