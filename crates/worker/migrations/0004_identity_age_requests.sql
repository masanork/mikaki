-- Experimental authenticated PAR age requests. Existing releases remain separate.
CREATE TABLE identity_age_request (
  code_hash TEXT PRIMARY KEY NOT NULL REFERENCES authorization_code(code_hash),
  request_json TEXT NOT NULL CHECK(length(request_json) BETWEEN 1 AND 4096 AND json_valid(request_json)),
  request_hash TEXT NOT NULL CHECK(length(request_hash)=43),
  document_id TEXT NOT NULL REFERENCES identity_document(document_id),
  release_version INTEGER NOT NULL CHECK(release_version>0),
  fields_json TEXT NOT NULL CHECK(json_valid(fields_json) AND json_type(fields_json)='array' AND json_array_length(fields_json) BETWEEN 1 AND 2)
) STRICT;
CREATE TRIGGER identity_age_request_immutable BEFORE UPDATE ON identity_age_request
BEGIN SELECT RAISE(ABORT,'age request must be authorized with a new code'); END;

-- One eligibility relation for both response preflight and conditional audit commit.
CREATE VIEW identity_age_eligible AS
SELECT q.*,ti.access_hash,ac.client_id,v.sub,d.document_json,d.policy_hash,
       min(ti.access_expires_at,v.expires_at,r.expires_at,d.valid_until) AS deadline
FROM identity_age_request q
JOIN token_issue ti ON ti.code_hash=q.code_hash
JOIN authorization_code ac ON ac.code_hash=ti.code_hash AND ac.consumed_by=ti.operation_id
JOIN code_context cc ON cc.code_hash=ac.code_hash
JOIN valid_client_session v ON v.client_id=ac.client_id AND v.sid=ac.sid
JOIN client c ON c.client_id=v.client_id
JOIN app_connection g ON g.account_id=v.account_id AND g.client_id=v.client_id
JOIN account_security a ON a.account_id=v.account_id
JOIN identity_claim_release r ON r.account_id=v.account_id AND r.client_id=v.client_id
JOIN identity_document d ON d.document_id=r.document_id AND d.account_id=r.account_id
WHERE ti.revoked=0 AND ti.access_expires_at>unixepoch()
  AND cc.scope IN ('openid profile','profile openid')
  AND c.active=1 AND c.revision=ac.client_revision AND c.revision=r.client_revision
  AND g.active=1 AND g.grant_version=r.connection_grant_version
  AND a.active=1 AND a.epoch=r.epoch AND a.epoch=d.epoch
  AND r.active=1 AND r.expires_at>unixepoch() AND r.version=q.release_version
  AND r.document_id=q.document_id AND d.revoked=0 AND d.valid_until>unixepoch()
  AND NOT EXISTS(SELECT 1 FROM json_each(q.fields_json) f
    WHERE NOT EXISTS(SELECT 1 FROM json_each(r.fields_json) consent WHERE consent.value=f.value));

-- Digest of a prepared response, committed before releasing it; no attributes or token bytes.
CREATE TABLE identity_age_audit (
  receipt_id TEXT PRIMARY KEY NOT NULL CHECK(length(receipt_id)=43),
  code_hash TEXT NOT NULL REFERENCES identity_age_request(code_hash),
  client_id TEXT NOT NULL REFERENCES client(client_id),
  request_hash TEXT NOT NULL CHECK(length(request_hash)=43),
  document_id TEXT NOT NULL REFERENCES identity_document(document_id),
  release_version INTEGER NOT NULL,
  response_digest TEXT NOT NULL CHECK(length(response_digest)=43),
  signing_kid TEXT NOT NULL REFERENCES signing_key(kid),
  signing_generation INTEGER NOT NULL,
  assurance TEXT NOT NULL CHECK(assurance='issuer_signed_static_data'),
  issued_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL CHECK(expires_at>issued_at AND expires_at<=issued_at+300)
) STRICT;
CREATE INDEX identity_age_audit_code ON identity_age_audit(code_hash);
CREATE TRIGGER identity_age_audit_immutable BEFORE UPDATE ON identity_age_audit
BEGIN SELECT RAISE(ABORT,'age response audit is immutable'); END;
