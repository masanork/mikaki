-- Explicit opt-in messaging schema. Apply only after the beta release preflight.
-- Requires the existing account_security/credential/sso_session/sso_context tables.
CREATE VIEW messaging_live_owner AS
SELECT ss.account_id,sx.secret_hash,ss.credential_id
FROM sso_context sx JOIN sso_session ss ON ss.sso_id=sx.sso_id
JOIN account_security a ON a.account_id=ss.account_id
JOIN credential c ON c.credential_id=ss.credential_id AND c.account_id=ss.account_id
WHERE ss.revoked=0 AND ss.expires_at>unixepoch() AND a.active=1
AND a.epoch=ss.epoch AND c.active=1;
CREATE TABLE messaging_account (
  owner_id TEXT PRIMARY KEY REFERENCES account_security(account_id),
  account_id TEXT NOT NULL UNIQUE CHECK(length(account_id)=36)
) STRICT;
CREATE TABLE messaging_device_head (
  account_id TEXT NOT NULL REFERENCES messaging_account(account_id),
  device_id TEXT NOT NULL,
  generation INTEGER NOT NULL CHECK(generation BETWEEN 1 AND 9007199254740991),
  revision INTEGER NOT NULL CHECK(revision BETWEEN 1 AND 9007199254740991),
  PRIMARY KEY(account_id,device_id)
) STRICT;
CREATE TABLE messaging_generation (
  account_id TEXT NOT NULL REFERENCES messaging_account(account_id),
  device_id TEXT NOT NULL,
  generation INTEGER NOT NULL CHECK(generation>0),
  revision INTEGER NOT NULL CHECK(revision>0),
  public_key TEXT NOT NULL CHECK(length(public_key)=43),
  status TEXT NOT NULL CHECK(status IN('active','revoked')),
  storage_id TEXT NOT NULL,
  key_id TEXT NOT NULL,
  fingerprint TEXT NOT NULL CHECK(length(fingerprint)=43),
  scope_hash TEXT NOT NULL UNIQUE CHECK(length(scope_hash)=43),
  enrollment_id TEXT NOT NULL UNIQUE,
  head_revision INTEGER NOT NULL DEFAULT 0 CHECK(head_revision BETWEEN 0 AND 9007199254740991),
  head_hash TEXT CHECK(length(head_hash)=43),
  PRIMARY KEY(account_id,device_id,generation),
  UNIQUE(account_id,public_key),
  CHECK((head_revision=0 AND head_hash IS NULL) OR (head_revision>0 AND head_hash IS NOT NULL))
) STRICT;
CREATE TABLE messaging_enrollment (
  enrollment_id TEXT PRIMARY KEY CHECK(length(enrollment_id)=36),
  owner_id TEXT NOT NULL REFERENCES messaging_account(owner_id),
  secret_hash TEXT NOT NULL,
  credential_id TEXT NOT NULL,
  request_hash TEXT NOT NULL,
  device_id TEXT NOT NULL,
  generation INTEGER NOT NULL,
  expected_revision INTEGER NOT NULL CHECK(expected_revision>=0),
  public_key TEXT NOT NULL,
  storage_id TEXT NOT NULL,
  key_id TEXT NOT NULL,
  nonce TEXT NOT NULL CHECK(length(nonce)=43),
  expires_at INTEGER NOT NULL,
  consumed_proof TEXT,
  created_at INTEGER NOT NULL DEFAULT(unixepoch())
) STRICT;
CREATE TABLE messaging_commit_guard (
  operation_id TEXT PRIMARY KEY,
  valid INTEGER NOT NULL CHECK(valid=1)
) STRICT;
CREATE VIEW messaging_enrollment_ready AS
SELECT e.*,m.account_id FROM messaging_enrollment e
JOIN messaging_account m ON m.owner_id=e.owner_id
JOIN messaging_live_owner a ON a.account_id=e.owner_id AND a.secret_hash=e.secret_hash AND a.credential_id=e.credential_id
LEFT JOIN messaging_device_head h ON h.account_id=m.account_id AND h.device_id=e.device_id
WHERE e.consumed_proof IS NULL AND e.expires_at>unixepoch()
AND COALESCE(h.revision,0)=e.expected_revision AND COALESCE(h.generation,0)+1=e.generation
AND NOT EXISTS(SELECT 1 FROM messaging_generation g WHERE g.account_id=m.account_id AND g.public_key=e.public_key)
AND (SELECT count(*) FROM messaging_generation g WHERE g.account_id=m.account_id)<64
AND (h.device_id IS NOT NULL OR (SELECT count(*) FROM messaging_device_head d WHERE d.account_id=m.account_id)<8);

-- Established, explicitly confirmed 1:1 groups; ciphertext only, no MLS secrets.
CREATE VIEW messaging_live_device AS
SELECT g.*,m.owner_id FROM messaging_generation g
JOIN messaging_device_head h ON h.account_id=g.account_id AND h.device_id=g.device_id AND h.generation=g.generation
JOIN messaging_account m ON m.account_id=g.account_id
JOIN account_security a ON a.account_id=m.owner_id AND a.active=1
WHERE g.status='active';
CREATE TABLE messaging_channel (
  channel_id TEXT PRIMARY KEY,
  group_id TEXT NOT NULL,
  a_scope TEXT NOT NULL REFERENCES messaging_generation(scope_hash),
  b_scope TEXT NOT NULL REFERENCES messaging_generation(scope_hash),
  a_fingerprint TEXT NOT NULL,
  b_fingerprint TEXT NOT NULL,
  a_consent INTEGER NOT NULL CHECK(a_consent IN(0,1)),
  b_consent INTEGER NOT NULL CHECK(b_consent IN(0,1)),
  blocked INTEGER NOT NULL DEFAULT 0 CHECK(blocked IN(0,1)),
  inviter_scope TEXT,
  bootstrap_complete INTEGER NOT NULL DEFAULT 1 CHECK(bootstrap_complete IN(0,1)),
  predecessor_id TEXT REFERENCES messaging_channel(channel_id),
  CHECK((inviter_scope IS NOT NULL AND inviter_scope IN(a_scope,b_scope)) OR (inviter_scope IS NULL AND bootstrap_complete=1)),
  CHECK(a_scope<b_scope),
  UNIQUE(a_scope,b_scope,group_id)
) STRICT;
CREATE VIEW messaging_delivery_ready AS
SELECT c.*,a.owner_id AS a_owner,b.owner_id AS b_owner
FROM messaging_channel c
JOIN messaging_live_device a ON a.scope_hash=c.a_scope AND a.fingerprint=c.a_fingerprint
JOIN messaging_live_device b ON b.scope_hash=c.b_scope AND b.fingerprint=c.b_fingerprint
WHERE c.a_consent=1 AND c.b_consent=1 AND c.blocked=0;
CREATE TABLE messaging_mail (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT CHECK(sequence BETWEEN 1 AND 9007199254740991),
  channel_id TEXT NOT NULL REFERENCES messaging_channel(channel_id),
  message_id TEXT NOT NULL,
  sender_scope TEXT NOT NULL REFERENCES messaging_generation(scope_hash),
  recipient_scope TEXT NOT NULL REFERENCES messaging_generation(scope_hash),
  kind TEXT NOT NULL CHECK(kind IN('application','commit')),
  digest TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  envelope_hash TEXT NOT NULL,
  wire TEXT,
  consumed INTEGER NOT NULL DEFAULT 0 CHECK(consumed IN(0,1)),
  CHECK((consumed=0 AND wire IS NOT NULL) OR (consumed=1 AND wire IS NULL)),
  UNIQUE(sender_scope,message_id)
) STRICT;
CREATE INDEX messaging_mail_inbox ON messaging_mail(channel_id,recipient_scope,consumed,sequence);
CREATE INDEX messaging_channel_a ON messaging_channel(a_scope,a_consent);
CREATE INDEX messaging_channel_b ON messaging_channel(b_scope,b_consent);
CREATE TABLE messaging_channel_close (
  channel_id TEXT NOT NULL REFERENCES messaging_channel(channel_id),
  scope_hash TEXT NOT NULL REFERENCES messaging_generation(scope_hash),
  operation_id TEXT NOT NULL UNIQUE,
  reason TEXT NOT NULL CHECK(reason IN('cancel_invitation','epoch_conflict','leave')),
  intent_hash TEXT NOT NULL,
  PRIMARY KEY(channel_id,scope_hash)
) STRICT;
CREATE TABLE messaging_invitation_packet (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT CHECK(sequence BETWEEN 1 AND 9007199254740991),
  channel_id TEXT NOT NULL REFERENCES messaging_channel(channel_id),
  message_id TEXT NOT NULL,
  sender_scope TEXT NOT NULL REFERENCES messaging_generation(scope_hash),
  recipient_scope TEXT NOT NULL REFERENCES messaging_generation(scope_hash),
  kind TEXT NOT NULL CHECK(kind IN('key_package','invite_commit','welcome')),
  digest TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  envelope_hash TEXT NOT NULL,
  wire TEXT,
  finished INTEGER NOT NULL DEFAULT 0 CHECK(finished IN(0,1)),
  CHECK((finished=0 AND wire IS NOT NULL) OR (finished=1 AND wire IS NULL)),
  UNIQUE(channel_id,kind),
  UNIQUE(sender_scope,message_id)
) STRICT;
CREATE INDEX messaging_channel_successor ON messaging_channel(predecessor_id,blocked,a_consent,b_consent);
CREATE TABLE messaging_replacement_approval (
  channel_id TEXT NOT NULL REFERENCES messaging_channel(channel_id),
  owner_id TEXT NOT NULL REFERENCES account_security(account_id),
  scope_hash TEXT NOT NULL REFERENCES messaging_generation(scope_hash),
  operation_id TEXT NOT NULL UNIQUE,
  intent_hash TEXT NOT NULL,
  PRIMARY KEY(channel_id,owner_id)
) STRICT;
-- Exactly one slot changes to a higher generation/different key. The other
-- endpoint stays byte-for-byte identical. Admission uses the live-pair view;
-- cancellation can match a historical peer while requiring a live caller.
CREATE VIEW messaging_replacement_candidate AS
SELECT c.channel_id AS previous_id,c.group_id AS previous_group,c.a_scope AS old_a_scope,c.b_scope AS old_b_scope,
c.a_fingerprint AS old_a_fingerprint,c.b_fingerprint AS old_b_fingerprint,c.inviter_scope AS old_inviter,
CASE WHEN na.scope_hash<nb.scope_hash THEN na.scope_hash ELSE nb.scope_hash END AS next_a_scope,
CASE WHEN na.scope_hash<nb.scope_hash THEN nb.scope_hash ELSE na.scope_hash END AS next_b_scope,
CASE WHEN na.scope_hash<nb.scope_hash THEN na.fingerprint ELSE nb.fingerprint END AS next_a_fingerprint,
CASE WHEN na.scope_hash<nb.scope_hash THEN nb.fingerprint ELSE na.fingerprint END AS next_b_fingerprint,
CASE WHEN na.scope_hash<nb.scope_hash THEN ma.owner_id ELSE mb.owner_id END AS next_a_owner,
CASE WHEN na.scope_hash<nb.scope_hash THEN mb.owner_id ELSE ma.owner_id END AS next_b_owner
FROM messaging_channel c
JOIN messaging_generation oa ON oa.scope_hash=c.a_scope AND oa.fingerprint=c.a_fingerprint
JOIN messaging_generation ob ON ob.scope_hash=c.b_scope AND ob.fingerprint=c.b_fingerprint
JOIN messaging_generation na ON na.account_id=oa.account_id AND na.device_id=oa.device_id
JOIN messaging_generation nb ON nb.account_id=ob.account_id AND nb.device_id=ob.device_id
JOIN messaging_account ma ON ma.account_id=na.account_id
JOIN messaging_account mb ON mb.account_id=nb.account_id
WHERE ma.owner_id<>mb.owner_id AND c.inviter_scope IS NOT NULL AND c.bootstrap_complete=1
AND ((na.scope_hash=oa.scope_hash AND na.fingerprint=oa.fingerprint AND nb.generation>ob.generation AND nb.public_key<>ob.public_key AND nb.fingerprint<>ob.fingerprint)
OR (nb.scope_hash=ob.scope_hash AND nb.fingerprint=ob.fingerprint AND na.generation>oa.generation AND na.public_key<>oa.public_key AND na.fingerprint<>oa.fingerprint));

CREATE VIEW messaging_replacement_pair AS
SELECT p.* FROM messaging_replacement_candidate p
JOIN messaging_live_device a ON a.scope_hash=p.next_a_scope
JOIN messaging_live_device b ON b.scope_hash=p.next_b_scope;
CREATE TABLE messaging_replacement_cancellation (
  channel_id TEXT NOT NULL REFERENCES messaging_channel(channel_id),
  owner_id TEXT NOT NULL REFERENCES account_security(account_id),
  scope_hash TEXT NOT NULL REFERENCES messaging_generation(scope_hash),
  approval_id TEXT NOT NULL,
  operation_id TEXT NOT NULL UNIQUE,
  intent_hash TEXT NOT NULL,
  outcome TEXT NOT NULL CHECK(outcome IN('cancelled','admitted')),
  PRIMARY KEY(channel_id,owner_id)
) STRICT;
-- Retained veto receipts also cover proposals whose approval never arrived.
CREATE TABLE messaging_rejoin_cancellation (
  channel_id TEXT NOT NULL REFERENCES messaging_channel(channel_id),
  owner_id TEXT NOT NULL REFERENCES account_security(account_id),
  scope_hash TEXT NOT NULL REFERENCES messaging_generation(scope_hash),
  operation_id TEXT NOT NULL UNIQUE,
  intent_hash TEXT NOT NULL,
  outcome TEXT NOT NULL CHECK(outcome IN('cancelled','admitted')),
  PRIMARY KEY(channel_id,owner_id)
) STRICT;
CREATE INDEX messaging_rejoin_cancellation_owner ON messaging_rejoin_cancellation(owner_id);
-- Explicit stop-only receipts survive subsequent endpoint registrations. Each
-- current generation records its own immutable intent; none conveys consent.
CREATE TABLE messaging_replacement_stop (
  channel_id TEXT NOT NULL REFERENCES messaging_channel(channel_id),
  owner_id TEXT NOT NULL REFERENCES account_security(account_id),
  scope_hash TEXT NOT NULL REFERENCES messaging_generation(scope_hash),
  operation_id TEXT NOT NULL UNIQUE,
  intent_hash TEXT NOT NULL,
  PRIMARY KEY(channel_id,scope_hash)
) STRICT;
CREATE INDEX messaging_replacement_stop_owner ON messaging_replacement_stop(owner_id);
