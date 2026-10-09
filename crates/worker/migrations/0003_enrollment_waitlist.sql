-- Email addresses are invitation contacts, never account identifiers or recovery credentials.
CREATE TABLE enrollment_waitlist (
  id TEXT PRIMARY KEY CHECK(length(id)=43),
  email TEXT NOT NULL COLLATE NOCASE UNIQUE CHECK(length(email) BETWEEN 3 AND 254),
  locale TEXT NOT NULL CHECK(locale IN ('ja','en')),
  created_at INTEGER NOT NULL,
  verified_at INTEGER,
  confirmation_hash TEXT NOT NULL CHECK(length(confirmation_hash)=43),
  confirmation_expires_at INTEGER NOT NULL,
  confirmation_sent_at INTEGER NOT NULL,
  invite_hash TEXT REFERENCES enrollment_invite(invite_hash)
) STRICT;
CREATE TABLE enrollment_mail (
  id TEXT PRIMARY KEY CHECK(length(id)=43),
  waitlist_id TEXT NOT NULL REFERENCES enrollment_waitlist(id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK(kind IN ('confirmation','invitation')),
  token_hash TEXT NOT NULL CHECK(length(token_hash)=43),
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  state TEXT NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','sending','sent','failed','cancelled')),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts>=0),
  next_attempt_at INTEGER NOT NULL,
  last_attempt_at INTEGER,
  lease_token TEXT,
  lease_until INTEGER NOT NULL DEFAULT 0,
  message_id TEXT,
  CHECK((state='sending')=(lease_token IS NOT NULL))
) STRICT;
CREATE UNIQUE INDEX enrollment_invitation_mail ON enrollment_mail(token_hash) WHERE kind='invitation';
CREATE INDEX enrollment_mail_due ON enrollment_mail(state,next_attempt_at);
CREATE INDEX enrollment_waitlist_order ON enrollment_waitlist(verified_at,created_at,id);
ALTER TABLE admin_invitation_transaction ADD COLUMN waitlist_id TEXT;
ALTER TABLE admin_invitation_transaction ADD COLUMN waitlist_action TEXT CHECK(waitlist_action IN ('invite','resend'));
CREATE TABLE enrollment_waitlist_audit (
  operation_id TEXT PRIMARY KEY,
  waitlist_id TEXT NOT NULL,
  invite_hash TEXT NOT NULL REFERENCES enrollment_invite(invite_hash),
  action TEXT NOT NULL CHECK(action IN ('invite','resend')),
  actor TEXT NOT NULL REFERENCES account_security(account_id),
  occurred_at INTEGER NOT NULL
) STRICT;
CREATE TABLE enrollment_waitlist_policy (
  id INTEGER PRIMARY KEY CHECK(id=1),
  confirmation_ttl_seconds INTEGER NOT NULL CHECK(confirmation_ttl_seconds BETWEEN 300 AND 86400),
  resend_seconds INTEGER NOT NULL CHECK(resend_seconds BETWEEN 60 AND 3600),
  source_per_hour INTEGER NOT NULL CHECK(source_per_hour BETWEEN 1 AND 100),
  deployment_per_hour INTEGER NOT NULL CHECK(deployment_per_hour BETWEEN 1 AND 10000),
  maximum_entries INTEGER NOT NULL CHECK(maximum_entries BETWEEN 1 AND 100000)
) STRICT;
INSERT INTO enrollment_waitlist_policy VALUES(1,3600,600,5,100,10000);
CREATE TABLE enrollment_request_window (
  key_hash TEXT NOT NULL CHECK(length(key_hash)=43),
  window_start INTEGER NOT NULL,
  attempts INTEGER NOT NULL CHECK(attempts>0),
  PRIMARY KEY(key_hash,window_start)
) STRICT;
