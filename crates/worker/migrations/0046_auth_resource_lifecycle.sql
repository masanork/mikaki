CREATE TABLE auth_resource_policy (
  id INTEGER PRIMARY KEY CHECK(id=1),
  source_per_minute INTEGER NOT NULL CHECK(source_per_minute BETWEEN 1 AND 10000),
  deployment_per_minute INTEGER NOT NULL CHECK(deployment_per_minute BETWEEN 1 AND 10000),
  pending_per_browser INTEGER NOT NULL CHECK(pending_per_browser BETWEEN 2 AND 100),
  pending_per_client INTEGER NOT NULL CHECK(pending_per_client BETWEEN 10 AND 1000),
  pending_total INTEGER NOT NULL CHECK(pending_total BETWEEN 100 AND 10000)
) STRICT;
INSERT INTO auth_resource_policy VALUES(1,120,600,5,100,1000);
CREATE TABLE auth_request_window (
  key_hash TEXT NOT NULL,
  window_start INTEGER NOT NULL,
  attempts INTEGER NOT NULL CHECK(attempts>0),
  PRIMARY KEY(key_hash,window_start)
) STRICT;
CREATE INDEX auth_window_expiry ON auth_request_window(window_start);
CREATE INDEX login_expiry ON login_transaction(expires_at);
CREATE INDEX login_browser_pending ON login_transaction(browser_hash,consumed,expires_at);
CREATE INDEX login_client_pending ON login_transaction(client_id,consumed,expires_at);
CREATE INDEX login_pending ON login_transaction(consumed,expires_at);
CREATE INDEX owner_login_expiry ON owner_login_transaction(expires_at);
CREATE INDEX owner_login_pending ON owner_login_transaction(consumed,expires_at);
CREATE INDEX owner_login_browser_pending ON owner_login_transaction(browser_hash,consumed,expires_at);
CREATE INDEX web_login_pending ON web_login_transaction(consumed,expires_at);
CREATE INDEX web_login_browser_pending ON web_login_transaction(browser_hash,consumed,expires_at);
CREATE INDEX logout_event_deadline ON sso_logout_event(deadline);
CREATE INDEX registration_expiry ON registration_transaction(expires_at);
CREATE INDEX code_expiry ON authorization_code(expires_at);
CREATE INDEX token_expiry ON token_issue(access_expires_at);
CREATE INDEX sso_expiry ON sso_session(expires_at);

CREATE TRIGGER login_transaction_capacity BEFORE INSERT ON login_transaction
WHEN (SELECT count(*) FROM login_transaction WHERE consumed=0 AND expires_at>unixepoch()) >= (SELECT pending_total FROM auth_resource_policy WHERE id=1)
 OR (SELECT count(*) FROM login_transaction WHERE browser_hash=NEW.browser_hash AND consumed=0 AND expires_at>unixepoch()) >= (SELECT pending_per_browser FROM auth_resource_policy WHERE id=1)
 OR (SELECT count(*) FROM login_transaction WHERE client_id=NEW.client_id AND consumed=0 AND expires_at>unixepoch()) >= (SELECT pending_per_client FROM auth_resource_policy WHERE id=1)
BEGIN SELECT RAISE(ABORT,'auth_capacity_exceeded'); END;

CREATE TRIGGER owner_login_transaction_capacity BEFORE INSERT ON owner_login_transaction
WHEN (SELECT count(*) FROM owner_login_transaction WHERE consumed=0 AND expires_at>unixepoch()) >= (SELECT pending_total FROM auth_resource_policy WHERE id=1)
 OR (SELECT count(*) FROM owner_login_transaction WHERE browser_hash=NEW.browser_hash AND consumed=0 AND expires_at>unixepoch()) >= (SELECT pending_per_browser FROM auth_resource_policy WHERE id=1)
BEGIN SELECT RAISE(ABORT,'auth_capacity_exceeded'); END;

CREATE TRIGGER web_login_transaction_capacity BEFORE INSERT ON web_login_transaction
WHEN (SELECT count(*) FROM web_login_transaction WHERE consumed=0 AND expires_at>unixepoch()) >= (SELECT pending_total FROM auth_resource_policy WHERE id=1)
 OR (SELECT count(*) FROM web_login_transaction WHERE browser_hash=NEW.browser_hash AND consumed=0 AND expires_at>unixepoch()) >= (SELECT pending_per_browser FROM auth_resource_policy WHERE id=1)
BEGIN SELECT RAISE(ABORT,'auth_capacity_exceeded'); END;

DROP TRIGGER vault_oauth_token_context_no_delete;
CREATE TRIGGER vault_oauth_token_context_no_delete BEFORE DELETE ON vault_oauth_token_context
WHEN NOT EXISTS(SELECT 1 FROM token_issue ti WHERE ti.access_hash=OLD.access_hash AND ti.access_expires_at<unixepoch()-7776000)
BEGIN SELECT RAISE(ABORT,'vault audit retention active'); END;

DROP TRIGGER vault_oauth_code_context_no_delete;
CREATE TRIGGER vault_oauth_code_context_no_delete BEFORE DELETE ON vault_oauth_code_context
WHEN NOT EXISTS(SELECT 1 FROM authorization_code ac WHERE ac.code_hash=OLD.code_hash AND ac.expires_at<unixepoch()-7776000)
BEGIN SELECT RAISE(ABORT,'vault audit retention active'); END;

DROP TRIGGER vault_oauth_grant_no_delete;
CREATE TRIGGER vault_oauth_grant_no_delete BEFORE DELETE ON vault_oauth_grant
WHEN OLD.expires_at>=unixepoch()-7776000
BEGIN SELECT RAISE(ABORT,'vault audit retention active'); END;

DROP TRIGGER vault_oauth_consent_no_delete;
CREATE TRIGGER vault_oauth_consent_no_delete BEFORE DELETE ON vault_oauth_consent
WHEN OLD.expires_at>=unixepoch()-7776000
BEGIN SELECT RAISE(ABORT,'vault audit retention active'); END;
