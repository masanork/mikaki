-- RP session checks use a D1 policy so an incident can shorten the lease
-- without deploying a Worker. Existing RP leases remain bounded by their
-- original expiry and the parent SSO expiry.
CREATE TABLE session_validation_policy (
  id INTEGER PRIMARY KEY NOT NULL CHECK(id=1),
  lease_ttl_seconds INTEGER NOT NULL CHECK(lease_ttl_seconds BETWEEN 1 AND 300),
  app_idle_timeout_seconds INTEGER NOT NULL CHECK(app_idle_timeout_seconds BETWEEN 60 AND 2592000),
  revision INTEGER NOT NULL CHECK(revision > 0)
) STRICT;
INSERT INTO session_validation_policy(id,lease_ttl_seconds,app_idle_timeout_seconds,revision)
  VALUES(1,300,604800,1);
CREATE TRIGGER session_validation_policy_revision BEFORE UPDATE ON session_validation_policy
WHEN NEW.revision <= OLD.revision
BEGIN SELECT RAISE(ABORT, 'session validation policy revision must increase'); END;
