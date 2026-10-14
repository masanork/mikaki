-- Existing connections deliberately remain unreviewed until a Passkey login.
-- One current context per account/app; switching context requires review again.
ALTER TABLE app_connection ADD COLUMN reviewed_redirect_uri TEXT;
ALTER TABLE app_connection ADD COLUMN reviewed_scope TEXT;
ALTER TABLE app_connection ADD COLUMN reviewed_client_revision INTEGER;
ALTER TABLE app_connection ADD COLUMN reviewed_grant_version INTEGER;

ALTER TABLE login_transaction ADD COLUMN client_revision INTEGER;
ALTER TABLE login_transaction ADD COLUMN requested_scope TEXT;
ALTER TABLE login_transaction ADD COLUMN connection_review_required INTEGER NOT NULL DEFAULT 0
  CHECK(connection_review_required IN (0,1));
