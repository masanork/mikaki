-- Optional RFC 9396 application profile. Existing scope-only requests retain
-- their contract; a detailed request is copied unchanged into its token.
ALTER TABLE agent_oauth_request ADD COLUMN authorization_details TEXT
  CHECK(authorization_details IS NULL OR json_valid(authorization_details));
ALTER TABLE agent_oauth_token ADD COLUMN authorization_details TEXT
  CHECK(authorization_details IS NULL OR json_valid(authorization_details));
CREATE TRIGGER agent_oauth_request_details_immutable BEFORE UPDATE OF authorization_details ON agent_oauth_request
BEGIN SELECT RAISE(ABORT,'authorization details are immutable'); END;
