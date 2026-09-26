-- An RP-initiated logout can identify the exact ID Token issued to its client
-- without storing the token itself or accepting an unverified JWT payload.
ALTER TABLE token_issue ADD COLUMN id_token_hash TEXT
  CHECK(id_token_hash IS NULL OR length(id_token_hash) = 43);
CREATE INDEX token_issue_id_token_hash ON token_issue(id_token_hash)
  WHERE id_token_hash IS NOT NULL;
