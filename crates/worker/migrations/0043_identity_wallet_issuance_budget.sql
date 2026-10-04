-- Existing approvals retain their one-credential budget. New HAIP consent
-- explicitly approves at most 16 credentials within the original token lifetime.
ALTER TABLE identity_wallet_grant ADD COLUMN redeemed_code_hash TEXT;
CREATE UNIQUE INDEX identity_wallet_redeemed_code ON identity_wallet_grant(redeemed_code_hash);
ALTER TABLE identity_wallet_grant ADD COLUMN issuance_limit INTEGER NOT NULL DEFAULT 1 CHECK(issuance_limit IN (1,16));
ALTER TABLE identity_wallet_grant ADD COLUMN issuance_count INTEGER NOT NULL DEFAULT 0 CHECK(issuance_count>=0 AND issuance_count<=issuance_limit);
UPDATE identity_wallet_grant SET issuance_count=1 WHERE state='issued';
DROP TRIGGER identity_wallet_issue_guard;
DROP TRIGGER identity_wallet_consume_nonce;
CREATE TRIGGER identity_wallet_issue_guard BEFORE UPDATE OF issuance_count ON identity_wallet_grant
BEGIN
  SELECT CASE WHEN OLD.state!='token' OR NEW.issuance_limit!=OLD.issuance_limit
    OR NEW.issuance_count!=OLD.issuance_count+1
    OR OLD.token_expires_at<=unixepoch() OR OLD.token_expires_at IS NULL
    OR NEW.token_expires_at IS NOT OLD.token_expires_at
    OR NEW.holder_json IS NULL
    OR (NEW.issuance_count<NEW.issuance_limit AND (NEW.state!='token' OR NEW.access_hash IS NOT OLD.access_hash))
    OR (NEW.issuance_count=NEW.issuance_limit AND (NEW.state!='issued' OR NEW.access_hash IS NOT NULL))
    OR NOT EXISTS (
      SELECT 1 FROM identity_nonce n WHERE n.nonce_hash=NEW.proof_nonce_hash
        AND n.used=0 AND n.expires_at>unixepoch()
    ) OR NOT EXISTS (
      SELECT 1 FROM identity_document d JOIN account_security a ON a.account_id=d.account_id
      WHERE d.document_id=NEW.document_id AND d.account_id=NEW.account_id
        AND d.revoked=0 AND d.valid_until>unixepoch() AND d.policy_hash=NEW.policy_hash
        AND a.active=1 AND a.epoch=d.epoch AND a.epoch=NEW.epoch
    ) THEN RAISE(ABORT,'identity wallet issuance preconditions failed') END;
END;
CREATE TRIGGER identity_wallet_consume_nonce AFTER UPDATE OF issuance_count ON identity_wallet_grant
BEGIN
  UPDATE identity_nonce SET used=1 WHERE nonce_hash=NEW.proof_nonce_hash;
END;
