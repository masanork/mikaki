-- Disabling a recipient key is an incident stop. Preserve envelope history,
-- but make every active Grant for that key visibly revoked in D1.
CREATE TRIGGER vault_recipient_disabled_revoke_grants
AFTER UPDATE OF state ON vault_recipient_key
WHEN NEW.state = 'disabled' AND OLD.state != 'disabled'
BEGIN
  UPDATE vault_attribute_grant
  SET status = 'revoked', version = version + 1,
      updated_at = CAST(strftime('%s','now') AS INTEGER)
  WHERE status = 'active' AND envelope_id IN (
    SELECT envelope_id FROM vault_attribute_recipient_envelope
    WHERE recipient_key_id = NEW.key_id
  );
END;

-- Reconcile rows stopped before this migration was installed.
UPDATE vault_attribute_grant
SET status = 'revoked', version = version + 1,
    updated_at = CAST(strftime('%s','now') AS INTEGER)
WHERE status = 'active' AND envelope_id IN (
  SELECT e.envelope_id FROM vault_attribute_recipient_envelope e
  JOIN vault_recipient_key k ON k.key_id = e.recipient_key_id
  WHERE k.state = 'disabled'
);
