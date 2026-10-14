UPDATE app_connection
SET reviewed_redirect_uri=?1,reviewed_scope=?2,
    reviewed_client_revision=(SELECT revision FROM client WHERE client_id=?4),
    reviewed_grant_version=grant_version
WHERE account_id=?3 AND client_id=?4 AND active=1
  AND EXISTS (
    SELECT 1 FROM login_transaction l
    JOIN client c ON c.client_id=l.client_id AND c.active=1 AND c.revision=l.client_revision
    JOIN client_redirect_uri r ON r.client_id=c.client_id AND r.redirect_uri=?1 AND r.active=1
    WHERE l.tx_id=?5 AND l.browser_hash=?6 AND l.client_id=?4 AND l.consumed=1 AND l.requested_scope=?2
  )
