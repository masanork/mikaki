FROM token_issue ti
JOIN authorization_code ac ON ac.code_hash=ti.code_hash AND ac.consumed_by=ti.operation_id
JOIN code_context cc ON cc.code_hash=ac.code_hash
JOIN valid_client_session v ON v.client_id=ac.client_id AND v.sid=ac.sid
JOIN vault_claim_release r ON r.account_id=v.account_id AND r.client_id=ac.client_id AND r.claim='name'
JOIN vault_claim_release_policy rp ON rp.id=1
JOIN vault_share_policy sp ON sp.id=1
JOIN vault_attribute_grant g ON g.account_id=v.account_id AND g.attribute_id='name'
  AND g.recipient_service='userinfo' AND g.purpose='oidc.userinfo.name'
JOIN vault_attribute_head h ON h.account_id=v.account_id AND h.attribute_id='name'
JOIN vault_attribute_recipient_envelope e ON e.envelope_id=g.envelope_id
JOIN vault_recipient_key k ON k.key_id=e.recipient_key_id
JOIN client c ON c.client_id=ac.client_id
JOIN app_connection a ON a.account_id=v.account_id AND a.client_id=ac.client_id
WHERE ti.access_hash=?1 AND ti.revoked=0 AND ti.access_expires_at>unixepoch()
AND cc.scope IN ('openid profile','profile openid')
AND rp.enabled=1 AND sp.enabled=1
AND r.status='active' AND r.expires_at>unixepoch()
AND g.status='active' AND g.expires_at>unixepoch()
AND r.attribute_revision=g.attribute_revision AND r.system_grant_version=g.version
AND r.client_revision=c.revision AND ac.client_revision=c.revision
AND r.connection_grant_version=a.grant_version
AND c.active=1 AND a.active=1
AND h.deleted=0 AND h.revision=r.attribute_revision
AND h.ciphertext_sha256=e.ciphertext_sha256
AND e.account_id=v.account_id AND e.attribute_id='name'
AND e.attribute_revision=h.revision AND e.recipient_service='userinfo'
AND k.service_id='userinfo' AND k.state='active'
AND k.generation=e.recipient_generation
