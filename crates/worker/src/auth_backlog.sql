SELECT 'login' AS kind, count(*) AS expired, min(expires_at) AS oldest
FROM login_transaction
WHERE expires_at < unixepoch() - 86400;

SELECT 'codes' AS kind, count(*) AS expired, min(expires_at) AS oldest
FROM authorization_code
WHERE expires_at < unixepoch() - 7776000;

SELECT 'tokens' AS kind, count(*) AS expired, min(access_expires_at) AS oldest
FROM token_issue
WHERE access_expires_at < unixepoch() - 7776000;

SELECT 'sso' AS kind, count(*) AS expired, min(expires_at) AS oldest
FROM sso_session
WHERE expires_at < unixepoch() - 7776000;

SELECT 'logout' AS kind, count(*) AS expired, min(deadline) AS oldest
FROM sso_logout_event
WHERE deadline < unixepoch() - 7776000;

SELECT 'dpop' AS kind, count(*) AS expired, min(retain_until) AS oldest
FROM dpop_proof_use
WHERE retain_until < unixepoch();
