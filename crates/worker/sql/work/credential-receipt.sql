SELECT body,observation,confirmation,receipt
FROM work_credential_attempt
WHERE preparation_id=?1
AND state='closed'
AND confirmation IN('refused','expired')
ORDER BY role,purpose
