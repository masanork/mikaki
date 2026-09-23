INSERT INTO pairwise_subject(account_id,sector_identifier,sub)
SELECT ?1,?2,?3 WHERE EXISTS (
  SELECT 1 FROM account_security WHERE account_id=?1 AND active=1
)
ON CONFLICT(account_id,sector_identifier) DO NOTHING
