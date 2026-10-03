UPDATE agent_attribute_commit SET result_revision=?14
WHERE proposal_id=?1 AND storage_version=2 AND account_id=?4 AND operation_id=?5
AND candidate_sha256=?6 AND candidate=?13 AND origin=?7 AND result_revision IS NULL
AND EXISTS(SELECT 1 FROM vault_owner_record_mutation m WHERE m.account_id=?4 AND m.operation_id=?5
  AND m.request_hash=?15 AND m.result_revision=?14 AND m.deleted=0)
