-- Unlike readiness this must not recheck the grant: writing the source note can
-- revoke that grant. Only the exact already-consumed immutable approval may pass.
INSERT INTO agent_attribute_commit_guard(operation_id,valid)
VALUES(?5,EXISTS(SELECT 1 FROM vault_owner_record_mutation m
 JOIN agent_attribute_commit ac ON ac.account_id=m.account_id AND ac.operation_id=m.operation_id
 JOIN agent_attribute_proposal p ON p.proposal_id=ac.proposal_id
 JOIN agent_grant g ON g.grant_id=p.grant_id AND g.account_id=m.account_id AND g.storage_version=2
 WHERE m.account_id=?4 AND m.operation_id=?5 AND m.request_hash=?15 AND m.result_revision=?14 AND m.deleted=0
 AND ac.proposal_id=?1 AND ac.storage_version=2 AND ac.candidate_sha256=?6 AND ac.origin=?7
 AND ac.candidate=?13 AND ac.result_revision=?14
 AND p.request_hash=?2 AND p.storage_version=2 AND p.attribute_id='owner_note' AND p.base_revision=?3
 AND p.state='committed' AND p.payload IS NULL AND p.target_origin=?7 AND p.target_vault_id=?10
 AND p.target_collection_id='personal' AND p.target_record_id='owner_note' AND p.target_kind='owner_note'
 AND p.target_key_generation=?11 AND p.target_owner_key_revision=?12 AND ?14=?3+1))
