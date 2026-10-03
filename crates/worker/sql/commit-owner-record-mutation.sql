INSERT INTO vault_owner_record_mutation(account_id,operation_id,request_hash,result_revision,deleted,created_at)
SELECT ?1,?2,?3,?4,?5,unixepoch() WHERE changes()=1
