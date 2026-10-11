UPDATE work_code_operation SET state='dispatched',revision=revision+1
WHERE operation_id=?1 AND revision=?2 AND body=?3 AND state='prepared'
 AND EXISTS(SELECT 1 FROM work_ready_operation a WHERE a.operation_id=work_code_operation.operation_id)
 AND EXISTS(SELECT 1 FROM work_target_claim l WHERE l.operation_id=work_code_operation.operation_id)
