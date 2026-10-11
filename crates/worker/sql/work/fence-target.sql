UPDATE work_code_target SET revision=revision+1,writable=0
WHERE revision<9007199254740991 AND EXISTS(SELECT 1 FROM work_target_claim l JOIN work_code_operation o ON o.operation_id=l.operation_id
 WHERE l.repository_id=work_code_target.repository_id AND l.reference=work_code_target.reference
 AND o.operation_id=?1 AND o.state IN('applied','rejected'))
