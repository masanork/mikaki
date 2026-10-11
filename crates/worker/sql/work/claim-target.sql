INSERT INTO work_target_claim(repository_id,reference,operation_id)
SELECT json_extract(o.body,'$.data.effect.repository'),json_extract(o.body,'$.data.effect.reference'),o.operation_id
FROM work_ready_operation o WHERE o.operation_id=?1 AND o.revision=?2 AND o.body=?3
 AND NOT EXISTS(SELECT 1 FROM work_target_claim l WHERE l.repository_id=json_extract(o.body,'$.data.effect.repository')
  AND l.reference=json_extract(o.body,'$.data.effect.reference'))
