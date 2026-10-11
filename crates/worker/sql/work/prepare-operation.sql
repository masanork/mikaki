INSERT INTO work_code_operation(operation_id,approval_id,owner_id,state,body)
SELECT json_extract(?1,'$.data.id'),a.approval_id,a.owner_id,'prepared',?1 FROM work_adoption_authority a
WHERE a.approval_id=json_extract(?1,'$.data.effect.approval') AND a.owner_id=json_extract(?1,'$.data.effect.owner')
