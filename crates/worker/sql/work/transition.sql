UPDATE work_code_operation SET state=?4,receipt=?5,revision=revision+1
WHERE operation_id=?1 AND revision=?2 AND body=?3 AND state=?6
