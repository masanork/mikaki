UPDATE work_preparation SET state=?4,revision=revision+1,evidence=?5,cleanup_receipt=?6
WHERE operation_id=?1 AND revision=?2 AND body=?3
