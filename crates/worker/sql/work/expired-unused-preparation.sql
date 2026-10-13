state='reserved' AND revision=1 AND expires_at<=unixepoch()
AND evidence IS NULL AND cleanup_receipt IS NULL
AND NOT EXISTS(SELECT 1 FROM work_copy_job WHERE preparation_id=work_preparation.operation_id)
AND NOT EXISTS(SELECT 1 FROM work_credential_attempt WHERE preparation_id=work_preparation.operation_id)
AND NOT EXISTS(SELECT 1 FROM work_preparation_repository WHERE preparation_id=work_preparation.operation_id)
AND NOT EXISTS(SELECT 1 FROM work_prepared_task WHERE preparation_id=work_preparation.operation_id)
AND NOT EXISTS(SELECT 1 FROM work_candidate_payload WHERE preparation_id=work_preparation.operation_id)
