INSERT INTO work_prepared_task(repository_id,preparation_id,preparation_digest,task_repo_id,snapshot_repo_id,payload_receipt,credential_receipt)
SELECT task_repository,operation_id,digest,json_extract(evidence,'$.data.task_repo_id'),json_extract(evidence,'$.data.snapshot_repo_id'),
 json_extract(evidence,'$.data.payload_receipt'),json_extract(evidence,'$.data.credential_receipt')
FROM work_preparation WHERE operation_id=?1
