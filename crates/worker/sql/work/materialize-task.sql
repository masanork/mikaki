INSERT INTO work_task_repository(repository_id,owner_id,revision,disclosure_digest,recipient,workload,code_repository,base_commit)
SELECT p.task_repository,p.owner_id,1,p.disclosure_digest,
 json_extract(d.body,'$.data.data.recipient'),json_extract(d.body,'$.data.data.workload'),
 json_extract(d.body,'$.data.data.code.repository'),json_extract(d.body,'$.data.data.code.commit')
FROM work_preparation p JOIN work_disclosure d ON d.digest=p.disclosure_digest
 JOIN work_disclosure_source_current c ON c.digest=d.digest
WHERE p.operation_id=?1 AND p.state='verified' AND p.expires_at>unixepoch()
