INSERT INTO work_request_preparation(request_digest,repository_id)
SELECT ?1,repository_id FROM work_prepared_task WHERE preparation_id=?2
