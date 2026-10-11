UPDATE work_candidate_payload SET state='retained',revision=2
WHERE candidate_digest=?1 AND body=?2 AND state='reserved' AND revision=1
