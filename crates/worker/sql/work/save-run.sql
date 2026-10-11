INSERT INTO work_run(run_id,grant_id,request_digest,expires_at,body)
SELECT json_extract(?1,'$.data.id'),g.grant_id,g.request_digest,json_extract(?1,'$.data.expires_at'),?1
FROM work_live_grant g JOIN work_request w ON w.digest=g.request_digest
WHERE g.grant_id=json_extract(?1,'$.data.grant') AND g.request_digest=json_extract(?1,'$.data.request')
 AND json_extract(?1,'$.data.expires_at')>unixepoch() AND json_extract(?1,'$.data.expires_at')<=g.expires_at
 AND ?2>unixepoch()
 AND (?3 IS NULL OR EXISTS(SELECT 1 FROM work_request_disclosure b JOIN work_disclosure_source_current d ON d.digest=b.disclosure_digest
  WHERE b.request_digest=w.digest AND b.disclosure_digest=?3))
 AND json_extract(?1,'$.data.client')=json_extract(w.body,'$.data.input.recipient')
 AND json_extract(?1,'$.data.workload')=json_extract(w.body,'$.data.input.workload')
