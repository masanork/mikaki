UPDATE messaging_generation SET status='revoked',revision=revision+1
WHERE (account_id,device_id,generation) IN
(SELECT e.account_id,e.device_id,h.generation FROM messaging_enrollment_ready e
 JOIN messaging_device_head h ON h.account_id=e.account_id AND h.device_id=e.device_id
 WHERE e.enrollment_id=?1 AND e.secret_hash=?2);
