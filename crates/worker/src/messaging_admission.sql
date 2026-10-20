-- Materialize the decision before either counter changes. Both reservations
-- succeed together, including when isolates race or only one new row would fit.
WITH admission AS MATERIALIZED (
  SELECT 1
  WHERE COALESCE((SELECT attempts FROM messaging_request_window WHERE key_hash=?1 AND window_start=?3),0)<?4
    AND COALESCE((SELECT attempts FROM messaging_request_window WHERE key_hash=?2 AND window_start=?3),0)<?5
    AND (SELECT count(*) FROM messaging_request_window)
      +(NOT EXISTS(SELECT 1 FROM messaging_request_window WHERE key_hash=?1 AND window_start=?3))
      +(NOT EXISTS(SELECT 1 FROM messaging_request_window WHERE key_hash=?2 AND window_start=?3))<=10000
)
INSERT INTO messaging_request_window(key_hash,window_start,attempts)
SELECT ?1,?3,1 FROM admission
UNION ALL SELECT ?2,?3,1 FROM admission WHERE 1
ON CONFLICT(key_hash,window_start) DO UPDATE SET attempts=attempts+1
RETURNING key_hash;
