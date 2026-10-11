INSERT INTO work_transition_guard(guard_id,passed) VALUES(?1,CASE WHEN changes()=1 THEN 1 ELSE 0 END)
