INSERT INTO work_disclosure_window(owner_id,window_start,attempts)
VALUES(?1,(unixepoch()/3600)*3600,1)
ON CONFLICT(owner_id,window_start) DO UPDATE SET attempts=attempts+1
