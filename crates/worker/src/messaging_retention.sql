DELETE FROM messaging_request_window WHERE rowid IN (
  SELECT rowid FROM messaging_request_window
  WHERE window_start<unixepoch()-120
  ORDER BY window_start LIMIT 1000
);
