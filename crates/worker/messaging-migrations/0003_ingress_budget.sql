-- Independent Chat ingress state. Never apply through the owner migration chain.
CREATE TABLE messaging_resource_policy (
  id INTEGER PRIMARY KEY CHECK(id=1),
  source_per_minute INTEGER NOT NULL CHECK(source_per_minute BETWEEN 1 AND 10000),
  deployment_per_minute INTEGER NOT NULL CHECK(deployment_per_minute BETWEEN 1 AND 10000)
) STRICT;
INSERT INTO messaging_resource_policy VALUES(1,600,2400);
CREATE TABLE messaging_request_window (
  key_hash TEXT NOT NULL CHECK(length(key_hash)=43),
  window_start INTEGER NOT NULL CHECK(window_start>=0 AND window_start%60=0),
  attempts INTEGER NOT NULL CHECK(attempts BETWEEN 1 AND 10000),
  PRIMARY KEY(key_hash,window_start)
) STRICT;
CREATE INDEX messaging_window_expiry ON messaging_request_window(window_start);
