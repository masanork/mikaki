-- One messaging device per owner in the limited beta. A missing local profile
-- never creates another device. Existing multi-device data fails this migration.
CREATE UNIQUE INDEX messaging_beta_one_device ON messaging_device_head(account_id);
CREATE TABLE messaging_beta_schema (id INTEGER PRIMARY KEY CHECK(id=1),version INTEGER NOT NULL CHECK(version=1)) STRICT;
INSERT INTO messaging_beta_schema VALUES(1,1);
