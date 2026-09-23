-- Initial product D1 schema slice for private_key_jwt client authentication.
-- This does not create OIDC sessions, authorization codes, or token tables.
CREATE TABLE client (
  client_id TEXT PRIMARY KEY NOT NULL CHECK(length(client_id) BETWEEN 1 AND 128),
  revision INTEGER NOT NULL CHECK(revision >= 0),
  active INTEGER NOT NULL CHECK(active IN (0, 1))
) STRICT;

CREATE TABLE client_key (
  client_id TEXT NOT NULL REFERENCES client(client_id),
  kid TEXT NOT NULL CHECK(length(kid) BETWEEN 1 AND 128),
  revision INTEGER NOT NULL CHECK(revision >= 0),
  active INTEGER NOT NULL CHECK(active IN (0, 1)),
  algorithm TEXT NOT NULL CHECK(algorithm = 'ES256'),
  public_key_sec1 BLOB NOT NULL
    CHECK(typeof(public_key_sec1) = 'blob' AND length(public_key_sec1) IN (33, 65)),
  PRIMARY KEY(client_id, kid)
) STRICT;

CREATE TABLE assertion_use (
  client_id TEXT NOT NULL REFERENCES client(client_id),
  jti TEXT NOT NULL CHECK(length(jti) BETWEEN 1 AND 256),
  endpoint TEXT NOT NULL CHECK(length(endpoint) BETWEEN 1 AND 2048),
  accepted_by TEXT NOT NULL UNIQUE,
  retain_until INTEGER NOT NULL CHECK(retain_until > 0),
  PRIMARY KEY(client_id, jti)
) STRICT;
CREATE INDEX assertion_gc ON assertion_use(retain_until);

-- A failed guard violates CHECK and makes the entire D1 batch roll back.
CREATE TABLE atomic_guard (
  operation_id TEXT PRIMARY KEY,
  passed INTEGER NOT NULL CHECK(passed = 1)
) STRICT;
