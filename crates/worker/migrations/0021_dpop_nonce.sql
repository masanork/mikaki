-- AS and RS nonces have separate authority. Recent values overlap to let
-- concurrent requests finish during rotation; clients can retry on challenge.
CREATE TABLE dpop_nonce (
  scope TEXT NOT NULL CHECK(scope IN ('as', 'rs')),
  nonce TEXT NOT NULL UNIQUE CHECK(length(nonce) = 43),
  challenge_until INTEGER NOT NULL CHECK(challenge_until > 0),
  accept_until INTEGER NOT NULL CHECK(accept_until = challenge_until + 60),
  PRIMARY KEY(scope, nonce)
) STRICT;
CREATE INDEX dpop_nonce_expiry ON dpop_nonce(accept_until);
