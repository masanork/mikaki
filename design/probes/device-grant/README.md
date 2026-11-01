# Device grant storage experiment

Run `node --test design/probes/device-grant/store.test.mjs` with the pinned
Node version. This host-only SQLite experiment tests one conditional update
against two independent concurrent connections. It is not a D1 test, schema
migration, authenticated endpoint, proof validator or token issuer. Its
literal identifiers and key values are test fixtures, not credentials.
It also checks that an injected token-record insert failure rolls back the
grant update when both statements are inside one host SQLite transaction.

The update atomically transitions one approved, unexpired grant bound to the
client and a previously verified key. A missed response after this operation
leaves the grant redeemed: the first deployment must fail closed and restart
authorization unless a separately reviewed recovery protocol is provided.
Issuing a token in a later operation is not atomic with consuming the grant;
the actual store must couple issuance to consumption or explicitly handle
this failure. The implementation must also bound polling, protect code lookup,
enforce consent and mitigate cross-device phishing. A valid DPoP proof alone
does not authenticate a person or prove proximity.

Before any route or discovery is enabled, implement and test the actual D1
transaction and simultaneous Workers, unknown outcomes, replay store, grant
expiry, revocation and the account-authorized consent boundary. See
[issue #325](https://github.com/masanork/mikaki/issues/325).

`node --test design/probes/device-grant/d1-worker.test.mjs` additionally runs
two workerd Workers with the same **local Miniflare D1** database. The fixture
tests a candidate batch containing an update and a conditional token-record
insert and a unique replay reservation, including races, a reused proof ID and
an injected uniqueness failure. The proof key and ID are synthetic strings;
the Worker fixture does not validate a DPoP signature. It does not use a
deployed D1 service, real tokens, user approval, DPoP verification or a public
endpoint. It is a database experiment, not a ready authentication design.

The local `rate-worker.test.mjs` adds a global fixed-window guessing budget and
uses Web Crypto HMAC with the same synthetic test vector as the Rust code. Two
Workers share the local D1 counter; malformed and expired codes still consume
the budget, and a lookup failure rolls its update back. It returns a match
signal only for testing, with an injected clock and test key. This fixed-window
probe is not an acceptable standalone production limiter: a boundary permits
two windows' worth of attempts, a global limit can deny legitimate users, and
old buckets require bounded cleanup. Production needs a risk-based layered
policy for aggregate and individual sources/accounts, trusted server time,
safe throttled/error UX, response timing and enumeration review, HMAC-key
custody/rotation, and tests against actual deployed D1. Never accept a clock or
limiter policy supplied by the client. No claim of user or device authentication
follows from a matching code.

`issuance-worker.test.mjs` probes an initiation batch in local D1: a unique
proof replay reservation, unique device-code digest, unique user-code HMAC
index and a synthetic audit row commit together. It checks concurrent user-code
collisions, device-code collisions and rollback after a later write failure. It
supplies already-derived synthetic indexes and proof IDs; it does not verify
signatures, generate or deliver real codes, authenticate a caller, cap pending
grants or expose a production endpoint. An unknown response after commit is
not safe to retry blindly: reconcile only through a separately designed policy
or restart with a fresh request. Production also needs expiry cleanup, bounded
collision retries, and durable replay retention.
