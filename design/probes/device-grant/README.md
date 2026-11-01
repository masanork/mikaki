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
