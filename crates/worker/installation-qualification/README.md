# Local installation enrollment qualification

Run `npm run test:installation-worker-qualification`. This builds the separate
`installation-qualification` Wasm example and runs it in local Miniflare with a
synthetic SSO authority fixture and D1. It exercises the actual Worker owner
lookup, native ES256 verification, and the qualification D1 batch, including
parallel completion, key and nonce mismatches, replay, and revoked SSO. The
fixture uses only the columns needed by these queries; it is not a migration or
an integration test against a deployed IdP.

This example must not be deployed or routed by the production Worker. It does
not issue tokens or create a usable Android session. Its local schema and API
lack user consent, account/device management, recovery, production rate limits,
replay-ledger cleanup, bounded streaming request reads, and deployment or
physical-device qualification. Its hard-coded native client and callback check
configuration but do not authenticate an app or prove Android Keystore custody.
Production design must address these gaps and transaction-failure semantics
before adding a migration or route.
