# Local installation enrollment qualification

Run `npm run test:installation-worker-qualification`. This builds the separate
`installation-qualification` Wasm example and runs it in local Miniflare with a
synthetic SSO authority fixture and D1 initialized with the repository migrations. It exercises the actual Worker owner
lookup, native ES256 verification, and the qualification D1 batch, including
parallel completion, key and nonce mismatches, replay, and revoked SSO. A local
fault adapter also changes SSO, DBSC, account, epoch, credential, client, or redirect
authority immediately before the completion batch; each must reject without
consuming the challenge. A duplicate-key constraint verifies D1 batch rollback. The fixture is not an integration test against a deployed IdP.

This example must not be deployed or routed by the production Worker. It does
not issue tokens or create a usable Android session. Its local schema and API
lack user consent, account/device management, recovery, production rate limits,
replay-ledger cleanup, bounded streaming request reads, and deployment or
physical-device qualification. Its hard-coded native client and callback check
configuration but do not authenticate an app or prove Android Keystore custody.
Production design must address these gaps and transaction-failure semantics
before adding a migration or route.

The shared `mikaki_identity::installation_proof` module constructs the two
qualification DPoP proofs using a native signer and checks the returned DER
signature against the public key before encoding it. The Android-only adapter
uses the separate device-session Keystore key; it is not yet invoked by an app
flow. `cargo test --locked -p mikaki-identity --test installation_proof` checks
interoperability with the IdP verifier using a synthetic host signer. This is
not proof of an Android Keystore-to-Worker transaction.
The Worker qualification also calls a local executable built from that same
proof-construction module for both requests, using a public fixed fixture key.
It checks successful D1 registration and the saved thumbprint, wrong nonce,
and completion replay. The fixed key and synthetic SSO are test inputs; this
still does not exercise the Android bridge, a consent UI, or network transport.
