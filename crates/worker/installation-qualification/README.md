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

The local `installation_transaction` types retain the original issuer and key
between proof steps, validate the short-lived challenge, require a new proof ID,
and consume the pending state when preparing completion. A completion request is
not a receipt: a lost response requires reconciliation before any future retry.
These types do not perform transport authentication, user approval or delivery.

The local status route reserves a fresh DPoP proof and reads the result in one
D1 batch after rechecking live SSO and matching the pending ID, owner and key.
It reports `pending`, `active`, `revoked`, or `unknown`; a pending or unknown
result is not evidence that an in-flight completion cannot still commit. The
fixture injects a lost completion response after the database batch commits and
then verifies that a same-key status query recovers `active`. It also exercises
wrong-key access, proof replay and authority changes before the status batch.
Status storage retention, lifecycle management and user-facing recovery remain
unimplemented, so this route remains qualification-only.

The native transaction can prepare same-key signed status requests and parse a
bounded status response tied to the original registration ID. The caller must
verify authenticated HTTPS and HTTP status before parsing. The local transaction
holds this recovery state in memory and allows at most 16 status proofs; it is
not durable recovery after process death. Fresh proof IDs are still required.

The shared transaction also exposes a bounded recovery checkpoint. It contains
the registration identity, public key and used proof IDs, but no nonce,
completion proof, token or private key. Restore requires a matching trusted
issuer, authenticated account binding and current signer. The caller must
persist the checkpoint before sending completion, then persist each reserved
status proof ID before transmitting that proof. Reusing an old checkpoint,
concurrent writers or accepting a caller-controlled account binding defeats
these guarantees. No authenticated atomic storage, rollback protection,
process-death integration, account lifecycle or production route is provided
by this codec; the host test checks serialization and authority mismatches only.

An isolated Android `InstallationRecoveryStore` additionally encrypts bounded
checkpoint bytes with a separate Keystore AES-GCM key, uses no-backup storage,
and serializes compare-and-set updates with a process and file lock. It checks
the device key and verifies the written ciphertext before acknowledging. A
missing file with an existing storage key fails closed. A restored older valid
ciphertext remains indistinguishable without an independent rollback witness;
concurrent state across machines and server-side replay or lifecycle policies
are not established by this fixture. A native-only Rust/Kotlin adapter exposes
load and compare-and-set, but no product registration flow invokes it yet.
`scripts/test-android-installation-recovery.sh` takes the fixture APK path and
an explicit emulator serial, then creates, updates and reads the same encrypted
record in three separate instrumentation processes before cleanup. The
`InstallationRecoveryStoreTest` separately checks contention, stale writes,
tampering and the missing-file fence.

The shared persist-before-send helpers release a completion or status proof
only after the storage compare-and-set reports success. Failed or ambiguous
storage results do not release a proof, and an already persisted status JTI
cannot be reused. This helper assumes an authenticated account binding and a
rollback-protected storage implementation; neither is supplied by the adapter.

For optional Android emulator coverage, build the separate test package with
`ANDROID_HOME=... JAVA_HOME=... scripts/build-android-installation-fixture.sh`,
install its printed APK path on a disposable emulator, then set
`MIKAKI_ANDROID_KEYSTORE_SERIAL` and an absolute `MIKAKI_ANDROID_ADB` when running
`node --test --test-concurrency=1 design/probes/android-device-registry/worker-qualification.test.mjs`
after building the normal host/Worker fixtures. This uses the exact
`DeviceSessionKeyStore.kt` source but a separate instrumentation package. The
test creates an ephemeral key, signs the local start, complete and status
requests, verifies each DER signature on the host, and deletes that key. The
emulator test does not exercise the production app identity, Rust-to-Kotlin IPC,
physical hardware, actual user authentication or a deployed Worker.

The host integration also runs `installation_transaction_probe` as a separate
process: it retains the real native transaction state while the test sends its
proofs to the local Worker. A committed completion response is deliberately
lost, then a fresh status proof obtains and parses `active`; replay is rejected.
The process uses a fixed public fixture key and does not exercise the Android
adapter or authenticate real transport.
