# FIDO2 Server Conformance adapter

This is an isolated test adapter. A persistent Rust server is used for native performance measurements, while Node supplies the HTTP entry point for the Wasm bundle; both call the shared Rust auth/WebAuthn core. It is not included in the product authentication entry point. The server listens on local IPv6 loopback only.

```sh
npm run build:wasm
cargo build --release --locked -p mikaki-browser-wasm --example conformance
node local/conformance/extract-metadata.ts
node local/conformance/prepare.ts
node local/conformance/server.ts
# Stop the previous server before measuring native performance:
cargo build --release --locked -p mikaki-browser-wasm --example conformance_server
FIDO_TIMING=1 target/release/examples/conformance_server > target/performance-native-file.log 2>&1
# Add FIDO_DB=memory when comparing with in-memory SQLite.
```

In FIDO Conformance Tools v1.9.2 on macOS, open FIDO2 Server and set the URL to the selected localhost port. Select every Server Test. The updated adapter supports all optional checkboxes; the 2026-09-28 run used port 8082 and passed 167 cases with every checkbox enabled. The suite's secp256k1 case is still pending IANA in Tools 1.9.2 and does not execute; independent native/Wasm fixtures cover it. Do not automatically submit results.

The four test routes were informed by iwato's adapter. Requested attestation, extensions, UV, and resident-key conditions enter options. UV and account/allow-list policy are saved server-side with the ceremony and reused at verification. Unsupported attestation is rejected. Product defaults are unchanged, and these routes are not product routes.

The persistent native server performs strict JSON checks, metadata selection, and signature verification in Rust. It reads credentials/users from SQLite and commits registration or counter updates before responding. Default `FIDO_DB=file` creates `target/fido-native-<random>.sqlite` with WAL and `synchronous=FULL`; `FIDO_DB=memory` uses the same SQL without disk durability. Files remain under `target` after a run. Ceremonies are expiring, single-use in-memory transactions and processing is serialized. Product session issuance and OIDC are absent.

The Wasm adapter runs the existing Worker bundle in Node with in-memory state only. This is not a Cloudflare/workerd/D1 test. The older Node `FIDO_TARGET=native` path starts a Rust process per verification and is retained only for diagnostics, not native performance comparison.

Count reached tests as well as successes: a rejected unsupported format can make a negative case pass, and a registration setup failure can hide later assertion cases. Do not count runs that force `none` and thereby alter suite input. Record configuration, unreachable and unsupported cases, and results together. See the [2026-09-22 run record](results-2026-09-22.md). The suite profile now advertises ES256, Ed25519, RS256, RS1, PS256/384/512, RS384/512, ES384/512, and ES256K, and stores COSE keys. The historical [ARM64 Tools 1.9.2 run](performance-arm64-2026-09-23.md) recorded 155/155 with file-backed native SQLite, 5.31 seconds initially and 3.09 seconds on rerun.

The native adapter bounds users and credentials to 1,000 each. Repeated runs eventually reach this limit and reject new registrations. Restart the server to create a fresh disposable SQLite file; the GUI RESET button clears only tool results. Previous files remain available under `target`.

## Metadata and evidence

On 2026-09-22 both native and Wasm passed all 155 mandatory cases. Fourteen optional cases were not selected; formal certification submission is separate.

`extract-metadata.ts` copies public metadata from an installed suite into `target/fido-metadata`. `prepare.ts` registers the localhost RP origin with the official MDS test service and saves BLOB/CRL data under `target/fido-mds`. `FIDO_ASAR` and `FIDO_PORT` select installation and port. These ignored files contain neither suite source nor private keys.

Network fetches are restricted to two official HTTPS hosts, including redirects, size limits, and timeouts. A failed BLOB does not supply trusted roots or metadata. On startup, each target revalidates BLOB/CRL using current time and its Rust verifier, then selects only verified metadata by AAGUID or certificate key identifier. The test-root SPKI is only in `prepare.ts` and never added to product trust. Re-run preparation when saved material expires or the service changes; do not bypass MDS validity checks. GUI suite and network preparation are outside ordinary CI, which uses independent fixed fixtures.

## MDS version profiles

The default `FIDO_MDS_PROFILE=mds3.1.1` requires a signed JWT header `iat`, as specified by MDS 3.1.1. There is no automatic downgrade based on BLOB content or its cached profile. Both native and Wasm servers select the profile from their own startup configuration and refuse to start without at least one verified MDS BLOB.

As checked on 2026-09-28, the official test service returned BLOBs without `iat`. The [official changelog](https://fidoalliance.org/mds-changelog/) announces MDS 3.1.1 service updates on May 26, 2026, but does not document a separate 3.1.1 conformance endpoint. The [server testing guide](https://github.com/fido-alliance/conformance-test-tools-resources/blob/main/docs/FIDO2/Server/README.md) still directs users to the MDS3 test service. The production BLOB linked from the [MDS overview](https://fidoalliance.org/metadata/) also lacked `iat` on this check; it is not a substitute for suite-specific metadata.

Use the explicit MDS 3.0 compatibility profile for this suite:

```sh
npm run build:wasm
cargo build --release --locked -p mikaki-browser-wasm --example conformance_server
FIDO_PORT=8082 FIDO_MDS_PROFILE=mds3.0 node local/conformance/prepare.ts
FIDO_PORT=8082 FIDO_MDS_PROFILE=mds3.0 FIDO_DB=file FIDO_TIMING=1 target/release/examples/conformance_server
# Alternatively, after stopping the native server:
FIDO_PORT=8082 FIDO_MDS_PROFILE=mds3.0 node local/conformance/server.ts
```

This profile allows an absent `iat` and returns `issued_at: null` rather than inventing a timestamp. If `iat` is present, it must still be an unsigned integer. Signature, pinned-root chain, certificate validity, CRL signature/validity/revocation, BLOB number, and authenticator status checks remain active. Legacy BLOBs must include a signed `nextUpdate`; this adapter conservatively rejects them after that date's UTC midnight. The default 3.1.1 profile retains its existing handling of optional `nextUpdate`.

Compatibility runs must be recorded as MDS 3.0 runs, not as evidence of MDS 3.1.1 conformance. The [2026-09-28 compatibility run](results-2026-09-28.md) passed 155/155 mandatory cases against the native SQLite server. The initial startup attempt on 2026-09-28 on port 8081 used the strict profile and rejected all five BLOBs before CRL discovery. The port-8081 positive BLOB also had a malformed 63-byte ES256 signature (the required length is 64); it remained rejected, without padding or re-signing. A new port-8082 registration supplied a valid BLOB with 100 WebAuthn entries. Its former `CRL transport rejected` diagnostic conflated header parsing and download failures; preparation now reports the discovery/download and verifier errors separately.

## Performance measurements

The native suite uses a release binary. `FIDO_TIMING=1` records metadata lookup, Rust verification, SQLite, and handler timings. `ms` runs to response construction; `response_ms` measures the respond call, neither including queue time or completed client receipt. Failure verification/DB time is included. Sequence and monotonic receipt time are logged without identifiers or response bodies. Summarize with `summarize-timing.ts`; see [native results](performance-native-2026-09-23.md).

Persistent-server regression tests are part of `cargo test --locked --workspace`, covering counter update, replay/expiry/challenge rejection, DB failure, and registration rollback. Separate core/process microbenchmarks can be run after all builds finish:

```sh
cargo build --locked --workspace --examples
cargo build --release --locked --workspace --examples
node local/conformance/benchmark.ts
```

They re-verify public fixtures and write `artifacts/webauthn-performance.json`, distinguishing native core, Wasm/JSON boundary, process startup, and metadata lookup. They do not include DB, HTTP, or official-suite duration. See the [performance investigation](performance-2026-09-23.md).

## Local OIDC Basic OP suite

Start OIDF Conformance Suite in Colima at `https://localhost:8443`, then start the isolated fixture in another terminal. Certificates, test passkey, client secrets, and detailed logs remain ignored under `local/generated/`.

```sh
npm run build:policy
worker-build --release crates/worker
openssl req -x509 -nodes -newkey rsa:2048 -days 1 -keyout local/generated/oidf-local.key -out local/generated/oidf-local.crt -subj '/CN=host.docker.internal'
node local/conformance/oidf-local-worker.ts
```

The fixture creates isolated D1 and prechecks passkey login with a single-use transaction. Run the Chromium virtual-authenticator driver separately:

```sh
node local/conformance/run-passkey-oidf.ts all 1
node local/conformance/run-passkey-oidf.ts oidcc-discovery-endpoint-verification 1 oidcc-config-certification-test-plan
node local/conformance/run-passkey-oidf.ts all 1 oidcc-rp-initiated-logout-certification-test-plan
node local/conformance/run-passkey-oidf.ts all 1 oidcc-backchannel-rp-initiated-logout-certification-test-plan
```

The `1` is the signature counter after fixture precheck; increase it for subsequent runs against the same fixture. Modules share one virtual authenticator and carry its counter forward. The driver uploads screenshots required for `REVIEW` and saves summary/logs as `local/generated/oidf-passkey-*.json`. This local test is distinct from formal certification at a public issuer; see [OIDC conformance status](../../docs/oidc-core-conformance.md) and [logout run record](../../docs/oidc-logout-conformance.md).

For the FAPI 2.0 Final AS profile, start the fixture with `MIKAKI_OIDF_PROFILE=fapi2` and run `node local/conformance/run-passkey-oidf.ts fapi2-security-profile-final-happy-flow 1 fapi2-security-profile-final-test-plan`. This fixture prechecks PAR discovery but does not consume a passkey signature, so a fresh fixture starts at counter `1`. It registers two disposable ES256 `private_key_jwt` clients and constrains the local TLS relay's TLS 1.2 ciphers. [The 2026-09-30 run](../../docs/fapi2-conformance-2026-09-30.md) records the full plan and its manual REVIEW outcomes. The driver waits long enough for the fixture's 300-second PAR expiry and controls the login-denial and pre-authentication-reuse journeys.

The [2026-09-29 current-build run](../../docs/oidf-conformance-2026-09-29.md) also records Config OP, all Basic OP modules and separate OID4VCI metadata / OID4VP component HTTPS adapters. The driver captures actual passkey prompts as JPEG within the suite's 500KB limit and returns nonzero for unfinished/failed runs. Review, warning and skipped results do not become automated passes. The credential adapters run serially on port 8793 and use the ignored certificate; include `subjectAltName=DNS:host.docker.internal,DNS:localhost` and renew expired certificates when preparing that fixture.

For the Back-Channel plan, run the fixture on the suite's Docker network so its outbound notification can resolve `suite-frontend`. Install the Linux dependencies in an isolated temporary volume, then start the fixture from the repository root:

```sh
docker run --rm -v "$PWD":/app -v /private/tmp/mikaki-oidf-node-modules:/app/node_modules -w /app node:24-trixie-slim npm ci --ignore-scripts
docker run --rm --network oidf-conformance_suite-net --add-host host.docker.internal:host-gateway -p 8792:8792 -e NODE_TLS_REJECT_UNAUTHORIZED=0 -v "$PWD":/app -v /private/tmp/mikaki-oidf-node-modules:/app/node_modules -w /app node:24-trixie-slim node local/conformance/oidf-local-worker.ts
```

Run the Back-Channel driver command above from the host after the fixture reports that it is listening. The suite's self-signed certificate is issued to `localhost`, not `suite-frontend`, so the Docker fixture disables Node certificate verification for this local process only. Do not use that setting outside the isolated conformance fixture. The `MIKAKI_BACKCHANNEL_TEST_ORIGIN` variable can override the notification receiver origin for another local suite topology. Verify the suite's notification result; an enqueued delivery alone does not prove receipt.

## Managed restart and physical checks (2026-09-29)

```sh
node local/conformance/manage.ts status
node local/conformance/manage.ts start native
node local/conformance/manage.ts restart native
node local/conformance/manage.ts restart wasm
node local/conformance/manage.ts stop
FIDO_PORT=8083 node local/conformance/manage.ts start wasm
```

The manager defaults to port 8082 and explicitly selects the suite compatibility profile `mds3.0`; set `FIDO_MDS_PROFILE=mds3.1.1` for strict startup. It stops only the recorded process with matching PID/start/command identity, sends SIGTERM, and preserves old logs and disposable SQLite files. It refuses to start over a live managed process. Startup checks the API after metadata verification, allowing up to roughly a minute for preparation. A normal GUI RESET does not reset adapter state; restart when repeated runs hit the 1,000-user/credential bound. Rebuild the release examples/Wasm package before restarting after core changes.

Tools 1.9.2's MDS preparation confirmation dialog must be answered promptly: its wait counts toward the 30-second before-hook timeout. A timeout there can leave 161 passes and one hook failure without running the six MDS cases. Answering it immediately allowed all 167 to pass on both adapters; it does not bypass a failed validation.

The Wasm HTTP adapter serves `/device` for operator-controlled physical registration, identified authentication, and separate discoverable authentication. It uses ES256, required UV/resident key, and none attestation. Creation and biometric/PIN entry are performed by the operator. For discoverable authentication choose the current test name; localhost may contain passkeys from other disposable test servers. The downloaded record contains no credential ID/signature. The device server on 8083 is separate from the official conformance server on 8082, so a suite restart need not invalidate the current device test.

[Certification preparation](../../docs/webauthn-certification-readiness.md) records what still requires official records, applicant information and interoperability testing. These development results have not been submitted.
