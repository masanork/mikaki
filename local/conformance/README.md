# FIDO2 Server Conformance adapter

This is an isolated test adapter. A persistent Rust server is used for native performance measurements, while Node supplies the HTTP entry point for the Wasm bundle; both call the shared Rust auth/WebAuthn core. It is not included in the product authentication entry point. The server listens on local IPv6 loopback only.

```sh
npm run build:wasm
cargo build --release --locked -p mikaki-browser-wasm --example conformance
python3 local/conformance/extract-metadata.py
node local/conformance/prepare.mjs
node local/conformance/server.mjs
# Stop the previous server before measuring native performance:
cargo build --release --locked -p mikaki-browser-wasm --example conformance_server
FIDO_TIMING=1 target/release/examples/conformance_server > target/performance-native-file.log 2>&1
# Add FIDO_DB=memory when comparing with in-memory SQLite.
```

In FIDO Conformance Tools v1.9.2 on macOS, open FIDO2 Server and set the URL to `http://localhost:8080`. Select every Server Test, leave optional algorithms/attestations unselected, and turn AUTOSCROLL off. Do not automatically submit results.

The four test routes were informed by iwato's adapter. Requested attestation, extensions, UV, and resident-key conditions enter options. UV and account/allow-list policy are saved server-side with the ceremony and reused at verification. Unsupported attestation is rejected. Product defaults are unchanged, and these routes are not product routes.

The persistent native server performs strict JSON checks, metadata selection, and signature verification in Rust. It reads credentials/users from SQLite and commits registration or counter updates before responding. Default `FIDO_DB=file` creates `target/fido-native-<random>.sqlite` with WAL and `synchronous=FULL`; `FIDO_DB=memory` uses the same SQL without disk durability. Files remain under `target` after a run. Ceremonies are expiring, single-use in-memory transactions and processing is serialized. Product session issuance and OIDC are absent.

The Wasm adapter runs the existing Worker bundle in Node with in-memory state only. This is not a Cloudflare/workerd/D1 test. The older Node `FIDO_TARGET=native` path starts a Rust process per verification and is retained only for diagnostics, not native performance comparison.

Count reached tests as well as successes: a rejected unsupported format can make a negative case pass, and a registration setup failure can hide later assertion cases. Do not count runs that force `none` and thereby alter suite input. Record configuration, unreachable and unsupported cases, and results together. See the [2026-09-22 run record](results-2026-09-22.md). The current suite profile advertises ES256, Ed25519, RS256, and RS1 and stores COSE keys; it differs from the older fixed-required profile. The later [ARM64 Tools 1.9.2 run](performance-arm64-2026-09-23.md) recorded 155/155 with file-backed native SQLite, 5.31 seconds initially and 3.09 seconds on rerun.

## Metadata and evidence

On 2026-09-22 both native and Wasm passed all 155 mandatory cases. Fourteen optional cases were not selected; formal certification submission is separate.

`extract-metadata.py` copies public metadata from an installed suite into `target/fido-metadata`. `prepare.mjs` registers the localhost RP origin with the official MDS test service and saves BLOB/CRL data under `target/fido-mds`. `FIDO_ASAR` and `FIDO_PORT` select installation and port. These ignored files contain neither suite source nor private keys.

Network fetches are restricted to two official HTTPS hosts, including redirects, size limits, and timeouts. A failed BLOB does not supply trusted roots or metadata. On startup, each target revalidates BLOB/CRL using current time and its Rust verifier, then selects only verified metadata by AAGUID or certificate key identifier. The test-root SPKI is only in `prepare.mjs` and never added to product trust. Re-run preparation when saved material expires or the service changes; do not bypass MDS validity checks. GUI suite and network preparation are outside ordinary CI, which uses independent fixed fixtures.

## Performance measurements

The native suite uses a release binary. `FIDO_TIMING=1` records metadata lookup, Rust verification, SQLite, and handler timings. `ms` runs to response construction; `response_ms` measures the respond call, neither including queue time or completed client receipt. Failure verification/DB time is included. Sequence and monotonic receipt time are logged without identifiers or response bodies. Summarize with `summarize-timing.mjs`; see [native results](performance-native-2026-09-23.md).

Persistent-server regression tests are part of `cargo test --locked --workspace`, covering counter update, replay/expiry/challenge rejection, DB failure, and registration rollback. Separate core/process microbenchmarks can be run after all builds finish:

```sh
cargo build --locked --workspace --examples
cargo build --release --locked --workspace --examples
node local/conformance/benchmark.mjs
```

They re-verify public fixtures and write `artifacts/webauthn-performance.json`, distinguishing native core, Wasm/JSON boundary, process startup, and metadata lookup. They do not include DB, HTTP, or official-suite duration. See the [performance investigation](performance-2026-09-23.md).

## Local OIDC Basic OP suite

Start OIDF Conformance Suite 5.2.4 in Colima at `https://localhost:8443`, then start the isolated fixture in another terminal. Certificates, test passkey, client secrets, and detailed logs remain ignored under `local/generated/`.

```sh
npm run build:policy
worker-build --release crates/worker
openssl req -x509 -nodes -newkey rsa:2048 -days 1 -keyout local/generated/oidf-local.key -out local/generated/oidf-local.crt -subj '/CN=host.docker.internal'
node local/conformance/oidf-local-worker.mjs
```

The fixture creates isolated D1 and prechecks passkey login with a single-use transaction. Run the Chromium virtual-authenticator driver separately:

```sh
node local/conformance/run-passkey-oidf.mjs all 1
node local/conformance/run-passkey-oidf.mjs oidcc-discovery-endpoint-verification 1 oidcc-config-certification-test-plan
```

The `1` is the signature counter after fixture precheck. Modules share one virtual authenticator and carry its counter forward. The driver uploads screenshots required for `REVIEW` and saves summary/logs as `local/generated/oidf-passkey-*.json`. This local test is distinct from formal certification at a public issuer; see [OIDC conformance status](../../docs/oidc-core-conformance.md).
