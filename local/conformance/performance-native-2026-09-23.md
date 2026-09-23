# Persistent native Conformance performance

This is the Tools 1.9.1 x86_64 result. The later [Tools 1.9.2 ARM64 rerun](performance-arm64-2026-09-23.md) passed 155/155 with the same file-backed SQLite setup in 5.31 and 3.09 seconds.

On 2026-09-23 the baseline used Apple M3/macOS, Rust 1.98.1, release `opt-level=s`/LTO, all FIDO2 Server Tests, optional cases and AUTOSCROLL off, `http://localhost:8080`. No build or competing load ran during measurement.

| Persistent native store | Mandatory cases | Suite total | Handler total | Rust verification | DB operations | Handler p95/p99 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| File SQLite, WAL/FULL | 155/155 | 40.68 s | 112.784 ms | 45.685 ms | 40.269 ms | 1.661/2.815 ms |
| In-memory SQLite | 155/155 | 40.78 s | 96.651 ms | 47.441 ms | 21.341 ms | 1.309/2.416 ms |

Both runs handled 320 requests: 165 successful options, 24 successful and 80 rejected registrations, 8 successful and 43 rejected assertions. Negative-case HTTP 400 responses are not suite failures. `respond` totals of 15.464/14.861 ms are separately counted. The stopped file DB held 24 users/credentials and passed `integrity_check`.

The improvement examined was a persistent native call into the core, not a skipped or changed cryptographic check. The earlier per-call process adapter totaled 544.764 ms of handler work; the new file-backed path totaled 112.784 ms even with synchronous persistence. HTTP/input details differ, so this is not a controlled effect-size estimate. Moving file DB to memory reduced DB work by about 19 ms but did not shorten suite wall time. Do not bypass the DB based on this result. See [raw summaries and hashes](performance-native-2026-09-23.json).

Workspace tests (22 then), two compile-fail doctests, fmt, Clippy, design checks, changed-JS Prettier, cargo audit, and Wasm-target Worker cargo check passed under the recorded state.

## Adapter boundary

The `conformance_server` example is a persistent Rust HTTP server calling auth/WebAuthn directly. `tiny_http` and `rusqlite` are native-only development dependencies, not product/Wasm dependencies. User and credential records are read from SQLite; registration transactions and counter updates commit before success is returned. A failed write does not produce success, and a duplicate registration rolls back the user insert. A fresh file DB uses WAL/FULL; the memory mode runs the same SQL and validation.

Ceremonies are bounded, expiring, single-use memory transactions consumed before verification. Requests are serialized so counter read-to-commit cannot be interleaved. This local adapter is not a benchmark for product sessions, OIDC, high concurrency, or restart recovery.

Handler `ms` measures receive-to-response-construction wall time, excluding preaccept wait and logging. `response_ms` measures `respond`, not client receipt; `verify_ms` covers Rust verification, `db_ms` SQLite and commit, and `metadata_ms` candidate selection. They include successful and rejected suite requests, so they are not ordinary login percentiles. Older monban/iwato totals under different storage designs were not rerun here and cannot rank implementations.

## Reproduction

Prepare metadata as described in the [adapter guide](README.md), then:

```sh
cargo test --locked --workspace
cargo build --release --locked -p mikaki-browser-wasm --example conformance_server
FIDO_TIMING=1 target/release/examples/conformance_server > target/performance-native-file.log 2>&1
# Stop the server, then start a new process:
FIDO_DB=memory FIDO_TIMING=1 target/release/examples/conformance_server > target/performance-native-memory.log 2>&1
node local/conformance/summarize-timing.mjs target/performance-native-file.log target/performance-native-memory.log
```

Native core verifies MDS signature, CRL, and expiry before listening. Reset the GUI suite and turn AUTOSCROLL off before each run. Do not add the test routes or state to product.
