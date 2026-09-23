# FIDO Conformance Tools 1.9.2 ARM64 rerun

On 2026-09-23 the persistent native server with file-backed SQLite was measured again on Apple M3/macOS 27.0. macOS sampling confirmed the newer suite Renderer was ARM64; profiling ended before measurement. No build or development tools ran during the measured suite.

| Condition | Mandatory cases | Suite total | Handler total | Rust verification | SQLite operations |
| --- | ---: | ---: | ---: | ---: | ---: |
| Tools 1.9.1 x86_64/Rosetta, earlier record | 155/155 | 40.68 s | 112.784 ms | 45.685 ms | 40.269 ms |
| Tools 1.9.2 ARM64, first run | 155/155 | **5.31 s** | 40.388 ms | 13.940 ms | 16.597 ms |
| Tools 1.9.2 ARM64, same suite process rerun | 155/155 | **3.09 s** | 42.374 ms | 14.773 ms | 17.855 ms |

Each run restarted the server with a fresh file SQLite DB; only the suite process persisted into run 2. Signatures, expiry, single-use ceremonies, credential reads, registration/counter updates, and synchronous commit remained enabled. Product core code was unchanged; server changes added sequence and monotonic `received_ms` logging. Each run had 320 HTTP requests: 165 successful options, 24 successful and 80 rejected registrations, and 8 successful and 43 rejected assertions. After run 2, SQLite still held 24 users/credentials and passed `integrity_check`. Handler p95 was 0.583/0.586 ms and p99 0.853/0.981 ms, including negative cases, not normal product login percentiles.

Suite version and execution architecture changed together, so the reduction cannot be attributed to Rosetta alone. Generated input, CPU state, and external MDS communication were not perfectly fixed. This establishes 3–5 second full mandatory passes without removing verification or DB durability, not a speed ranking against older other implementations.

## Unmeasured time and transport

From first handler start to last respond completion, runs took 5,305.234 and 3,085.945 ms, consistent with GUI totals. Gaps between responses and the next handler totaled 5,260.283 and 3,039.343 ms; their largest individual gaps were 2,873.175 and 863.296 ms. These gaps combine suite work, external/local communications, server acceptance, scheduling, and logs; they are not pure network delay.

An independent serial Node client registered with a synthetic ES256 key and repeated a real challenge/signature/counter flow. After five warmups and 100 operations per condition, it timed from request start through response-body receipt, excluding client signing:

| Loopback HTTP mode | Options p95 | Assertion result p95 | Assertion result p99 |
| --- | ---: | ---: | ---: |
| Keep-alive | 0.139 ms | 0.349 ms | 0.377 ms |
| New connection each request | 0.444 ms | 0.611 ms | 0.703 ms |

This ran before the suite update on the same file-backed native server. It does not reproduce Electron's complete transport path, but ordinary loopback HTTP did not produce seconds of delay.

In the second suite run, handler total was about 1.4%, Rust verification about 0.5%, and SQLite work about 0.6% of first-handler-to-last-response time, with overlapping measurement scopes. Removing crypto checks or durable commits to optimize suite wall time is unsupported. Investigate product latency or a reproducible handler hotspot before tuning. A separately profiled old-Renderer diagnostic run passed 155/155 in 64.77 s but is excluded from speed comparison because profiling and unresolved Rosetta stacks affected it.

## Reproduction

[Machine-readable data](performance-arm64-2026-09-23.json) records both runs, request outcomes and gaps, transport checks, and source/binary SHA-256. Conditions: all FIDO2 Server Tests, optional and AUTOSCROLL off, `http://localhost:8080`, Rust 1.98.1 release `opt-level=s`/LTO, SQLite WAL/`synchronous=FULL`. Re-extract Tools 1.9.2 metadata and fetch official MDS BLOB/CRL before starting the server.

```sh
python3.14 local/conformance/extract-metadata.py
node local/conformance/prepare.mjs
cargo build --release --locked -p mikaki-browser-wasm --example conformance_server
FIDO_TIMING=1 target/release/examples/conformance_server > target/performance-native-profile.log 2>&1
# Run and stop the suite; retain separate logs for each run.
node local/conformance/summarize-timing.mjs target/performance-native-1.9.2-run1.log target/performance-native-1.9.2-run2.log
# Run separately while the server is up:
node local/conformance/transport-benchmark.mjs
```

Formatting, Clippy, and changed-JS Prettier checks passed, as did every independent HTTP response. Both suite runs ended with the test server stopped.
