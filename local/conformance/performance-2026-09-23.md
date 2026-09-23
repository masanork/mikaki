# WebAuthn performance investigation — 2026-09-23

The suite's wall time was not dominated by verification CPU inside the server. This investigation removed duplicate metadata parsing in the adapter and aligned native comparison with a release build. It did not skip signature checks, expiry/revocation checks, one-time ceremony consumption, or credential updates.

## Conditions and core measurements

The earlier native adapter launched a debug Rust process for every verification; it did not represent a persistent native product server. The adapter already used memory storage, so no DB was removed in this change. Wasm used the existing size-optimized release bundle. Historical iwato runs of 14.82, 33.02, and 40.03 seconds over the same 155 cases and differing adapter storage paths also caution against treating total suite time as verifier speed. Monban and iwato were not rerun for this initial investigation.

On Apple M3, Node 26.9.0, Rust 1.98.1, the same public fixture was verified each time with result checks. After five warmups, the table shows the median of seven batch means: 20 operations/batch in native debug and 100 in release/Wasm, measured sequentially after builds.

| Operation | Native debug | Native release | Wasm/JSON boundary |
| --- | ---: | ---: | ---: |
| None/ES256 registration | 28.94 µs | 2.65 µs | 8.86 µs |
| ES256 assertion | 2,327.29 µs | 139.24 µs | 416.43 µs |
| Packed certificate chain | 11,247.35 µs | 780.16 µs | 2,740.33 µs |
| U2F | 8,806.81 µs | 633.44 µs | 2,278.55 µs |
| TPM RSA | 9,568.12 µs | 707.26 µs | 2,528.59 µs |

Native includes an owned response copy but excludes JSON, HTTP, and DB. Wasm includes the existing Worker JSON parsing, ceremony verification, result serialization, and JS call. These are different boundaries. The release profile still used `opt-level="s"` and LTO, not a speed-optimized `opt-level=3`. Fixture chains and keys differ from official-suite input; multiplying fixture times by suite case count would be invalid.

After an MDS result-type change, a 09:00 JST rerun recorded native release medians 2.63, 138.65, 781.03, 635.65, 708.00 µs and Wasm/JSON medians 9.43, 417.09, 2,721.66, 2,299.89, 2,539.87 µs in the same row order. [Machine-readable core data](performance-core-2026-09-23.json) includes four metadata lookups over 25 entries, versus 125 previously; lookup times are not directly comparable. At that point the whole Worker Wasm was 644,011 bytes and the native conformance server 2,604,224 bytes. Neither is the isolated WebAuthn core size.

Per-operation process startup distorted native measurements: an ES256 assertion rose from 139.24 µs in release core to 1,791.37 µs through JSON/stdin/stdout plus child process; none registration rose from 2.65 to 1,647.61 µs. A persistent native HTTP server addresses that test-only cost; see [follow-up](performance-native-2026-09-23.md).

## Change and official-suite rerun

The metadata filter had reparsed the same attestation CBOR/certificate for each of 125 entries. Parsing once before filtering retained the same selection, while the core still authenticated AAGUID or certificate key identifier against trusted metadata.

| Lookup | Before | After |
| --- | ---: | ---: |
| Packed | 592.79 µs | 6.43 µs |
| U2F | 1,035.01 µs | 9.20 µs |
| TPM | 1,122.27 µs | 10.19 µs |
| None | 170.18 µs | 2.46 µs |

The native adapter also switched its reference to the release example and added `FIDO_TIMING=1` metadata, verification, and HTTP timings without logging identifiers or response bodies.

| Target | Suite pass/fail | Total | HTTP handler total, 320 requests | Verification calls | Metadata lookup |
| --- | --- | ---: | ---: | ---: | ---: |
| Wasm | 155/0 | 46.66 s | 157.452 ms | 68.457 ms | 4.489 ms |
| Native release with per-call process | 155/0 | 48.20 s | 544.764 ms | 448.250 ms | 9.674 ms |

Handler p95 was 1.834 ms Wasm and 5.003 ms native, across success and negative cases; it is not product login p95. The native verification call includes process startup and JSON transport. Handler time ends when a response is queued, excluding completed send and GUI time. MDS validation happened at startup. The previous totals of 47.49 s native debug and 48.35 s Wasm were not demonstrably improved; the evidence supports reduced duplicate work and preserved 155/155, not a shorter full suite. [Raw measurements and hashes](performance-2026-09-23.json) retain batch distributions and route percentiles.

## Product interpretation and reproduction

Conformance tests protocol behavior and fixture timings isolate CPU work, but a DB-free suite duration is not product latency. Measure a future D1 path through challenge consumption, credential read, signature verification, counter update, session issuance, and commit with p50/p95/p99, CPU, cold/warm, concurrency, and failure consistency. This investigation did not decompose a DB-backed product path and does not identify D1 as a bottleneck. A cache of parsed certificate keys would also need metadata-revision, expiry, and revocation correctness before adoption.

```sh
cargo build --locked --workspace --examples
cargo build --release --locked --workspace --examples
node local/conformance/benchmark.mjs
FIDO_TIMING=1 node local/conformance/server.mjs > target/performance-wasm.log 2>&1
# Stop that server before a separate full-suite run:
FIDO_TARGET=native FIDO_TIMING=1 node local/conformance/server.mjs > target/performance-native.log 2>&1
node local/conformance/summarize-timing.mjs target/performance-wasm.log target/performance-native.log
```

The GUI run used Tools 1.9.1, all Server Tests, optional cases and AUTOSCROLL off, `localhost:8080`. Restart the server and validate MDS before each run. Do not run builds or other load tests concurrently. Ordinary CI has no speed threshold for this manual measurement.
