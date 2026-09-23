# iwato and Mikaki FIDO suite comparison

On 2026-09-23 the persistent native servers were run sequentially on the same Mac under the same FIDO Conformance Tools 1.9.2 GUI process: `http://localhost:8080`, all Server Tests, optional cases and AUTOSCROLL off, memory DB. Each server started from fresh state for each run.

| Implementation | Mandatory cases per run | Run 1 | Run 2 | Median |
| --- | ---: | ---: | ---: | ---: |
| iwato | 155/155 | 5.85 s | 4.92 s | 5.385 s |
| Mikaki | 155/155 | 3.25 s | 3.32 s | 3.285 s |

Mikaki's median total was shorter in these two runs, but suite time includes test-data generation, HTTP, internal GUI work, and OS scheduling; it is not verifier speed. DB/ceremony design and metadata initialization also differ. Mikaki used release `conformance_server` with `FIDO_DB=memory` but still performed Rust verification and SQLite operations. Each suite made 320 HTTP requests; a separate HEAD reachability check in one log was excluded from timing. iwato used `bash scripts/run-conformance.sh` with its `:memory:` setting. The second Mikaki run recorded 83.288 ms total handler work, 47.842 ms Rust verification, 14.656 ms SQLite, and 1.364 ms handler p95 across positive and negative cases. Equivalent iwato internal timings were unavailable.

## Same-fixture verification core

Separately, one offline-exported none/ES256 registration and one ES256 assertion were passed directly into each library's verifier. Both accepted them, and registration returned a COSE key byte-equal to the fixture credential. Challenges, configuration, and saved credential setup were outside timing. Each call included an owned response-buffer clone, but excluded HTTP, wire JSON, DB, and challenge issuance/consumption.

Both crates were built together in one temporary Cargo harness on the same host with `opt-level=3`, LTO, and one codegen unit, not their differing product release profiles. After ten warmups, 5,000 operations × nine samples were collected twice. Values are the median and full range of 18 samples:

| Verification | iwato | Mikaki | Mikaki / iwato |
| --- | ---: | ---: | ---: |
| None ES256 registration | 1.366 µs (1.229–2.553) | 2.440 µs (2.342–2.637) | 1.79× |
| ES256 assertion | 158.333 µs (156.030–164.184) | 96.853 µs (96.359–100.028) | 0.61× |

Mikaki was slower for this tiny none-registration fixture and about 39% shorter for this assertion fixture. Do not generalize to other attestation, MDS, Wasm, DB/HTTP, or complete product behavior; short registration calls are especially sensitive to scheduling outliers.

An instrumented allocator measured peak **live requested Rust heap during one verification call**, including response clone and temporary allocations, after fixture/context/credential setup. Ten warmups preceded two repeated sets of 5,000 × nine and 500 × nine samples; results matched exactly:

| Verification | iwato | Mikaki |
| --- | ---: | ---: |
| None ES256 registration | 1,159 bytes | 2,094 bytes |
| ES256 assertion | 1,119 bytes | 1,366 bytes |

This excludes preheld data, stack, allocator internals, and resident executable pages. Instrumentation was not used for timing. It cannot predict Worker heap limits or process RSS.

## Native process memory

Each server was launched twice under `/usr/bin/time -l` and passed 155/155 under Tools 1.9.2. iwato used its existing release binary, in-memory DB, bundled suite MDS metadata and registered MDS3 endpoint; Mikaki used release `conformance_server` and `FIDO_DB=memory`.

| Implementation | Maximum RSS median (range) | macOS peak footprint median (range) |
| --- | ---: | ---: |
| iwato | 45,867,008 bytes (45,268,992–46,465,024) | 32,236,156 bytes (32,146,032–32,326,280) |
| Mikaki | 18,251,776 bytes (18,219,008–18,284,544) | 16,146,876 bytes (16,105,904–16,187,848) |

In these two runs Mikaki reported roughly 40% of iwato's RSS and 50% of its macOS footprint. These are startup-to-stop OS high-water values, not live Rust heap. Run duration and MDS initialization were not equal, particularly for iwato, so this is a reference measurement rather than a controlled memory ranking. Both servers were stopped afterward.

## Wasm assertion and artifact sizes

Minimal wasm-bindgen harnesses verified the same ES256 assertion under Rust 1.98.1, `opt-level=z`, LTO, one codegen unit, stripped symbols, panic abort, no wasm-opt, and Node 26.9.0. After ten warmups, 1,000 × nine samples were gathered in three runs; values are medians of run medians:

| Verification | iwato | Mikaki | Mikaki / iwato |
| --- | ---: | ---: | ---: |
| ES256 assertion | 805.156 µs (799.679–836.706) | 411.036 µs (410.004–418.760) | 0.51× |

The boundary includes the wasm-bindgen export, verifier, and owned response clone; it excludes fixture JSON parsing/setup and preconstructs the credential. Raw shim Wasm was 363,714 bytes iwato and 373,840 Mikaki. Those are reachable experimental shim/glue artifacts, not product Worker or isolated crate sizes. The difference in time is observed under this fixture/Node runtime only, not an exact universal factor.

Under the same release settings, full product Worker Wasm measured 2,303,854 bytes iwato and 738,618 Mikaki. Their product features and dependency graphs differ, including iwato's D1/Postgres adapters, so this is not a WebAuthn size comparison. Resolved wasm32 normal dependency package counts of 76/63 include packages that may not link.

iwato `verify_registration` calls `SystemTime::now()` to fill `created_at`; in this wasm32/Node run it trapped with “time not implemented on this platform.” Thus there is no paired Wasm none-registration result. Mikaki's core-only shim was about 7.5 µs, but cannot establish a comparative rank. Node results do not directly test Cloudflare.

This completes the scoped WG-08 fixture/core and suite measurement with explicit differences in memory, artifact, initialization, and product responsibility. It is neither formal FIDO certification nor a general product ranking. Reopen measurement for a concrete user latency issue, regression, or hotspot; see the [fit/gap backlog](../../docs/webauthn-fit-gap-todo.md).
