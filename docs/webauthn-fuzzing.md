# WebAuthn parser fuzzing

**WG-05, 2026-09-23.** The isolated [fuzz package](../fuzz/Cargo.toml) stays outside the ordinary Cargo workspace so `libfuzzer-sys` is not a product dependency. Each run regenerates corpus seeds from independent [Python cryptography/OpenSSL fixtures](../crates/webauthn/testdata/README.md). The seed step checks registration and MDS expected outcomes and completes a valid signed assertion. Generated corpus files are ignored rather than committed.

| Target | Mutated input | Processing reached |
| --- | --- | --- |
| `registration` | attestationObject and clientDataJSON | JSON/base64url, CBOR, authenticatorData, COSE, packed/U2F/TPM, certificates, metadata lookup, signature |
| `assertion` | clientDataJSON, authenticatorData/extensions, COSE public key, DER signature | Saved-credential binding, flags/counter, key parse, signature |
| `metadata` | MDS JWT/header, CRL bytes, signed BLOB JSON | JWT/X.509, signature, CRL, expiry, entries |
| `android` | Android Key extension DER and client-data hash | KeyDescription, bounded tagged AuthorizationLists, challenge/purpose/origin/allApplications |

Signature rejection after arbitrary raw mutation is expected. The fuzzers search for panic, hang, and libFuzzer timeout; there is no test-only signature bypass or acceptance route. A valid signed whole-BLOB seed helps reach later payload/entry parsing. Signature-preserving structured mutation and differential tests against a physical authenticator are outside this run; independent regression fixtures and Conformance provide other evidence.

## Reproduce and respond to a crash

```sh
cargo run --manifest-path fuzz/Cargo.toml --locked --bin seed
cargo +nightly-2026-09-21 fuzz run registration -- -max_total_time=120 -max_len=65538 -timeout=10
cargo +nightly-2026-09-21 fuzz run assertion -- -max_total_time=120 -max_len=65538 -timeout=10
cargo +nightly-2026-09-21 fuzz run metadata -- -max_total_time=120 -max_len=131074 -timeout=10
cargo +nightly-2026-09-21 fuzz run android -- -max_total_time=120 -max_len=16416 -timeout=10
```

The [workflow](../.github/workflows/webauthn-fuzz.yml) runs weekly with 30 minutes per target. Manual dispatch accepts a strict decimal duration of 1..1800 seconds; a shorter run is a smoke test. Four isolated jobs can run concurrently, each with a 55-minute job ceiling. Each process requests AddressSanitizer, a ten-second input timeout, the target's fixed maximum input length, and a 1024 MiB RSS limit. The driver gives the process group the requested exploration interval plus 120 seconds, then kills Cargo and its descendants if necessary. Builds and independent seed replay happen before this interval. Runs queue instead of automatically cancelling an active campaign.

The [driver](../scripts/run-webauthn-fuzz.ts) records the exact source commit, source cleanliness, fuzz lockfile hash, pinned cargo-fuzz version/binary hash, compiler identity, requested limits, elapsed time, executed units, throughput, new units and peak RSS. CI requires clean source; commit, tree and lockfile changes during execution fail qualification. Fuzz execution is offline after the explicit build, with absolute Cargo/Git selection and a small child environment that omits inherited credentials and compiler wrappers.

Every invocation has a separate execution ID, log, working corpus, input/output hash manifests, findings directory and JSON report under `artifacts/webauthn-fuzz/<target>/`. Only flat regular input files are accepted, with target-specific size limits, at most 20,000 entries and 64 MiB total. A run copies and hashes the same seed bytes before mutation; it never mutates the original seed directory. Successful and failed evidence is retained for 14 days. The report starts as incomplete and replaces any prior passing summary. A zero exit alone is insufficient: missing/duplicate/inconsistent statistics, incomplete elapsed budget, interruption, resource failure, sanitizer findings or a finding artifact cannot pass.

The separate `harness_canary` target intentionally panics on one inert marker. A prerequisite job runs it through the actual driver and requires its nonzero fuzzer exit, expected marker and libFuzzer failure diagnostic. Its report remains failed with qualification `harness-canary-only`; the successful self-test means the detector observed the expected failure, not a product finding. Unit tests also exercise process-group termination, malformed reports, unsafe corpus entries, executable-home validation and stale passing evidence.

To run the managed campaign locally after installing the pinned toolchain and cargo-fuzz into `target/fuzz-tools`:

```sh
cargo +nightly-2026-09-21 run --manifest-path fuzz/Cargo.toml --locked --bin seed
export PATH="$PWD/target/fuzz-tools/bin:$PATH"
cargo +nightly-2026-09-21 fuzz build registration --sanitizer address
node scripts/run-webauthn-fuzz.ts registration 1800
cargo +nightly-2026-09-21 fuzz build harness_canary --sanitizer address
node scripts/run-webauthn-fuzz.ts self-test
```

Previous corpus artifacts are retained for reviewed manual reuse, not automatically restored from a cache or arbitrary archive. Check the producing revision, target, tool versions and manifest hashes, review the data, then copy selected regular files into `fuzz/corpus/<target>/` before a new managed run. The new report records every byte actually used. Do not import real credentials, private keys, card data or production records. This iteration does not add automatic corpus merging, stateful/property oracles or native/Wasm crash replay.

A clean run means only that no panic/timeout or configured sanitizer failure was found for that revision and exploration interval. It is not measured source coverage, cryptographic correctness, physical-device qualification or a security proof. See the [Rust Fuzz Book](https://rust-fuzz.github.io/book/cargo-fuzz/guide.html) and [libFuzzer options](https://llvm.org/docs/LibFuzzer.html#options) for the underlying tool behavior.

For a crash, retain and minimize the artifact using `cargo +nightly-2026-09-21 fuzz tmin <target> <input>`. Determine the intended acceptance/rejection, add the minimized input to shared native/Wasm regression tests, then close the artifact. A mutated signed fixture rejected because its signature broke is not itself a bug.

## Recorded local runs

On macOS arm64 with nightly Rust 1.100.0, cargo-fuzz 0.13.2, and libfuzzer-sys 0.4.13:

| Target | Time | Executions | Seeds | Result |
| --- | ---: | ---: | ---: | --- |
| Registration | 25 s | 268,184 | 42 | No crash/timeout |
| Assertion | 25 s | 363,762 | 4 | No crash/timeout |
| Metadata | 25 s | 259,561 | 43 | No crash/timeout |

The first AddressSanitizer-enabled build/run peaked at up to 560 MiB among three parallel targets. A symbolizer startup warning prevented symbolic panic stacks, but exit and fuzzer statistics were normal. UBSan was not claimed. A second default AddressSanitizer run of ten seconds each reached registration 88,391/42 seeds/476 MiB, assertion 111,850/4/511 MiB, metadata 89,231/43/440 MiB, with no crash, timeout, or sanitizer report. Durations and memory are separate measurements, not one combined run.

### Expanded algorithm and Android runs, 2026-09-28/29

Registration/assertion seeds include independent PS256/384/512, RS384/512, ES384/512/256K and Android Key fixtures. Metadata includes ES256/RS256 operation fixtures and algorithm/key mismatch. The feature-gated Android parser hook is excluded from ordinary product builds; it returns parser acceptance, not trusted evidence. Full signed Android registration paths are covered by regression fixtures. Weekly CI now runs four targets.

The seed generator replays expected registration/assertion/MDS outcomes. Current generated seeds: registration 186 (93 cases), assertion 80 (20 cases), Android DER 25, metadata 131 (29 cases). These counts exclude retained fuzzer-generated corpus inputs.

| Target | Time | Executions | Peak RSS | Result |
| --- | ---: | ---: | ---: | --- |
| Android DER | 121 s | 2,856,487 | 410 MiB | No crash/timeout/sanitizer finding |
| Registration | 181 s | 726,139 | 453 MiB | No crash/timeout/sanitizer finding |
| Assertion | 181 s | 652,399 | 463 MiB | No crash/timeout/sanitizer finding |
| Metadata, original MDS corpus | 181 s | 856,143 | 455 MiB | No crash/timeout/sanitizer finding |
| Metadata, added RSA operation corpus | 121 s | 960,968 | 446 MiB | No crash/timeout/sanitizer finding |

These are bounded exploration runs, not exhaustive signature-preserving mutation of trust chains. Logs are retained under ignored `target/fuzz-*-2026-09-*.log`. Real-device compatibility and external review remain separate evidence.
