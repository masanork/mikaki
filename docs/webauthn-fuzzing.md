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

The [workflow](../.github/workflows/webauthn-fuzz.yml) runs weekly or manually, not daily, with 90 seconds per target. Record duration, executions, peak RSS, target, and seed count. A clean run means only that no panic/timeout was found for that commit and exploration interval; it is not coverage, cryptographic correctness, or a security proof.

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
