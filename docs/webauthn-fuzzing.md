# WebAuthn parser fuzzing

**WG-05, 2026-09-23.** The isolated [fuzz package](../fuzz/Cargo.toml) stays outside the ordinary Cargo workspace so `libfuzzer-sys` is not a product dependency. Each run regenerates corpus seeds from independent [Python cryptography/OpenSSL fixtures](../crates/webauthn/testdata/README.md). The seed step checks registration and MDS expected outcomes and completes a valid signed assertion. Generated corpus files are ignored rather than committed.

| Target | Mutated input | Processing reached |
| --- | --- | --- |
| `registration` | attestationObject and clientDataJSON | JSON/base64url, CBOR, authenticatorData, COSE, packed/U2F/TPM, certificates, metadata lookup, signature |
| `assertion` | clientDataJSON, authenticatorData/extensions, COSE public key, DER signature | Saved-credential binding, flags/counter, key parse, signature |
| `metadata` | MDS JWT/header, CRL bytes, signed BLOB JSON | JWT/X.509, signature, CRL, expiry, entries |

Signature rejection after arbitrary raw mutation is expected. The fuzzers search for panic, hang, and libFuzzer timeout; there is no test-only signature bypass or acceptance route. A valid signed whole-BLOB seed helps reach later payload/entry parsing. Signature-preserving structured mutation and differential tests against a physical authenticator are outside this run; independent regression fixtures and Conformance provide other evidence.

## Reproduce and respond to a crash

```sh
cargo run --manifest-path fuzz/Cargo.toml --locked --bin seed
cargo +nightly-2026-09-21 fuzz run registration -- -max_total_time=120 -max_len=65538 -timeout=10
cargo +nightly-2026-09-21 fuzz run assertion -- -max_total_time=120 -max_len=65538 -timeout=10
cargo +nightly-2026-09-21 fuzz run metadata -- -max_total_time=120 -max_len=131074 -timeout=10
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

These seeds cover signed positive and negative attestation/MDS fixtures, not exhaustive signature-preserving mutation of trust chains. Long fuzzing, real-device compatibility, and external review remain separate tasks.
