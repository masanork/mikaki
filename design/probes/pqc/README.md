# Isolated PQC feasibility probe

This crate is excluded from the product workspace. It uses public deterministic fixture seeds to test RustCrypto `ml-kem` 0.3.2 (ML-KEM-768) and `ml-dsa` 0.1.1 (ML-DSA-65) on native Rust and Node Wasm. Deterministic ML-KEM encapsulation uses the crate's `hazmat` feature **only here**. The Node harness compares both implementations with pinned [NIST ACVP sample vectors](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files) for ML-KEM-768 key generation/encapsulation and ML-DSA-65 key generation/deterministic signing. The fixture JSON stores public inputs and hashes of expected outputs. `hpke` 0.14.1 additionally exercises a Vault data-key recipient wrap using ML-KEM-768, HKDF-SHA256, and AES-256-GCM, binding origin, attribute, revision, recipient, and key ID. This is based on an HPKE PQ Internet-Draft and has no production wire format. The probe does not create production keys, a FIDO credential, or an OIDC algorithm.

From the repository root:

```sh
cargo test --locked --manifest-path design/probes/pqc/Cargo.toml
cargo clippy --locked --manifest-path design/probes/pqc/Cargo.toml --all-targets -- -D warnings
wasm-pack build design/probes/pqc --target nodejs --release --out-dir pkg -- --locked
npm ci --prefix design/probes
node design/probes/pqc/check.mjs
cargo audit --file design/probes/pqc/Cargo.lock
npm audit --prefix design/probes --audit-level=low
```

On 2026-09-23 with Rust 1.98.1 and Node 26.9.0, native and Node Wasm round trips, four NIST sample cases through noble, and Rust/Wasm↔noble byte-level interoperability passed. ML-KEM ciphertext mutation changed the decapsulated secret; ML-DSA rejected a changed message. The HPKE exercise opened a 32-byte Vault data key and rejected a changed revision, attribute, key ID, or ciphertext. The probe checked the FIPS parameter sizes: ML-KEM-768 public key 1184 bytes and ciphertext 1088 bytes; ML-DSA-65 public key 1952 bytes and signature 3309 bytes. Optimized probe Wasm was 124,121 bytes raw and 48,436 bytes gzip. Ten combined Wasm runs had a median of about 3.16 ms on this machine. These figures exclude Worker routing, WebAuthn parsing, key management, and network latency.

The NIST sample vectors and noble comparison improve correctness coverage; they are not FIDO interoperability, browser, or production Worker tests. Both RustCrypto crates and noble state that their implementations have not been independently audited. `cargo audit` and `npm audit` check advisories, not cryptographic correctness. The HPKE exercise uses a draft-04 KEM implementation while [draft-05](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-pq-05) is current; its bytes must not be stored as a production envelope. See [PQC rollout](../../../docs/pqc-rollout.md) before considering any product use.

## FIDO device arrival

Run `node design/probes/pqc/fido-eval.mjs` and open `http://localhost:8789/` in the target browser. The isolated page offers an ML-DSA-65-only registration (`COSE -49`) and an ES256 control (`COSE -7`), followed by an assertion. Download the result JSON, then run `node design/probes/pqc/analyze-fido.mjs path/to/result.json`. The analyzer checks origin, challenges, RP ID hash, credential binding, COSE algorithm, and the assertion signature with noble (ML-DSA-65) or Node crypto (ES256). It does not validate attestation chains or certify the device model. Record the dongle model, firmware, OS, and browser version separately. Use a test browser profile and test authenticator credential. `node --test design/probes/pqc/analyze-fido.test.mjs` checks the analyzer with synthetic credentials; real-device behavior remains untested until the dongle arrives.
