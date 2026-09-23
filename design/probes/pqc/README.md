# Isolated PQC feasibility probe

This crate is excluded from the product workspace. It uses public deterministic fixture seeds to test RustCrypto `ml-kem` 0.3.2 (ML-KEM-768) and `ml-dsa` 0.1.1 (ML-DSA-65) on native Rust and Node Wasm. Deterministic ML-KEM encapsulation uses the crate's `hazmat` feature **only here**. The probe does not create production keys, a Vault format, a FIDO credential, or an OIDC algorithm.

From the repository root:

```sh
cargo test --locked --manifest-path design/probes/pqc/Cargo.toml
cargo clippy --locked --manifest-path design/probes/pqc/Cargo.toml --all-targets -- -D warnings
wasm-pack build design/probes/pqc --target nodejs --release --out-dir pkg -- --locked
node design/probes/pqc/check.mjs
cargo audit --file design/probes/pqc/Cargo.lock
```

On 2026-09-23 with Rust 1.98.1 and Node 26.9.0, native and Node Wasm round trips passed. ML-KEM ciphertext mutation changed the decapsulated secret; ML-DSA rejected a changed message. The probe checked the FIPS parameter sizes: ML-KEM-768 public key 1184 bytes and ciphertext 1088 bytes; ML-DSA-65 public key 1952 bytes and signature 3309 bytes. Optimized probe Wasm was 64,724 bytes raw and 26,291 bytes gzip. Ten combined Wasm round trips had a median of about 2.28 ms on this machine. These figures exclude Vault encoding, Worker routing, WebAuthn parsing, key management, and network latency.

The native/Wasm probe is a self-consistency check, not an independent NIST known-answer or FIDO interoperability test. Both RustCrypto crates state that their implementations have not been independently audited. `cargo audit` reported no RustSec advisory for the locked 35-package graph on this date; that is not an audit of the cryptography. See [PQC rollout](../../../docs/pqc-rollout.md) before considering any product use.
