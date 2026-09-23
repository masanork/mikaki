# WebAuthn external security review brief

This brief defines scope and questions for a future independent review. It is **not** a record of an audit or completed review. Add the reviewed revision, reviewer, findings, and disposition after engagement.

## Review scope, in priority order

1. **Ceremonies and credentials:** [core](../crates/webauthn/src/lib.rs) and `key.rs`; binding of challenge, origin, RP ID, UP/UV, credential/user handle, allow list, and counter; replay and subject mix-up rejection.
2. **Attestation and certificate trust:** `attestation.rs`, `attestation/tpm.rs`, and `certificate.rs`; packed/U2F/TPM signed bytes, paths, anchors, expiry, critical extensions, and TPM structure. Check unsupported Web PKI cases fail rather than appearing trusted.
3. **MDS:** `metadata.rs`; BLOB signature and pinned root, CRL signature/time/revocation, entry choice, BLOB-number interpretation, and separation from missing durable snapshot/rollback protection.
4. **Store and lifecycle:** Product transaction boundaries, one-time and expiring challenges, rollback, and multi-instance durability. Distinguish in-memory adapters from product guarantees.
5. **Native/Wasm boundary:** Worker/Wasm JSON size/depth, error/result conversion, and leakage of secrets or attestation material into logs.

Questions include whether attacker-controlled CBOR, DER/X.509, and TPM values can bypass bounds or cause panic/excessive work/ambiguous acceptance; whether client input can change policy, anchor, or owner; whether replay, expiry, or counter rollback can bypass checks; whether incomplete/expired/revoked/mismatched chains or MDS/CRLs can be misreported as trusted; and whether native/Wasm/store side effects differ for the same input. Review the documented unsupported cases and RSA advisory exception.

## Known boundaries and existing evidence

The product default is ES256, required UV, discoverable credentials, and `none` attestation request; verifier capability is broader. HTTP, clock retrieval, DB, and MDS download are supplied by callers, not embedded in the core. The core validates BLOB/CRL offline, while durable MDS snapshots, number high-water mark, and atomic updates are absent from the product. RUSTSEC-2023-0071 is excluded only for RSA **public-key verification** without private-key operations, per [ADR 0008](adr/0008-webauthn-conformance.md).

The [mandatory FIDO result](../local/conformance/results-2026-09-22.md), [fit/gap backlog](webauthn-fit-gap-todo.md), [fuzz record](webauthn-fuzzing.md), [ceremony contract](webauthn-ceremony-contract.md), [attestation contract](webauthn-attestation.md), and [MDS boundary](webauthn-mds-operation.md) provide internal evidence. Mandatory conformance, optional cases, formal certification, real-device coverage, and external review are distinct.

CI is configured for `cargo audit --file Cargo.lock` and `npm audit --audit-level=low` on push/PR, with weekly Dependabot for Cargo, npm, and Actions. On 2026-09-23 a current RustSec database scan covered 129 Rust dependencies and found nothing beyond the documented narrow RSA exception; npm audit found zero vulnerabilities. These are dependency scans, not source audits.

The original brief had not fixed an external reviewer or reviewed commit and had no completed external review. Use [SECURITY.md](../SECURITY.md) for the current vulnerability-reporting route; verify its availability before advertising it for a release.

| Review record | Current value |
| --- | --- |
| Reviewed commit, reviewer, date | Not yet recorded |
| Scope and exclusions | This brief only |
| Findings and severity | No external review performed |
| Remediation and residual risk | Not applicable yet |

Never present internal tests, advisory scans, or FIDO Conformance as an external clean audit.
