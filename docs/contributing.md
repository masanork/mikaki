# Development guide

Mikaki is an experimental security-sensitive project. Keep each change narrow and explain the user-visible behavior, trust boundary, failure behavior, and evidence for it. A design document is useful context; a test or deployment record is needed to claim implemented behavior.

## Repository map

| Path | Role |
| --- | --- |
| `crates/webauthn/` | Portable WebAuthn parsing and verification |
| `crates/auth/` | Account, credential, and ceremony logic |
| `crates/oidc/` | OIDC core and protocol state |
| `crates/worker/` | Cloudflare Worker, D1, HTTP, and runtime adapters |
| `crates/browser-wasm/` | Browser and conformance WebAssembly boundary |
| `local/` | Disposable integration harness and test RP |
| `design/` | Probes and design-validation models |
| `config/` | Runtime-policy input examples |
| `docs/` | Guides, contracts, proposals, and ADRs |

The intended dependency direction is Worker → OIDC → auth → WebAuthn. Keep HTTP, D1, Workers, time, and randomness outside the portable verifier. Use maintained cryptographic libraries rather than new cryptographic primitives. Do not treat Rust types alone as proof of database atomicity.

## Before opening a change

1. Check [status](status.md), the relevant topic document, and any [ADR](adr/) for the affected contract.
2. Update the document that owns the behavior. Mark proposed, locally verified, and deployed claims separately.
3. Add tests for meaningful failure and race conditions where the change affects identity or durable state. Keep test evidence tied to the environment actually exercised.
4. Run the checks relevant to the changed code. The common local checks are `cargo test --workspace`, `npm run test:e2e`, `npm run check:ui`, and `npm run check:i18n`. CI and additional target-specific checks may apply.
5. Record limitations and migration or rollout steps when the change affects persisted data or a deployed Worker.

For vulnerabilities, use the private route in [SECURITY.md](../SECURITY.md) instead of a public issue. External test data and dependency licenses remain subject to their own terms.
