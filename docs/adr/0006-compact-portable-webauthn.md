# ADR 0006: Build Mikaki around a compact, portable WebAuthn core

**Status:** Accepted, 2026-09-22

## Context and alternatives

The project considered extending monban or iwato instead of continuing Mikaki. Their coverage and test assets are useful, while Mikaki has been designed around a small verification boundary, atomic state transitions, revocation, and browser-side secret handling. The decision is to develop that foundation.

## Decision

- Continue Mikaki and prioritize a compact, understandable implementation. Add the vault and other distinct capabilities in stages.
- Use the same Rust WebAuthn verifier in native and Wasm adapters. Keep DB, HTTP, OIDC, accounts, and vault logic outside it. Avoid a general framework or new crates before a concrete need.
- Keep the initial `none` attestation request, ES256 product default, and required user verification. Use maintained cryptographic libraries. Additional algorithms must follow the crypto-agility policy and are not a substitute for quality.
- Preserve an API boundary that prevents external code from fabricating verified states. Challenge consumption and credential updates belong to auth/store; successful signature verification alone is not a completed login.
- Reuse selected lessons and test assets from monban and iwato without inheriting their structure or compatibility obligations.
- Aim to make the small API, native/Wasm consistency, and size meaningful reasons to select Mikaki over a broader library. Do not advertise superiority before comparing equivalent features and security conditions.

## Trade-offs and verification

Assess size using public API, production dependencies, Wasm artifact, performance, input limits, verification coverage, and state-transition clarity, not source-line count alone. Separate test dependencies from production dependencies and the verifier from an OIDC bundle.

An independent verifier carries ongoing specification, interoperability, and vulnerability-maintenance costs. Run common success and failure cases in native and Wasm, plus independent vectors, fuzzing, and real-device/browser checks. One home-grown fixture passing in both environments is not proof of compliance. Limited coverage makes Mikaki unsuitable as a replacement for broader libraries in some uses.

The [WebAuthn crate guide](../../crates/webauthn/README.md) tracks implementation and verification. This ADR does not change prior OIDC, session, or invitation decisions. [ADR 0007](0007-packed-self-attestation.md) later extends acceptance to ES256 packed self-attestation while retaining the `none` request default.
