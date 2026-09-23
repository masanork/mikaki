# Architecture decision records

ADRs record accepted choices and their rationale. They do not certify that a feature is implemented or deployed. The [status page](../status.md) records implementation evidence.

| ADR | Decision |
| --- | --- |
| [0001](0001-common-account.md) | Use one Mikaki account per instance for normal login across participating applications. Keep application subjects, sessions, and permissions separate; do not require a vault for login. |
| [0002](0002-oidc-from-first-release.md) | Use OIDC Authorization Code with PKCE from the first production RP integration, while presenting a passkey-first user experience. |
| [0003](0003-session-lifecycle.md) | Bound SSO, app-session, management, code, and vault lifetimes; include managed RP logout and a bounded status-check lease. |
| [0004](0004-runtime-policy-configuration.md) | Put adjustable operational values in validated, versioned configuration. Preserve safety invariants and do not silently change issued expiries. |
| [0005](0005-invitation-bootstrap-and-recovery.md) | Require invitations for enrollment, close a one-time first-admin bootstrap gate, and offer no recovery for loss of all passkeys in the initial product. |
| [0006](0006-compact-portable-webauthn.md) | Continue Mikaki with a compact Rust WebAuthn core shared by native and Wasm adapters. Keep account, storage, HTTP, and OIDC logic outside it. |
| [0007](0007-packed-self-attestation.md) | Add ES256 packed self-attestation verification while retaining a product attestation request of `none`. Self-attestation does not establish authenticator provenance. |
| [0008](0008-webauthn-conformance.md) | Require all mandatory FIDO2 Server Conformance tests to pass. Keep compatibility verifier capabilities distinct from product defaults. |
| [0009](0009-rust-oidc-and-worker-stack.md) | Own OIDC state transitions in Rust; prefer a Rust Worker adapter and use TypeScript for browser UI and browser-specific operations. |
| [0011](0011-d1-runtime-policy.md) | Store complete, immutable runtime-policy versions in D1 and atomically select one active version per deployment. Fail closed on missing or invalid policy. |

There is no ADR 0010 in the repository. The numbering is not renumbered to hide that gap.
