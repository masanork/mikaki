# ADR 0014: Bounded delegated-agent OAuth authority

**Status:** accepted for the local preregistered public-client profile, 2026-09-28. Production activation and real-client qualification remain open.

## Context

[ADR 0009](0009-rust-oidc-and-worker-stack.md) places authentication/authorization transitions in Rust. [ADR 0013](0013-agent-proposal-authority.md) permits TypeScript for isolated agent product transitions; that decision alone does not authorize a new OAuth protocol implementation. The agent Worker already holds the selected snapshot recipient, grant transitions and MCP transport. Its public OAuth profile delegates an existing grant; it does not authenticate owners, issue identity tokens or reuse OIDC login codes/clients.

## Decision

Record a second, explicit limited exception: `crates/agent-worker/oauth.ts` and migration `0018` own this separate delegated-agent AS's validated request, owner/session binding, consent, one-time code, narrowed token and token revocation transitions. The public HTTP handlers and owner dashboard call that authority. D1 conditional statements, unique constraints, audit triggers and a final transaction guard enforce single-use/concurrency and rollback. No browser decision or independent second ledger authorizes access.

The profile is operator-preregistered public clients, exact callbacks/resource, S256 PKCE, bounded codes/tokens and no refresh, dynamic registration or metadata-document fetch. Each token derives from one selected existing same-owner grant/revision and a requested scope subset. Domain writes and disclosure recheck that token and the original grant authority. Client labels remain disclosures, not proof of a provider/bot identity. The dedicated AS accepts neither SSO cookies nor OIDC/UserInfo tokens; the Rust OP alone authenticates owners and forwards server-derived identity on its private service binding.

OIDC/login/logout and their existing Rust authorities remain unchanged. Rust also retains owner ciphertext storage and final approved-note consumption/commit. Widening this OAuth profile or production activation requires review of this exception and the actual client/operational evidence; the local implementation is not a general relaxation of ADR 0009. If the AS moves to Rust, run the same positive, revocation, concurrency, audit-failure and adapter cases and retire the TypeScript transition authority rather than maintaining both.

## Alternatives and consequences

Routing agent authorization through the existing confidential OIDC profile would silently change its scope/client/token semantics and confuse login with decrypting-recipient delegation. A separate Rust AS could preserve the general language direction but would split this isolated grant domain across another authority before the public-client profile and real client requirements are qualified. The narrow local exception keeps one auditable transition owner and adds explicit runtime validation; it gives up Rust's validated domain types for this profile and therefore is a real trade-off, not equivalent assurance.

No new recipient disclosure or owner-key release occurs during OAuth connection: the owner selects an already-authorized snapshot. Note proposals still require separate target/revision capabilities, and note commits remain owner-only. See the [profile, failure/retention contract and qualification gates](../agent-oauth.md).
