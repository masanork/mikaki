# ADR 0011: Manage the active runtime policy in D1

**Status:** Accepted, 2026-09-23

## Context

[ADR 0004](0004-runtime-policy-configuration.md) removed operational values from code, but the Worker initially read a generated environment-variable projection. Every change to durations, rates, or limits would require another Worker deployment.

## Decision

- The runtime authority is deployment-specific D1. TOML is an initial or editing example; the environment-variable projection is transitional.
- Store complete, immutable policy versions. Validate schema, types, ranges, cross-field constraints, and revision before atomically changing one active-version pointer. Audit the actor, reason, time, and old and new versions. Do not merge partial updates implicitly.
- At request start, read and use one complete, validated snapshot. Record issuance-time expiry and policy revision with durable state. Activation does not silently change issued deadlines. A request crossing activation uses either the complete old or complete new version.
- Fail closed for a D1 read error, missing policy, invalid schema, or hash mismatch. Do not fall back to environment variables or built-in defaults. The initial implementation reads D1 on each request; a future cache needs an explicit freshness and revocation contract.
- Keep signing secrets, recovery-generation secrets, D1 bindings, stable issuer, and deployment-level bounds on authentication methods outside the D1 policy. Only an isolated conformance deployment may register secret-based clients. Per-client authentication method, public key or secret verifier, redirect URI, and PKCE requirement belong to that deployment's D1. An HTTP request cannot switch the deployment profile.

## Consequences

Changing policy no longer requires a Worker redeploy, but new authentication depends on D1. Management needs authorization, compare-and-update behavior, audit, and rollback checks. Measure read consistency and activation time. An already-issued status-check lease still matters when reporting the revocation bound. If D1 read replication is enabled, policy reads must use primary state or equivalent freshness.

## Alternatives

Continuing to treat the environment projection as authoritative would require deployment for every operational change. Putting signing secrets or the set of permitted deployment authentication methods in D1 would let D1 management alone change the production trust boundary. Neither option was adopted.
