# Runtime-policy contract

**Revision 2, 2026-09-23.** Operational durations and counts belong in typed configuration, with accepted design values as initial defaults. [ADR 0004](adr/0004-runtime-policy-configuration.md) defines separation from code; [ADR 0011](adr/0011-d1-runtime-policy.md) selects versioned active D1 state. A full product loader for every field remains incomplete. A design validator, Worker D1 projection loader for selected OIDC values, and activation CLI exist.

## Source and deployment boundary

Use [`runtime-policy.example.toml`](../config/runtime-policy.example.toml) for initial input and editing. Older session/flow/key examples remain historical references; do not merge them at runtime. Each deployment has exactly one authoritative active D1 version. Validate and store a complete immutable candidate, then atomically switch the active pointer. No unauthenticated configuration API, implicit environment override, browser override, or file merge is allowed.

The core receives a validated snapshot from an adapter, not a file/env/D1 handle. Signing private keys and recovery secrets remain in secret custody; D1 binding, stable issuer, and permitted deployment profile stay deployment-controlled. Per-client authentication method, public key or verifier, redirects, and PKCE requirement are stored in deployment-specific D1.

`MIKAKI_DEPLOYMENT_PROFILE` selects a deployment profile and defaults to `normal`. An isolated [conformance config](../crates/worker/wrangler.conformance.jsonc) uses separate issuer, D1, and signing secrets. Only that profile accepts `client_secret_basic` or `client_secret_post`. Each client's `auth_method` is fixed in D1. A secret is at least 32 random bytes; store only its SHA-256/base64url verifier. `allow_missing_pkce` defaults to 0 and can be 1 only for an isolated conformance secret client; normal clients still require PKCE. Client changes increment revision. The initial secret-attempt window is 60 seconds/300 per client, sourced from active D1 projection. Real IDs, keys, and secrets are absent from examples.

The current Rust Worker reads selected OIDC TTLs, SSO absolute lifetime, skew, target/parameter/state/nonce bounds, request/JWT/response sizes, and token attempt limits as strict JSON projected from active D1 on each request. Projection contains schema version 5, a revision derived from the whole policy, and its own hash. There is no `MIKAKI_WORKER_POLICY` fallback. `npm run build:policy` validates one TOML and generates `local/generated/worker-policy.json` for activation. Issuer is `MIKAKI_ISSUER`; `OP_PRIVATE_JWK` is a separate Worker secret, with matching public signing key in D1. RSA signing uses Workers WebCrypto. Never put private keys into vars or policy.

Migration `0001_oidc_initial.sql` creates policy-version, active-pointer, and audit tables but does not autoactivate a version. The CLI validates schema, ranges, and projection hash, then batches insertion, expected-revision compare-and-swap, and audit. Use `--expected none` only for first activation and the current revision thereafter. The example config below points at local D1; a remote operation needs the correct production binding, `--remote yes`, and appropriate authorization.

```sh
npm run build:policy
npx wrangler d1 migrations apply DB --local --config crates/worker/wrangler.jsonc
node scripts/activate-worker-policy.ts --config crates/worker/wrangler.jsonc --policy local/generated/worker-policy.json --expected none --actor local-operator --reason initial-policy --remote no --apply no
node scripts/activate-worker-policy.ts --config crates/worker/wrangler.jsonc --policy local/generated/worker-policy.json --expected none --actor local-operator --reason initial-policy --remote no --apply yes
```

Require `schema_version`; reject unknown versions/keys, duplicate keys, missing fields, and wrong types. An example lists every active field explicitly; omission does not fall back to a hidden code default. Read only fields needed at a product stage, so P0 does not need a working P1 Vault loader.

## Types and initial values

Durations are positive integer strings with one suffix `s`, `m`, `h`, or `d` (one day is 86,400 seconds). No months, years, fractions, bare numbers, compound durations, zero, or negative sentinel for “unlimited.” Counts are positive integers. Normalize to seconds and check overflow and safe timestamp addition.

| Key | Initial value | Meaning |
| --- | --- | --- |
| `authentication.ceremony_ttl` | `5m` | WebAuthn ceremony lifetime |
| `authentication.ceremony_max_failures` | `5` | Completion failures per ceremony |
| `session.sso_absolute_ttl` | `30d` | SSO absolute lifetime |
| `session.app_idle_timeout` | `7d` | RP app idle timeout |
| `session.validation.lease_ttl` | `5m` | Maximum managed RP status-check lease |
| `session.management.operation_authorization_ttl` | `5m` | One-time operation-bound management permission |
| `oidc.authorization_code_ttl` | `60s` | Authorization code |
| `oidc.id_token_ttl` | `5m` | ID Token |
| `vault.unlock_idle_timeout` | `15m` | Vault local idle lock |
| `vault.unlock_absolute_ttl` | `1h` | Vault absolute unlock |

Logout Token lifetime, signing-key cadence and advance publication, JWKS cache, old-key minimum retention, Access Token and transaction TTLs, clock skew, retries, network timeouts, sizes, rates, capacity, and GC belong to the integrated policy. [OIDC operations](oidc-operations.md) defines their control unit. The older [key-policy example](../config/oidc-key-policy.example.toml) is historical, not an independent runtime input. Example values are tuning starts, not evidence that every product endpoint enforces them.

## Invariants and activation checks

Configuration may adjust durations, counts, and intervals but cannot turn off UV, one-time code/management permission, client/target binding, denial after revocation, or fail-closed lease expiry during outage. Algorithm, key size, entropy, ID format, and crypto suite need adopted/tested profiles, not arbitrary strings. App absolute expiry derives from the parent SSO rather than a contradictory separate knob.

Check `app_idle_timeout <= sso_absolute_ttl`; `lease_ttl <= app_idle_timeout` and `<= sso_absolute_ttl`; management and code TTLs no longer than SSO bounds; Vault idle no longer than absolute unlock; and signing-key advance publication covering JWKS cache, skew, and deployment overlap when that feature is active. Reject values exceeding integer, body, or configuration limits instead of silently clamping. A failed candidate leaves the healthy active version untouched. Missing/corrupt/unreadable active D1 state stops new authentication and issuance, without a fallback default. Syntactic validity is distinct from operational suitability.

Normalize all effective keys to ASCII dotted paths, durations to integer seconds, include `schema_version`, serialize a lexically key-sorted whitespace-free ASCII JSON object, and take lowercase hex SHA-256 as `policy_revision`. Comments or `60s` versus `1m` do not change it. New types require a schema revision. Compare the [TypeScript design validator](../scripts/check_design.ts) against Rust behavior. Keep revision in server records/audit; it is not a required public token claim.

Store immutable versions, one active pointer, and audit separately. An operator reviews complete candidate and diff, then switches using expected old revision; only one concurrent update wins. A request reads pointer and payload consistently, verifies schema/hash, and uses the same snapshot to completion. Initially read D1 on every request. A future cache or read replica needs a freshness guarantee compatible with revocation; do not mix fields from old and new versions.

| State | Ordinary change behavior |
| --- | --- |
| New SSO, ceremony, management permission, code, token | Save issuance-time deadline/limit and policy revision |
| Existing SSO, code, token | Keep issued deadline; no implicit extension or truncation |
| RP application session | Keep creation-time idle timeout and parent absolute expiry |
| New status-check result | Use policy active when checked, even for an older SSO |
| Existing status-check result | Keep original lease deadline |
| Current Vault unlock | Keep unlock-time setting; next unlock uses new value |
| Keys and revocation records | Never shorten necessary retention; lengthen when newly issued history requires it |

An immediate stop needs explicit revocation or global logout, separate from shortening policy. A rollback cannot revive revoked sessions, sid, or keys.

## Propagation, revocation, and retention

Do not duplicate numbers in Mikaki and RPs. Authenticated session-check responses include `policy_revision`, parent SSO expiry, maximum validation lease, and idle timeout for a **new** app session. RPs cap a lease from request start by their local and parent expiry; they may choose shorter limits but not longer. A cached status result is not the same as app-session lifetime.

Give the Vault UI only required public settings from Mikaki origin, fixed with revision for that unlock. Network failure cannot switch to a longer value. Browser locking describes an honest client, not remote erasure of a compromised device.

The revocation bound follows `lease_ttl`, initially five minutes. After shortening from five to one minute, previously issued five-minute leases remain until the last old-version issuance expires; do not advertise a one-minute bound earlier. During old/new deployment overlap, the operational bound is the larger lease either can issue. Lengthening takes effect as soon as new responses issue. Audit revisions and the transition time, including rollback.

Old signing-key retention must account for minimum configured time, actually issued token expiry, sessions whose ID Token can be used as a hint, logout-hint allowance, and clock skew. `retain_until` may increase but not decrease from a shorter setting. Revoked sid and retry records similarly need a history-derived lower bound; GC grace alone cannot delete live evidence. Immediate compromised-key rejection is a separate operation.

Activation sequence: edit → parse/type/relationship validation → register immutable D1 version → inspect diff → atomically switch with expected revision → verify running revision and guarantee transition. Audit actor, reason, time, and revisions; rollback is another recorded pointer switch. Never display secret signing keys or tokens as policy output. Test default and short profiles, unknown or empty tables, units/zero/negative/overflow, cross-field mismatch, changes in both directions, mixed deployments, rollback, and key GC after a long-lived session. Validating an example does not prove a complete future product loader.
