# Managed-work domain profile v1

**Status:** Portable Rust core integrated with main baseline `8d48ba93fef64f4802627939ec63235eeef6aa68`, 2026-10-08 JST. D1/Worker/UI integration remains pending; no endpoint, issuer or external effect is activated.

This narrows [ADR 0016](adr/0016-personal-context-and-workload-delegation.md) and the [authorization contract](workload-authorization.md). The [integration plan](work-delegation-implementation.md) distinguishes current qualification from preserved pre-main evidence.

## Component ownership

| Concern | Authority |
| --- | --- |
| Request, grant, run, candidate and exact approval | Portable [mikaki-auth::work](../crates/auth/src/work/mod.rs), under [ADR 0009](adr/0009-rust-oidc-and-worker-stack.md). |
| Durable transitions, current owner/source state and audit | Rust OP adapter, pending integration of retained WorkStore with main's fresh schema. |
| Checkpoint and external-effect admission | Independent durable authority plus fixed-operation adapters, pending main integration. Preserve [ADR 0015](adr/0015-service-data-ownership.md); downstream services receive bounded capabilities. |
| Frontend | [Work-request UI contract](work-request-ui.md); display durable confirmed state and bind each confirmation to the reviewed operation. |

`from_authority`, `from_verified_session` and `from_verified_request` are trusted adapter inputs, not authentication mechanisms. Production adapters must obtain current verified principals and authoritative facts; a submitted issuer/client/run/key claim is not trusted by construction.

## Portable contract

The profile is `mikaki-managed-work-v1`. Workload proposal submission uses `repo.proposal.submit`. Exact owner adoption is a separate `repo.change.adopt` operation; it does not reactivate a revoked producer.

Requests bind owner epoch, policy/request revision, selected disclosure, recipient, task repository, upstream target/ref/head, operations and deadline. Runs additionally bind issuer revision, client, logical workload, instance, grant and proof key. Approvals bind the exact candidate and target to current owner authority. Relevant changes require fresh authorization at commitment. Unknown dispatched effects preserve identity; reconciliation cannot create another dispatch.

[Source rules](../crates/auth/src/work/sources.rs) validate selected membership, versions, access receipts and actual content digests. [Disclosure rules](../crates/auth/src/work/disclosure.rs) distinguish selected snapshot contents from reachable code history. Storage/Git adapters must independently establish these facts.

[Credential custody](../crates/auth/src/work/credentials.rs) binds an attempt to preparation, role, purpose and expected repository. Initial/upload purposes use write scope; readback uses read scope. Secret envelopes authenticate the attempt, observed repository/token/expiry and wrapping-key generation. These rules do not issue/revoke a provider token or prove Git refusal.

Closed request input and versioned authority-record codecs remain separate from private domain state. Restoring immutable JSON cannot restore live permission. Storage must repeat current guards and audit atomically on primary records.

## Local qualification record

The main-based auth suite passes **35 unit tests** (34 work cases and the existing ceremony case) plus **one compile-fail test** preventing untrusted input deserialization into authoritative state. Independent digest vectors, substituted actor/key, stale/revoked authority, exact approval, retained unknown effects, credential AEAD binding and disclosure/history limits are covered. The Wasm target check also passes:

```sh
cargo test -p mikaki-auth --offline --locked
cargo check -p mikaki-auth --target wasm32-unknown-unknown --offline --locked
```

These use main's Rust `1.98.1`, SHA-256 `0.11.0`, base64 `0.23.1`, AES-GCM `0.11.1` and zeroize `1.9.1`. No dependency downgrade is required. Portable tests do not qualify D1 atomicity, Artifacts behavior, workload signature verification, AuthZEN HTTP, actual owner ingress or production activation.
