# Managed-work checkpoint on current main

The opt-in managed-work authority has an independent SQLite Durable Object
checkpoint and transaction frames for covered OP security changes. The source
is ported from the preserved pre-main work; qualification below uses the current
Owner Vault baseline and dependency versions. No production checkpoint, binding
or migration is activated.

[Work migration 0009](../crates/worker/work-migrations/0009_work_authority_checkpoint.sql)
adds a single authority/epoch/sequence/tip marker without enrolling existing
data. [Migration 0010](../crates/worker/work-migrations/0010_op_authority_frames.sql)
requires a transaction-scoped frame for enrolled account, credential, Passkey,
SSO, account-role and runtime-policy changes. A deferred foreign key requires
the frame to close within the same transaction. Ordinary OP operations keep
their existing behavior when both the checkpoint binding and enrollment are
absent, including when the opt-in schema has not been applied.

The [Rust coordinator](../crates/worker/src/work_store/checkpoint.rs) obtains a
write-ahead permit, advances the primary D1 marker together with live guards and
audit, and confirms the exact next marker before acknowledging success. An
unknown result with an old marker remains quarantined. Reconciliation of a
committed next marker replays no business SQL or external effect. A definitive
constraint abort can settle an empty marker slot while leaving business state
unchanged. Missing, stale, pending, frozen or unsupported independent state
refuses affected work and source plaintext release.

The [private Worker](../crates/work-checkpoint-worker/worker.ts) has a fixed
authority scope and named service/operator entrypoints. Its default HTTP
handler returns 404. The OP receives only the service capability. Bootstrap,
release-floor raising and irreversible freeze belong to a separate operator;
there is no reset, unfreeze or automatic rebase API.

The [OP adapter](../crates/worker/src/op_authority.rs) frames current-main
enrollment completion, login/session creation, additional Passkey completion,
admin invitation completion, logout revocation/outbox creation and auth-state
collection. Logout still commits before asynchronously waking its Queue.
The [named administration facade](../crates/worker/service/authority-admin-facade.ts)
supplies its own OP environment to a bounded, strict `POST /authority` adapter.
It supports only exact account/session revocation, credential disablement and
validated policy activation against expected revision and generation. Public
and named facades deny the raw Wasm administration RPC; no public administration
route is added. The policy activation CLI uses this capability for enrolled
state and has no direct-SQL fallback after refusal or an unknown response.

The [16 checkpoint cases](../local/conformance/work-authority-checkpoint.test.ts)
pass on actual Rust/Wasm/workerd/D1/SQLite-DO. They cover whole D1-file restore,
independent runtime restart, concurrent permits, lost publication, durable
unknown-state quarantine, audit rollback, deferred-frame closure, current
source release, account/credential/policy revocation, actual logout and additive
migration preservation. Tests assert persisted rollback state rather than
depending on workerd's error wording for deferred foreign-key rejection.

This is managed-work protection for the covered mutation/release paths, not an
IdP-wide rollback guarantee. Other OIDC issuance, Agent/Vault/Wallet release,
control-plane mutation, privileged SQL and partial schema restoration still need
their own coverage. Protecting the checkpoint's own restore/deployment path,
independent operator identity, release provenance and schema/key/payload
inventories remains an activation gate. A checkpoint observation is not a
reusable permission to mint credentials or mutate Git; M4/M6 admission remains
separate. See the [integration plan](work-delegation-implementation.md).
