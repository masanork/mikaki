# Initial Artifacts effects on current main

M4 ports the preserved initial-create gate and safety maintenance boundaries
onto the fresh Owner Vault baseline. **50 local effect qualification cases pass**
using the current Rust/Wasm and TypeScript dependencies. No remote Artifacts
resource, checkpoint, production binding or deployment is changed.

The [native OP adapter](../crates/worker/src/work_effect.rs) derives an exact
initial plan from live managed-work authority. Inputs cannot supply a URL,
namespace, SQL or credential. The [named OP facade](../crates/worker/service/authority-admin-facade.ts)
holds the OP environment; public and named facades refuse raw administration
and effect RPC. The cold product adapter refuses effects by default.

The [initial gate](../crates/work-effect-worker/worker.ts) checks that plan against
its fixed account/namespace/authority and obtains one durable admission from the
independent checkpoint before provider I/O. Admission is the concurrency point:
an already admitted call can still finish while an owner revocation races it.
A lost reply or process restart never permits another create for the same
attempt. Unknown attempts remain charged and retained; expiry or empty inventory
does not prove that the external effect did not happen.

Successful closure requires exact repository identity, initial token inventory,
revocation and an explicit 403 from the fixed Git endpoint for the returned
bearer. The initial secret is never returned to an owner/workload or persisted
in D1, DO, receipts or logs. Independent closure survives failed OP metadata
synchronization. Replaying a closed result repeats only bounded metadata
reconciliation.

The [maintenance broker](../crates/work-effect-worker/maintenance.ts) owns the
physical Artifacts binding. Its read-only ledger lookup determines the admitted
repository; callers provide only an attempt ID. It returns a disposable RPC
target with metadata, bounded token inventory and qualified ID-specific
revocation. The target has no create, mint, fork, write, delete or namespace
methods and checks admission and immutable identity again on each call.

The [safety reconciler](../crates/work-effect-worker/reconcile.ts) receives that
broker plus a safety-only checkpoint capability. It holds no physical Artifacts
binding and cannot admit a productive effect. A retained ID/token observation
can support fresh revocation evidence, including after freeze, floor raising or
OP loss. Lost revocation followed by token absence cannot certify cleanup.
Metadata evidence does not claim bearer refusal or reopen an unknown create.

The [local suite](../local/conformance/work-effect-gate.test.ts) covers one-time
concurrent admission, restart, whole D1 restore, pending/frozen/revoked admission,
lost provider/ledger/OP replies, substituted repositories/tokens, capacity,
refusal/redirect failures, capability attenuation and RPC disposal. Synthetic
Artifacts/Git validates these failure contracts; it is not fresh evidence about
actual remote bindings.

The six previously recorded empty development repositories and their protected
journals remain untouched, including unresolved allocations. Do not replace
them with new creates/remints or infer closure from an empty repository. A real
remote recovery/trial must resume those same identities with a complete
resource/token inventory. Productive upload/readback, new credential mint and
release, signed deployment/recovery provenance and complete IdP release coverage
remain open. See the [integration order](work-delegation-implementation.md) and
[checkpoint scope](work-authority-checkpoint.md).
