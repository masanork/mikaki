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
resource/token inventory. Productive upload/readback and credential
release, signed deployment/recovery provenance and complete IdP release coverage
remain open. See the [integration order](work-delegation-implementation.md) and
[checkpoint scope](work-authority-checkpoint.md).

[M6a one-shot mint and Native custody](work-artifacts-mint-gate.md) now provides a separately qualified local gate for the upload/readback credential slots. It does not change these initial-effect closure and maintenance boundaries.

## Read-only protected allocation inspection

From a clean committed checkout, run `npm run inspect:work-artifacts`. The
[inspector](../scripts/inspect-work-artifacts.ts) pins the exact SHA-256 of each
of the three retained `work-artifacts-effect` journals and projects their six
original attempt IDs, names, repository IDs and states. It never imports these
synthetic checkpoint records into an enrolled remote authority or changes a
protected journal. The existing saved Artifacts OAuth credential supplies
Artifacts GET requests; the environment API token separately supplies the fixed
production OP settings read. Credential values and OP binding values are never
returned or written to receipts.

The [REST API](https://developers.cloudflare.com/artifacts/api/rest-api/)
inspection enumerates the complete bounded namespace inventory and checks each
protected repository by its original ID/name/remote. It reads token metadata
with `state=all`, verifies offset pagination/counts, reads repository metadata
again, and requires the final namespace inventory to match. Duplicate IDs/names,
repeated cursors, missing pages, replacement identities and changing observations
stop the inspection. Repository descriptions/source strings and secret values
are omitted from retained projections. The fixed HTTP transport has only GET
and allows only this namespace inventory, the six repository metadata/token
routes and `mikaki-auth` settings; there is no Git, create, mint, revoke or delete.

Each run creates a separate ignored `local/generated/work-artifacts-inspection/`
directory. Its exclusive synchronized `inspection.jsonl` records read intents,
HTTP statuses and validated observations. A complete run writes an exclusive
`result.json` and rechecks the protected journal hashes. A failed read retains
the incomplete journal without overwriting previous runs. Read-only inspection
may be repeated; it cannot reopen productive effects or mutate their ledgers.

An absent/inactive token does not independently prove revocation or bearer
refusal. A retained `outcome_unknown` stays unknown, even if its repository is
empty and every token is absent. Binding names are a configuration observation,
not proof of remote Native/checkpoint enrollment. This inspector supplies current
identity/inventory evidence for a later recovery/activation review; it grants no
productive adoption or delegation authority.
