# Preparation evidence composition

M6e connects the [fixed Git gate](work-artifacts-git-gate.md) to Native's
`dispatched → verified` preparation transition. The caller supplies only an
opaque preparation ID. Rust derives the six credential obligations from primary
storage, reads independently retained evidence and constructs `VerifiedPreparation`.
There is no caller-supplied receipt, token, Git fact, repository handle or URL.

## Evidence and authority

The [read-only checkpoint entrypoint](../crates/work-checkpoint-worker/worker.ts)
returns a bounded projection of two closed initial effects and four closed mint
records. Every mint must have retained Native bearer-refusal proof and a completed
Git result. Its six synchronous SQLite reads precede `storage.sync()`. It has no
framing, admission, mutation, maintenance, physical Artifacts or credential API.
The default checkpoint handler remains inaccessible publicly. Native resolves
this capability through `WORK_PREPARATION_EVIDENCE`, with no network fallback.

The [Rust composer](../crates/worker/src/work_effect/preparation.rs) compares every
attempt/digest, role/purpose/scope, fixed namespace/name, initial repository and
token identity/expiry, key generation/fingerprint and closure receipt with the
six closed Native records. All must be independently refused; expiry alone does
not satisfy this adapter. Closed envelopes are absent. Verification reads retained
key metadata without obtaining a wrapping secret, so closed proof remains usable
after the secret generation is no longer available for decryption.

For each role, both Git plans must match the preparation/disclosure digests and
registered commit/tree and branch. Historical admission checkpoints must belong
to the current authority/epoch and cannot be ahead of its sequence. Upload must
be `git_push_accepted`; independent readback must be `git_readback_verified`.
Their commit/tree/branch, commit/object counts, decoded object bytes and complete
inventory hash must agree. Task counts/bytes must also equal Native's registered
code inventory; the snapshot must have exactly one commit. Native checks the
host v1 result commitments using the sorted Native plan JSON and fixed facts
field order. These receipts are private trusted-adapter commitments, not signed
provider attestations. The Git host and independent ledger remain trusted
components; this increment does not establish public attestation or provenance.

The payload commitment uses domain `mikaki.work-preparation-payload.v1`, the
preparation and disclosure digests, and task then snapshot repository IDs and
upload/readback results. Array order in the ledger response does not change it.
The credential commitment uses the existing Native
`mikaki.work-credential-receipt.v1` contract over all six retained closures. Both
are passed to the existing framed verification transition. D1 repeats live
owner/source/epoch/policy and preparation expiry guards at commit. The response
contains only the existing owner-visible preparation/destination projection.

## Retry, restoration and product meaning

An unavailable, missing, malformed, extra, conflicting or over-32-KiB evidence
response fails closed. Native strictly rejects duplicate JSON keys and bounds
nesting. Neither the opaque trigger nor composer performs Artifacts calls, Git
execution, token minting, revocation or credential decryption. An unknown upload
result cannot become a verified copy just because its credentials were closed.

Exact retries rebuild the same commitment from immutable retained facts and
return the existing verified record without another audit or checkpoint mutation.
Concurrent verification writes at most one transition; checkpoint contention may
require a later exact retry. Losing the verify acknowledgement does not replay
Git. Restoring D1 behind the independently retained checkpoint fences verification
even if the independent copy evidence is complete. Freeze, pending admission or
an external release-floor increase also fences new Native verification.

`verified` is historical preparation evidence. It does not materialize a task,
create a request/grant/run, release a workload token or authorize a code adoption.
An exact historical retry after source revocation can still return the same
verified projection; the product must use the separately checked current
availability before making any productive decision. Cleanup/cancellation retains
the evidence rather than returning it to a productive state.

The composition acknowledgement is a private preparation/destination projection,
not the complete browser DTO. UI integration must reread the session-bound
[owner projection](../crates/worker/src/work_store/owner.rs), which supplies
`revision`, `materialized` and `current_authority` for the existing
[presentation schema](../crates/worker/ui/work-view.ts). Its `current_authority`
is true only for a materialized, current prepared task. A newly verified copy
therefore remains unmaterialized with that flag false; it must not enable
delegation merely by changing its preparation status label.

## Integration and qualification

`WorkPreparationGate` accepts only `{preparation_id}` on its named private
`/verify-preparation` binding. Its only service binding is the fixed Native effect
facade. Its public default handler returns 404. Both
`WORK_PREPARATION_GATE_ENABLED` and Native `WORK_PREPARATION_VERIFY_ENABLED` are
opt-in; all production flags, binding inventories and baseline migrations remain
unchanged. No new migration or independent ledger capacity slot is introduced.

The [local qualification](../local/conformance/work-preparation-evidence.test.ts)
uses actual Rust/Wasm/workerd/D1/R2, independent SQLite/RPC and real loopback Git
smart HTTP. Artifacts metadata and credentials are synthetic. It checks both
copies, six closures, bounded metadata/substitution, closure without copy proof,
lost upload/verify replies, concurrency/restart, rollback fencing, authority loss
during the evidence wait, wrapping-secret independence and capability isolation.
Run `npm run test:work-preparation-evidence` for this increment, or
`npm run test:work-delegation` for the combined local work lane.

The installed Miniflare rejects `2026-10-09` as a future compatibility date;
the disposable new gate fixture therefore uses its supported `2026-10-08` date.
A deployment must select and qualify its actual supported runtime/configuration.
[Service bindings](https://developers.cloudflare.com/workers/runtime-apis/bindings/service-bindings/)
and [SQLite DO storage](https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/)
are the platform contracts used by this adapter.

Copy/delegation UI, managed launch/issuer exchange, workload credential release,
Cloudflare Git-host/source-registry placement, missing/unobserved custody recovery,
protected remote reconciliation and real Artifacts trials remain separate gates.
This local result does not activate production or qualify the canonical Artifacts
baseline. The protected development repositories, journals and preserved stash
remain untouched.

Implementation source is `b4e3b010212240ef4c7692df0149e5605d110c11`.
Current local qualification passes **289/289 combined work cases** (274 previous
plus 15 composition cases), and **29/29 production OP/service boundary,
baseline/Owner-schema, worker-roster and release-inventory cases** against the
Worker rebuilt with that exact source revision. Native default-production Wasm
Clippy with warnings denied, Rustfmt, Node/service/effect/checkpoint types,
Prettier, product-source and documentation checks pass. Named OP packaging
preserves the 64-statement static Agent SQL catalog. Served UI and both Wasm size
checks pass; OP Wasm measures **6,225,033 raw bytes / 2,186,597 gzip estimate**,
within the existing 8 MiB / 3 MiB ceilings. No new browser, remote CI, real
Artifacts or production-activation qualification is claimed.
