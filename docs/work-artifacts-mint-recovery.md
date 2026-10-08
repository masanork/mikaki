# Known-ID Artifacts mint recovery

M6b adds safety recovery for an admitted upload/readback mint whose independent
ledger already observed a token ID. Recovery keeps the same attempt, repository
and charge; it cannot mint again, perform Git operations, verify a copy, release a
credential or close the Native obligation. This extends the
[M6a mint gate](work-artifacts-mint-gate.md) without production activation.

## Fixed capabilities

The private named [reconciler](../crates/work-effect-worker/mint-reconcile.ts)
accepts only POST `/reconcile-mint` with `{attempt_id}`. Its bindings are the
safety-only `WorkMintMaintenance`, the attenuating maintenance factory and the
named Native effect adapter. It has no physical Artifacts binding, mint admission,
OP checkpoint administration, wrapping key or plaintext API. Default/public
handlers return 404; disabled and unadmitted requests are refused.

The separately bound
[physical broker](../crates/work-effect-worker/mint-maintenance.ts) receives only
Artifacts and `WorkMintLookup`, a read-only ledger capability. It opens the
retained plan's fixed name and checks immutable repository ID, name, branch,
remote and initial-operation description. The returned `RpcTarget` retains its
binding and plan in JavaScript private fields. It exposes only bounded metadata
inspection and qualified revocation of the already observed token ID. It cannot
mint, fork, read files, write Git, delete a repository or return its raw binding.
Held capabilities recheck both identity and ledger eligibility and stop working
after disposal or completed cleanup.

## Durable intent and evidence

Before provider I/O, safety recovery records `cleanup_requested` durably in the
independent SQLite ledger. This prevents an in-flight mint from subsequently
acknowledging productive custody. Late observations can still be retained for
cleanup. The productive gate also requests cleanup when capture/custody fails,
including a lost custody acknowledgement followed by unsuccessful revocation.
An older retained custody record moves to cleanup only when an exact Native
status confirms revocation-pending or closed, rather than from status-read
failure.

Inventory must be complete and bounded. Known-token scope and expiry must match
the stored observation. For an active token the broker revokes that exact ID;
a positive provider acknowledgement is saved before another inventory lookup.
A fresh matching `revoked` inventory entry can instead supply control-plane
evidence. A token missing from inventory is usable only with an already retained
ID-specific positive revoke acknowledgement. Failed/lost revocation, substituted
metadata, incomplete inventory and an `expired` state remain unconfirmed.

The first accepted cleanup proof retains the exact observation, evidence method,
domain-separated digest receipt and observation time. Repeated reconciliation
uses the retained proof and performs no further provider I/O, including after
process restart. The proof is a trusted reconciler's record of control-plane
evidence; the receipt hash is neither a provider signature nor bearer-refusal
evidence. A changed receipt or method cannot replace the first proof.

If no token ID was observed, even a single active token with matching scope and
expiry is not attributable to this mint. Recovery returns `token_unobserved`,
retains the tombstone and does not revoke candidates or remint. Empty inventory
and elapsed time do not prove non-issuance or revocation.

## Native synchronization and remaining gates

After independent proof retention, the fixed metadata-only `mint-cleanup` Native
action can record or confirm the matching revocation-pending liability.
`op_synchronized` describes that metadata result; it does not authorize use or
close an obligation. No plaintext is reconstructed. Metadata capture needs no
wrapping key, while every new Native batch still passes the existing checkpoint
fence. Freeze, pending framing, a raised release floor, Native disablement or D1
restore can leave independent cleanup confirmed with Native synchronization
false. Confirming an already recorded exact Native state requires no new batch.

Cleanup itself does not advance preparation verification, issue a grant, return
a credential or release its reservation. Bearer-refusal closure when plaintext is unavailable,
unobserved-token/operator recovery, fixed Git upload, independent readback,
workload release and owner copy/delegation controls remain separate gates.
Independent-ledger restore/reset remains an operator provenance problem.

The protected remote journals, six empty development repositories, production
flags/bindings and baseline migrations are untouched. New recovery workers are
bound only in the synthetic local qualification profile; the existing remote
fixture gains no mint recovery workers. No remote mint/revocation trial or
production deployment is performed.

## Qualification

The [recovery suite](../local/conformance/work-mint-recovery.test.ts) exercises
actual Rust/Wasm, workerd RPC, D1 and persistent SQLite with synthetic Artifacts.
It covers task/snapshot and upload/readback, fixed-ID revocation, retained charges,
restart without provider replay, lost custody/revoke/inventory acknowledgements,
unobserved-token quarantine, incomplete/substituted inventory and repository
identity, empty/expired inventory, in-flight custody fencing, Native authority
loss/restore/key absence, immutable evidence, and cold/public/RPC boundaries.
Current counts and combined regressions are recorded in the
[integration plan](work-delegation-implementation.md). These are local results,
not remote provider or production qualification.


After M6a reconciliation, Native recovery uses the separate mint-only facade and
flag. A retained `closed` record with explicit Git-refusal evidence is eligible
for metadata synchronization without opening the physical broker or issuing an
ID revoke. Control-plane cleanup proof alone still leaves the obligation charged.
Frozen/pending/restored Native authority continues to fence new batches.
