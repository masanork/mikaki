# One-shot Artifacts mint and Native custody

M6a connects the existing six-slot credential journal to a private upload/readback
mint gate on current main. Copy upload, independently verified Git readback,
workload credential release and owner copy/delegation controls remain open.
Production flags, bindings, resources and baseline migrations remain unchanged.
The protected remote journals and their six empty development repositories are
untouched. This increment uses synthetic Artifacts over actual Workers RPC and
persistent SQLite, together with the actual Rust/Wasm OP and D1.

## Fixed authority and admission

The [Native adapter](../crates/worker/src/work_effect.rs) accepts an opaque attempt
ID for a plan; callers cannot select a repository, scope, URL, TTL or wrapping
key. [Native plan derivation](../crates/worker/src/work_store/credentials.rs) binds
that journal's preparation digest, role, destination, immutable repository ID,
absolute deadline, purpose, current checkpoint and active key fingerprint/version.
The initial token must already have a Native refusal closure for the same role
and repository. All owner, source, policy, key-floor and preparation guards still
apply. A primary dispatch is not an external dispatch permit.

The separately bound `WorkMintCheckpoint` checks its own initial-create closure,
exact current checkpoint, release floor and pending/frozen state before admission.
Its SQLite transaction durably retains one attempt and a unique permanent
namespace/name/purpose slot **before provider I/O**. A new attempt ID cannot
replace the same slot after primary restore. Retries compare immutable plan
fields and receive no new permit. Initial and mint tombstones share the existing
256-record bound; neither expiry nor token absence reclaims capacity.

The [mint gate](../crates/work-effect-worker/mint.ts) owns the physical Artifacts
binding, the named Native adapter and this mint-only ledger. Its implementation
uses only `get` followed by the fixed repository operations; the TypeScript
`Pick` annotation itself is not runtime capability attenuation. It returns no
repository or raw binding capability.
Its default/public handler returns 404. Its named handler accepts only POST
`/mint` with `{attempt_id}`. The checkpoint binding cannot create repositories,
bootstrap, reset, mutate OP frames or release credentials. Existing initial-effect
maintenance capabilities gain no mint methods.

## Provider result and custody

The gate verifies repository ID, name, branch and fixed remote before minting. It
requires a complete bounded inventory without active tokens. Therefore upload and
readback credentials for one repository must be used and closed sequentially;
an unresolved active token blocks the next purpose. It requests only the Native
scope (`write` for upload, `read` for readback), with a TTL at most 300 seconds and
below the absolute preparation deadline. The installed Workers binding and
[official API](https://developers.cloudflare.com/artifacts/api/workers-binding/)
use `createToken(scope, ttl)` and disposable repository capabilities.

A matching fresh inventory must identify exactly the returned active token and
preserve the previous inventory. Returned scope, immutable identity and expiry
must match the plan. Fractional ISO expiry rounds conservatively. The independent
ledger retains metadata before the returned plaintext enters the Native adapter.
Native checks the attempt digest, purpose, repository, scope, expiry, key version,
fingerprint and operator secret/floor, then seals into the existing AES-GCM
service custody. Plaintext is not put in D1, the checkpoint, receipts, logs or
owner/workload responses. Rust keeps the parsed request and secret in zeroizing
containers; JavaScript strings have no guaranteed memory erasure.

The ledger's `custodied` state records a successful Native custody acknowledgement.
It does not certify current token validity, copy completion, readback, preparation
verification or workload release. A metadata-only `op_synchronized` check verifies
that the matching encrypted Native row still exists in captured state. Following
D1 restore, the historical custody observation remains but synchronization is
false: the gate cannot reconstruct a missing secret or remint it.

## Failure and authority loss

Lost admission, provider, Native capture or ledger acknowledgements retain the
same attempt. Repeat calls and process restarts perform no further Artifacts I/O.
A known returned bearer is revoked when validation or custody fails. A positively
acknowledged revoke can be recorded independently, including after freeze; it is
not bearer-refusal evidence and does not close the charged Native obligation.

Revocation can race a call admitted earlier. Owner or source loss after mint sends
the returned credential to encrypted revocation-pending custody and cleanup. A
retired/substituted active key prevents secret capture; metadata can still retain
the liability when Native framing is available. Frozen, pending or unavailable
checkpoints continue to fence **all Native batches**. In that case Native stays
unchanged while the independent ledger retains the observed token and qualified
revocation acknowledgement. No general checkpoint bypass is added for cleanup.

A provider mint reply lost before the token is observed may leave an active token
without plaintext. The tombstone retains the destination and charge, but this
increment adds no fresh inventory-based mint recovery broker. Even an empty
inventory or elapsed deadline cannot certify revocation/non-issuance. This must
be resolved before productive Git execution or a remote mint trial. Malformed
provider results likewise remain uncertain even if the known returned bearer was
revoked.

SQLite admission uses `transactionSync` and waits for `storage.sync()` before
returning a dispatch permit, following the [Durable Object storage contract](https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/).
The independent ledger is outside D1 restore. Restoring/resetting that ledger is
still an operator recovery/provenance problem, not something these local tests
qualify.

## Qualification

The [mint suite](../local/conformance/work-mint-gate.test.ts) covers both roles and
both scopes, concurrency, independent Node AES-GCM decryption, no plaintext in
stored/returned metadata, no preparation verification or grant issuance,
restart, whole D1 restore, permanent slot conflicts, shared capacity, cold/public
and RPC boundaries, Native key floors, incomplete/substituted inventories,
overlong expiry, lost admission/provider/capture/custody replies, pending/freeze/
owner loss before admission, and owner/source/key loss after admission.

Current local results: **28 mint cases pass**. The initial-effect suite is retained
through the [shared fixture](../local/conformance/support/work-effect-fixture.ts).
Combined regression and production build/check results are recorded in the
[integration plan](work-delegation-implementation.md). These are local synthetic
provider results, not remote Artifacts qualification or production activation.
