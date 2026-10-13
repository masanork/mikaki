# One-shot Artifacts mint and Native custody

M6a connects the existing six-slot credential journal to a private upload/readback
mint gate on current main. Copy upload, independently verified Git readback,
workload credential release and owner copy/delegation controls remain open.
Production flags, bindings, resources and baseline migrations remain unchanged.
The protected remote journals and their six empty development repositories are
untouched. This increment uses synthetic Artifacts over actual Workers RPC and
persistent SQLite, together with the actual Rust/Wasm OP and D1.

## Initial operator key registration

The named `OpAuthorityAdmin` capability accepts `inspect-work-credential-key`
with `key_version`, and `initialize-work-credential-key` with `key_version`
and `expected_fingerprint`, through its existing private POST `/authority`.
Both require enrolled, current independent authority and
`WORK_CREDENTIAL_KEY_ADMIN_ENABLED=true`. Production enables this private initial
registration capability with version floor 1 and a required secret binding;
copy execution remains disabled. Deployment does not register the key automatically.
Public HTTP and raw Wasm RPC remain closed. The request never carries key bytes;
Native reads only the already provisioned `WORK_CREDENTIAL_KEY_V<version>`
secret and verifies its fingerprint and `WORK_CREDENTIAL_KEY_FLOOR`.

Initialization inserts only into an empty key ledger. The exact active key can
be read on retry, without another audit or authority frame. Any different
existing, decrypt-only or retired key prevents initialization; this capability
cannot rotate, retire or replace a key. The first insertion and existing
`work_credential_key_audit` record commit in one checkpoint-covered transaction,
and audit failure rolls both back. Responses contain only version, fingerprint
and state, with `Cache-Control: no-store`.

Provisioning and retained external secret custody still precede registration.
They must preserve the existing OP secrets and its complete deployment
configuration. Neither successful registration nor an inspected fingerprint
establishes that external custody is recoverable, enables copy execution or
authorizes an agent. No provider credential, repository, grant or run is created.
The Work product CI suite qualifies this Native path, concurrent/exact retries,
fingerprint/input/floor/secret refusal, audit rollback and frozen/unenrolled
authority alongside the existing custody and public-boundary tests.

## Fixed authority and admission

The [Native adapter](../crates/worker/src/work_effect.rs) accepts an opaque attempt
ID for a plan; callers cannot select a repository, scope, URL, TTL or wrapping
key. [Native plan derivation](../crates/worker/src/work_store/credentials.rs) binds
that journal's preparation digest, role, destination, immutable repository ID,
absolute deadline, fixed short mint expiry, purpose, current checkpoint and active key fingerprint/version.
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
binding, the separate `WorkMintStore` Native adapter and this mint-only ledger.
Native mint actions require `/mint-effect` and `WORK_MINT_STORE_ENABLED=true`;
initial actions retain `/effect` and their own flag. Each named facade rejects
the other path, and Native rejects actions crossing those paths. Public, admin,
initial-effect and mint facades all refuse raw administration RPC. Its implementation
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
scope (`write` for upload, `read` for readback), with a TTL below the independently retained Native expiry
(`min(preparation deadline, plan time + 300 seconds)`). A repeated plan cannot
replace that retained expiry or issue another permit. The installed Workers binding and
[official API](https://developers.cloudflare.com/artifacts/api/workers-binding/)
use `createToken(scope, ttl)` and disposable repository capabilities.

A matching fresh inventory must identify exactly the returned active token and
preserve the previous inventory. Returned scope, immutable identity and expiry
must match the plan. Fractional ISO expiry rounds conservatively. The independent
ledger retains returned metadata before later provider validation and before
the returned plaintext enters the Native adapter. Wrong-scope/overlong results
are retained only as safety observations; they cannot enter productive custody
or acquire a refusal closure for this plan.
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
A known returned bearer is revoked when validation or custody fails. Cleanup intent is retained before revocation and prevents a late custody
acknowledgement from reopening that attempt. A positively acknowledged revoke
can be recorded independently, including after freeze; it is not bearer-refusal
evidence. Closure additionally requires explicit Git 403 for the same plaintext,
unchanged immutable repository identity, and a complete fresh token inventory
matching the observed ID/scope/expiry within the fixed plan. A lost revoke reply
can still be followed by that concrete refusal. Redirects, success, transport
errors and mismatched/incomplete inventories cannot close an obligation.

The independent closed record retains the domain-separated refusal digest.
Native repeats the same observation and closes its existing credential journal
without reconstructing or releasing plaintext. `op_synchronized` is false while
frozen/pending framing or an old D1 marker prevents that metadata synchronization.
Retrying a retained closure performs no Artifacts/Git I/O.

Revocation can race a call admitted earlier. Owner or source loss after mint sends
the returned credential to encrypted revocation-pending custody and cleanup. A
retired/substituted active key prevents secret capture; metadata can still retain
the liability when Native framing is available. Frozen, pending or unavailable
checkpoints continue to fence **all Native batches**. In that case Native stays
unchanged while the independent ledger retains the observed token and qualified
revocation acknowledgement. No general checkpoint bypass is added for cleanup.

A provider mint reply lost before the token is observed may leave an active token
without plaintext. The tombstone retains the destination and charge. Subsequent
[M6b known-ID recovery](work-artifacts-mint-recovery.md) can revoke only the token
ID already observed for that operation. It cannot attribute an unobserved ID from
inventory, even with exactly one matching active token. Empty inventory, an
expired state or an elapsed deadline cannot certify revocation/non-issuance.
Unobserved outcomes and full credential-backed productive use remain qualification gates
before productive Git execution or a remote mint trial. Malformed provider
results likewise remain uncertain even if the known returned bearer was revoked.

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

Current reconciled local results: **33 mint cases pass**. The initial-effect suite is retained
through the [shared fixture](../local/conformance/support/work-effect-fixture.ts).
Combined regression and production build/check results are recorded in the
[integration plan](work-delegation-implementation.md). These are local synthetic
provider results, not remote Artifacts qualification or production activation.

The current `token.mint` protocol keeps the independent initial-effect closure
and Native key fingerprint from `45a0102`, and incorporates the separate mint
facade, retained short expiry and refusal closure from the parallel
`feat/work-productive-mint` prototype (`bb73f1d`, `b19913d`). That older branch is
retained; its separate `token.create` protocol is superseded by this one contract.

Known-ID safety recovery is integrated through the mint-only Native adapter;
its control-plane evidence remains distinct from the explicit Git-refusal
closure above. The recovery broker holds only `WorkMintLookup`; it cannot close
a Native obligation, custody a secret or admit a new mint.
