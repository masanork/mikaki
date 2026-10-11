# Fixed upload and independent Git readback

M6d connects encrypted Native custody to one fixed productive Git exchange per
upload/readback mint. Local qualification uses actual Rust/Wasm/workerd/D1,
persistent independent SQLite/RPC and a loopback Git smart-HTTP server backed by
real `git http-backend`. Artifacts metadata and credentials remain synthetic.
Production flags, bindings, baseline migrations and protected remote journals
are unchanged. This is not remote Artifacts qualification or production activation.

## Authority and single dispatch

The [Native plan](../crates/worker/src/work_store/credentials.rs) derives the
repository, purpose/scope, branch, commit/tree, disclosure/preparation digests,
observed token/expiry and wrapping-key generation from captured primary custody
and the registered disclosure. Current owner epoch, source access/head, policy,
preparation state, key/fingerprint/floor and independent OP checkpoint are checked.
Only SHA-1 Git repositories are supported by this increment. Inputs cannot select
a URL, local directory, ref, pack, token or wrapping secret.

The [opaque gate](../crates/work-effect-worker/git.ts) accepts only an attempt ID
on a named private binding; the default handler returns 404. Its distinct Native `WorkGitStore` facade uses `/git-effect`, while cleanup
uses the separately bound mint-only facade. Its independent
checkpoint records one immutable Git plan inside the existing permanent mint
slot and synchronizes storage before acknowledging admission. No extra slot can
be obtained by primary rollback or a new attempt ID. Capacity remains the shared
256 initial/mint records; each mint holds at most one bounded Git result.

Native consumes `admitted → dispatching` through a separately bound execution
checkpoint before emitting a bearer. The physical transport consumes
`dispatching → outcome_unknown` before calling the Git host. Both transitions
check the exact current checkpoint, pending/frozen state and release floor and
wait for durable storage synchronization. Losing either acknowledgement leaves
the consumed slot in place and permits no retry of external execution.

Native decrypts only captured custody under the current active operator key;
it repeats primary authority and encrypted-row checks around decryption and
service waits. The secret goes only into the Authorization header of the fixed
named transport request. There is no public credential getter or global-fetch
fallback. Rust owns zeroizing secret/header buffers; JavaScript strings do not
guarantee memory erasure. The transport and Git host are trusted secret-bearing
components and need private ingress with no header/body logging.

The [physical bridge](../crates/work-effect-worker/git-transport.ts) checks the
independent Git plan, exact Artifacts ID/name/remote/default branch/initial-attempt
description and complete bounded token inventory before and after the host call.
The stored observed token must be the only active token and match scope/expiry.
It returns bounded closed result metadata, never an Artifacts capability, bearer,
Git response body or arbitrary host error. Callers cannot select the executor URL.

## Actual Git data

The [trusted host adapter](../scripts/work-git-executor.ts) uses an explicit,
immutable registry keyed by disclosure digest and role. A registered directory
must independently match Native's commit/tree and supported full Git source
rules. The code copy includes exactly the reachable history; the snapshot source
is the previously built selected-content repository with one parentless commit.
There is no checkout, import/fork, source discovery, persistent credential helper,
remote configuration, hook, tag/mirror upload or owner-supplied command.

[Upload](../scripts/work-git-upload.ts) checks an empty receive-pack advertisement,
builds the exact commit closure using local `pack-objects`, and sends a create-only
update from the all-zero old OID to the fixed branch. It uses one explicit HTTPS
POST with a fresh non-pooled connection, TLS verification, absolute timeout,
bounded response, no redirects and no retry. Only a strict `unpack ok` and exact
branch `ok` report yields `git_push_accepted`. This acknowledgement does not verify
the remote copy. HTTP 200 alone is insufficient. Qualification discovered that
Git CLI push can internally resend after response loss; productive push therefore
does not use that CLI transport.

[Readback](../scripts/work-git-readback.ts) uses a separate read credential only
after the same repository's independent upload result and strong bearer-refusal
closure are retained. It checks the exact complete advertised branch set, fetches
the fixed commit without thin-pack/sideband negotiation, and checks the refs again.
The response pack is bounded to 70 MiB and 65,536 objects. Preflight verifies its
checksum, framing, object types, offsets, compressed/decompressed entry sizes and
delta source/target sizes; both total inflated entries and reconstructed objects
are limited to 64 MiB before Git indexing. REF and OFS delta packs are supported;
Git performs the actual delta reconstruction and object/hash consistency checks.

The pack enters a fresh bare object database without alternates, source objects
or preexisting refs. `index-pack --strict`, complete independently hashed object
inventory comparison, exact commit/tree/ref checks and `fsck --full --strict`
must pass. Pack entry count must equal the verified reachable object count, so
extra unreachable packed objects cannot be accepted as copy evidence. Snapshot
readback additionally requires one parentless commit. Raw remote data and
temporary files remain in the private host and are removed after the check.

The SHA-256 receipt commits to the exact plan and measured metadata. It is a
trusted adapter commitment, not a provider signature or public attestation.
Private result-recording bindings are part of this trust boundary. A retained
`completed` readback does not grant workload access or mark the whole preparation
verified; that requires combining both roles and all six strong credential closures.

## Cleanup, loss and remaining deployment

Success or uncertainty durably requests mint cleanup before Native metadata
synchronization. M6b/M6c perform exact known-ID revocation, fixed bearer refusal
and encrypted-custody closure. The independent Git result and permanent slot
survive that cleanup, restart and D1 restore. An `admitted`, `dispatching` or
`outcome_unknown` phase is historical dispatch evidence, not a new permit or proof
of non-issuance. Retries reconcile metadata only. Lost successful upload/Native
replies cannot be reclassified as success from a populated ref or empty token list.

All Native batches, including cleanup, still require OP checkpoint framing.
Independent safety/result recording can continue after freeze while Native stays
unchanged. Owner/source/key loss can reject results after an external effect was
accepted; it cannot erase already delivered bytes. Concurrent retries may cancel
an in-flight attempt into cleanup, but cannot obtain a second send.

The original Git host factory was qualified through a private Miniflare host
capability. The [private host increment](work-git-host.md) now adds a bounded
Linux listener, exact Native source registration, private R2 provisioning and
Cloudflare Container configuration with retained host admission. Its local
Linux/R2 qualification does not establish remote Container execution or
Artifacts behavior. The Workers bridge alone does not make Node child processes
available in Workers.
Protected existing remote allocations must be reconciled before a real trial.
M6e now [composes both-role evidence and six Native closures](work-preparation-evidence.md)
into verified preparation. Owner copy/delegation consent, workload token release
and unobserved/missing-custody recovery remain separate gates.

## Qualification

[24 Git gate cases](../local/conformance/work-git-gate.test.ts) cover task history,
selected parentless snapshot, one upload and independent fresh readback, sequential
refusal closure, restart/whole-D1 restore, lost accepted push/Native/admission/
consumption/result replies, redirects/unavailability, malformed reports, corrupt
packs, extra refs, before/after-admission owner/source/key/checkpoint loss,
immutable metadata substitution, absent upload evidence and opaque/RPC boundaries.
[Three pack cases](../scripts/work-git-pack.test.ts) additionally exercise malformed
bounds/compression/checksums and real strict indexing of REF/OFS delta packs.
Run `npm run test:work-delegation` for the integrated regression; final build and
boundary results are recorded in the [implementation plan](work-delegation-implementation.md).

Protocol references: [Artifacts Git API](https://developers.cloudflare.com/artifacts/api/git-protocol/),
[Git smart HTTP](https://git-scm.com/docs/gitprotocol-http),
[Git pack format](https://git-scm.com/docs/gitformat-pack),
[Node zlib bounds](https://nodejs.org/api/zlib.html),
[independent SQLite storage](https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/).
