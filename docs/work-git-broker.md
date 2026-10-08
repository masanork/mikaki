# Private productive Git broker

M6c2 connects the [fixed copy core](work-git-copy.md) to Native encrypted custody,
independent admission and a fixed smart HTTP v1 transport. It is locally wired
only; no production binding, migration, flag, deployment or real Artifacts
resource is activated. Existing protected remote journals remain intact.

## Fixed authority and custody

The private `WorkGitBroker` accepts an opaque credential attempt, the closed copy
manifest and bounded binary request bytes. It has only `OP_GIT_STORE` and
`GIT_CHECKPOINT`; it has no Artifacts, secret, key, SQL, mint or network capability.
Caller Authorization headers, extra manifest fields and alternate destinations
are refused. Public/default handlers return 404.

The separate Native `WorkGitStore` facade admits only `/git-effect`. Other OP
facades cannot call that path; every facade denies raw administration RPC. Native
requires the feature flag, current independent checkpoint, live owner/source/
policy/preparation, exact captured observation, live expiry and the active
wrapping-key fingerprint/version. Commit and tree must match the registered
code or parentless snapshot disclosure. It fixes the destination, create-only
ref, purpose/scope, complete upload commitment and readback request in a
SHA-256 operation digest. Native repeats these checks before private custody use.

The trusted local core independently selects/hashes the complete object graph;
Native validates its registered Git roots and committed request, not the full
Git graph itself. The core and the private caller supplying it remain trusted
source-selection boundaries. No browser payload becomes copy authority.

Native decrypts only that captured credential and uses it inside the named
transport. No caller can select a bearer, wrapping key, URL or arbitrary HTTP
operation. Rust plaintext temporaries use the existing Zeroizing custody types;
JavaScript HTTP headers remain in the trusted runtime secret boundary.

## Permanent admission before transmission

The independent SQLite ledger retains one namespace/name/purpose slot. Admission
checks the current checkpoint and the independent custodied mint; it precedes
provider I/O and survives whole primary restore. The physical transport alone
can consume that send once, durably before any Artifacts or Git access. Admission
and consumption have separate capabilities; Native reads metadata only.

Lost admission/consumption acknowledgements, failed preflight, malformed replies,
process restart and repeated/concurrent requests cannot create another send.
There is no timeout reclamation, replacement attempt or retry. The existing
256-record capacity now includes permanent Git slots as well as initial effects
and mints. Readback admission also requires the same immutable manifest in a
previously consumed upload slot.

The transport repeats the checkpoint, cleanup, observation, immutable repository
identity and complete token inventory before discovery, before POST and after
response. A framed authority change prevents later I/O or success acknowledgement;
an already dispatched request cannot be recalled. Redirects, changed scope/expiry,
partial inventory and foreign identity fail closed.

## Exact Git and bounded independent readback

Discovery accepts only a bounded, complete smart HTTP v1 advertisement. Upload
requires an empty destination and `report-status`; readback requires exactly the
fixed ref/commit, with an optional matching advertised HEAD alias. Additional
refs, unsupported object format, malformed capability framing or trailing data
are refused. There is no protocol downgrade, arbitrary ref, force-update,
credential helper or inherited Git configuration.

Only the fixed create-only receive-pack body or a single fixed want/done
upload-pack request is sent. Upload returns only the exact successful unpack/ref
status; other response content is discarded. Readback returns only a bounded
SHA-1-validated pack from an exact NAK+PACK response to the trusted private
verifier. Response headers, redirects and arbitrary provider error text are
never forwarded. The provider pack is untrusted Git data, not a credential API.

The [local adapter](../scripts/work-git-broker.ts) indexes readback into a new bare
object database, then independently verifies exact refs/commit/tree, every
physical and reachable object, strict fsck and snapshot history through the
existing copy core. It fixes the Native upload/readback plan digests alongside
the payload receipt. Pack data never enters owner UI or workload token results.

This first broker buffers at most **8 MiB per request/response**, narrower than
the local copy core's 64 MiB limit. Larger prepared packs are refused before
sending; streaming/R2 transport is a later increment. The exact byte limit is
local policy, not a platform-capacity claim.

## Credential lifecycle and remaining gates

The existing mint gate requires no active token before a new mint. The local
adapter therefore requests a private readback attempt only after upload succeeds:
the trusted coordinator revokes upload, independently reconciles its known ID,
retains Native bearer-refusal closure, then mints readback. Readback cleanup uses
the same existing closure path. No simultaneous credentials or guard relaxation
is needed.

A successful copy stays `dispatched`. Its payload receipt cannot verify a Native
preparation, erase other credential charges, materialize a task, issue a grant or
release a workload credential. The next step binds both repository payload
receipts to the same preparation, closes all six obligations, and verifies that
Native preparation under current authority. Owner copy/delegation composition
and protected remote reconciliation remain separate gates.

## Qualification

`npm run test:work-git-broker` uses actual Rust/Wasm, workerd, D1, persistent
SQLite/RPC and actual Git receive-pack/upload-pack, with synthetic Artifacts and
injected local HTTP transport. Both role graphs are independently restored.
Cases cover fixed source/bytes/ref, unknown/lost replies, concurrent admission,
restart/primary restore, cold/key/source/revocation/checkpoint refusal, provider
identity/inventory substitution and attenuated capabilities. These are local
results, not remote provider or production qualification.

The transport follows [Git smart HTTP](https://git-scm.com/docs/gitprotocol-http)
and [Git pack protocol](https://git-scm.com/docs/gitprotocol-pack). Named HTTP
capability calls use [Workers service bindings](https://developers.cloudflare.com/workers/runtime-apis/bindings/service-bindings/http/).
