# Fixed Git copy payload and independent readback

M6c1 provides the trusted local copy core in
[work-git-copy.ts](../scripts/work-git-copy.ts). It performs no network I/O,
credential decryption, Native admission, preparation verification or grant
issuance. The private productive broker remains the next integration step.

## Fixed bytes

`PreparedGitCopy.prepare` accepts a pinned SHA-1 commit/tree and the task or
snapshot role. It uses the existing trusted source inspection to reject shallow,
grafted, alternate and promisor repositories. It independently hashes every
reachable object and fixes the inventory before packaging. Task copies preserve
the selected code history. Snapshot copies require a parentless commit; selected
context paths are supplied by the existing disclosure adapter.

The pack contains the explicit verified object list, with no revision expansion,
unrelated refs/tags, thin-pack bases or reused deltas. The existing 65,536-object
and 64 MiB object budget applies; the complete pack is also bounded to 64 MiB.
The immutable manifest binds the commit, tree, inventory, pack and exact upload
request with SHA-256 commitments. Callers receive copies of the request bytes.

The protocol-v1 request creates only `refs/heads/work` or
`refs/heads/snapshot`, with an all-zero old object ID. An existing destination
ref is refused rather than overwritten. Before real transmission, the broker
must independently admit the fixed operation and confirm the provider advertises
the required `report-status` capability. Pack generation and status parsing
follow the [Git pack protocol](https://git-scm.com/docs/gitprotocol-pack) and
[pack-objects contract](https://git-scm.com/docs/git-pack-objects).

## Acknowledgement and readback

The bounded status parser accepts exactly successful unpacking, the one fixed
ref acknowledgement and a final flush. Missing, truncated, mismatched, additional
or trailing status data remains unknown. A valid response produces only
`uploaded_unverified`; it does not prove content, current authority or credential
closure and cannot trigger a retry itself.

Independent readback uses a fresh bare object database from the transport. It
repeats trusted repository inspection, exact-ref/commit/tree verification,
independent object hashes, complete reachable inventory and strict Git fsck.
The physical received object inventory must also match, so an unsolicited
unreachable object cannot hide behind the correct visible branch. Snapshots
must contain one root commit. The result commits to the fixed upload manifest
and the observed Git facts in a domain-separated payload receipt.

These checks describe the received object database. They cannot certify objects
or refs withheld by a provider. The productive broker must qualify complete
remote ref discovery and immutable repository identity separately. Its Native
adapter must bind the payload receipt to the exact preparation and require all
six credential slots to close before preparation verification. A local receipt
is never owner consent, a credential getter or workload authority.

## Qualification

`npm run test:work-copy` passes **17 cases** in
[work-git-copy.test.ts](../scripts/work-git-copy.test.ts). Actual Git receive-pack
consumes the generated body, then actual Git fetch restores into an independent
fresh repository. Both roles preserve the exact selected graph. Tests cover
required code history, exclusion of unselected context/history and unrelated
source refs, create-only retry refusal, unexpected received refs/objects,
malformed status, source restrictions and immutable request commitments.

No real Artifacts repository is read or written. Deployment bindings, protected
remote journals, token releases and the owner copy/delegation flow remain outside
this increment.
