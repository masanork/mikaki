# Operator registration of a code snapshot

The first production trial uses committed mikaki files without the original Git
history. The selected main history is about 162 MB, above Work's 64 MiB code
capacity. A parentless code snapshot preserves its exact Git tree and contains
one reachable commit. Its owner-visible label explicitly excludes earlier
history. This is an actual source choice, not a claim that full mikaki history
was copied or qualified.

`prepare:work-code-source` reads an exact commit, verifies its Git identity,
copies only its tree into an independent bare repository and hashes every
reachable object. The immutable packet retains the selected original commit,
snapshot commit/tree, closed source metadata and a Git bundle with SHA-256
digests. Verification restores that bundle into another independent repository,
checks it against the original committed tree, runs Git fsck and refuses extra
refs, physical objects or original ancestry. It reads no uncommitted files.

The retained bundle is the operator's registered Git source. The code source
name is a logical registry identity; registration does not assert an Artifacts
repository was created. Context repositories still need a separately configured
private source reader and owner access. Code-only composition does not call that
reader or inspect personal/Vault content.

## Private Native registration

Only the existing named `OpAuthorityAdmin` service accepts the bounded
`register-source` and `inspect-source` operations. Public HTTP and raw RPC remain
closed. Registration accepts validated code metadata at revision one plus a
current owner epoch. The operator must first independently verify Git bytes;
the Native metadata constructor does not establish that external observation.

Native commits source version, head, owner access, source audit and Work audit in
one checkpointed batch, repeating active-owner/epoch checks at commit. No new
migration is needed. Exact retries read identical active retained metadata and
do not add a frame or audit. Different metadata, another owner, changed epochs,
retired authority and frozen checkpoints are refused. Registration creates no
preparation, copy consent, provider credential, grant or run.

The fixed production CLI requires a successful full main run, its exact clean
source and the corresponding active production Worker with the existing D1 and
named checkpoint binding. It selects the sole active administrator and retains
a private, synchronized intent before the single registration request. Its
global reservation cannot be reminted from another checkout. After a missing
reply, use read-only inspection; never repeat registration automatically.

```sh
npm run prepare:work-code-source -- .git EXACT_MAIN_COMMIT local/generated/work-code-source
node scripts/register-work-code-source.ts inspect PACKET SUCCESSFUL_MAIN_RUN
node scripts/register-work-code-source.ts register PACKET SUCCESSFUL_MAIN_RUN
```

Production composition and explicit copy consent are enabled for the trial's
fixed account/namespace and `mikaki-work-test` planning identifiers. Those names
identify the proposed trial; they establish no issuer or launcher assurance.
The real owner must log in, create a preparation and separately confirm the
reviewed copy. Operator registration supplies none of those confirmations.
Copy execution, credential issuance and AI delegation remain disabled pending
their productive provider/host and launcher qualification.

## Prepare the code-only copy host

On source review, select the registered repository with **Choose this code for
copying**. The file/byte count refers only to optional context files. With no
context, **Inspect selected files** stays disabled and **Prepare copy** is the
next action after choosing the code.

Composition retires only the current owner's expired, never-dispatched
reservations that have no copy job, credential attempt, registered destination,
prepared task or candidate payload. Native transitions and independently
checkpointed audits retain the old identity/body while releasing its byte charge.
An expired queued job or any external obligation keeps its reservation pending
its existing reconciliation and cleanup protocol.

After the owner creates a code-only preparation, open its review and use **Save
disclosure record** under **Integrity records**. The browser rechecks the live
owner session, exact selected preparation, current source revisions and expiry
before downloading the closed Native record. It contains metadata only, without
file contents, login credentials or copy consent. The opt-in WebMCP
`mikaki_read_work_disclosure` tool returns the same record through the same
fresh checks; hiding, locking or changing selection refuses a late result.

Retain that exact current Native disclosure review. The local bridge accepts it
and the original source packet; it derives the source binding rather than
accepting arbitrary repository paths.

```sh
npm run prepare:work-code-copy -- NATIVE_DISCLOSURE_REVIEW SOURCE_PACKET OUTPUT_PARENT
```

The bridge independently restores the retained bundle and checks its selected
tree, single snapshot commit and all code inventory facts against the Native
review. It provisions the existing sealed Git registry and code-only Linux image
context, with separate task and empty-context snapshot packs. A changed packet,
expired or stale review, different source revision or context-bearing review is refused.
Changes to the packet's mutable `source.git` cannot add unselected objects.
The immutable `code-copy-receipt.json` records the source/bundle, disclosure and
registry digests without owner credentials or consent.

This prepares local input bytes. The review is a projection, not independent
authorization or proof of current owner consent. Host deployment still needs
private R2 provisioning, exact version/image/binding observations and an enrolled
authority. Productive copying additionally needs the Workflow, fixed effect/mint/
Git gates and active wrapping-key custody. Native repeats source/session and
consent checks when executing; no local package enables those capabilities or
reconciles protected unknown provider outcomes.

## Freeze the copy companion runtime inputs

Before attaching a real disclosure or enabling productive copy, prepare the
companion Worker bytes from a clean committed checkout:

```sh
npm run prepare:work-copy-runtime -- local/generated/work-copy-runtime
npm run verify:work-copy-runtime -- PACKET_DIRECTORY RETAINED_MANIFEST_SHA256 SOURCE_COMMIT
```

The packet contains fourteen actual companion bundles (Workflow, initial/mint/Git
and maintenance/refusal/composition gates, private Git host and checkpoint),
their committed project inputs, dependency lockfiles, consumed dependency files,
package metadata, registry archives and tool versions. Project modules are read
against the selected Git commit during bundling. Dependency bytes and resolution
metadata are compared with the archive whose SHA-512 integrity matches the lock.
Archives come from npm cache with `--offline --ignore-scripts`; a missing cache
entry refuses preparation. Every bundle
has only the Cloudflare runtime import remaining. Keep the returned source and
manifest digest outside the packet; verification requires those exact values
and rejects changed, missing, additional, linked or source-substituted members.
Traversal is bounded to 768 entries, 12 path levels and 64 MiB total; dependency
verification repeats lock/archive/file checks after the member inventory.

The release-candidate pipeline now packages these same verified bytes in
`artifacts/work-copy-runtime/mikaki-work-copy-runtime.tar.gz` and binds the archive,
runtime manifest and exact source in `release.json`. The separate supply-chain
job independently restores/rechecks the packet before attesting both files
alongside the existing OP/checkpoint release. Both attestations still need
verification against the intended repository, workflow, main ref and source
commit before treating the inputs as authentic. Local `verify:work-copy-release`
performs integrity checks and explicitly reports authenticity unverified; it
does not verify a signature or authorize deployment. The signed checkpoint
deployment archive remains separate from the companion packet's local checkpoint
reference bundle. Existing promotion continues to activate only the existing
OP/Claims/checkpoint release; it does not deploy any copy companion.

Outside CI, `npm run prepare:work-copy-release -- artifacts/work-copy-runtime`
creates the same exclusive release directory. Recheck the retained receipt digest
and source with `npm run verify:work-copy-release -- RELEASE_DIRECTORY
RECEIPT_SHA256 SOURCE_COMMIT`. Archive extraction follows bounded decompression,
complete path/type/duplicate checks and the original runtime/dependency verifier.
No source pack, owner record, credential or Container image enters this archive.

The local packet alone is a byte inventory, not a signed release, target configuration or
remote runtime observation. It contains no OP Wasm, owner disclosure/consent,
source packs, Container image or provider credentials. The matching attested OP,
current Native disclosure/source packet, sealed image/R2 supply, actual private
resource/version/binding observations and active wrapping-key custody remain
required before activation. Copy and AI execution permissions remain absent.
The [first productive-copy Issue #200](https://github.com/masanork/mikaki/issues/200)
tracks those separate gates.

`npm run test:work-copy-runtime` builds the real companion bundles and checks
public and named cold admission in local workerd without provider bindings. It
also qualifies retained-digest rejection of byte/manifest substitution, unknown
members, symlinks and attempts to relabel the packet as execution authority.

## Retain the private copy binding plan

After freezing runtime bytes, use `copyBindingTargetSchema` in
`scripts/work-copy-binding-plan.ts` to prepare a closed, secret-free target
review. It names the account/authority/Artifacts namespace, thirteen companion
service names through a prefix, the existing OP and checkpoint versions, an OP
source/attestation digest, checkpoint namespace/object, sealed host
disclosure/registry/image digests and private R2 bucket, and wrapping-key
version/custody review references. The OP source must equal the runtime source.
Service names must be distinct. Keep the exact review SHA-256 outside the packet.

```sh
npm run prepare:work-copy-bindings -- RUNTIME_PACKET RUNTIME_SHA256 SOURCE_COMMIT TARGET_REVIEW TARGET_SHA256 local/generated/work-copy-bindings
npm run verify:work-copy-bindings -- BINDING_PACKET RETAINED_MANIFEST_SHA256
```

The exclusive child retains the entire verified runtime packet byte for byte,
the target review and the canonical 36 named service bindings. It specifies all
eight copy orchestration bindings, independent preparation/Git/dispatch/refusal
capabilities, narrowly scoped checkpoint lookup/maintenance gates, Workflow and
private host resource expectations. Its whole inventory uses the runtime
packet's entry/depth/aggregate-byte bounds. Verification is portable without
the original runtime directory, rechecks dependency integrity and refuses
changed graph/authority even if a caller rewrites the child inventory. The
binding format follows [named service entrypoints](https://developers.cloudflare.com/workers/runtime-apis/bindings/service-bindings/rpc/).

This is an offline graph plan, not a deployable full OP/Container configuration,
an attestation verifier or provider observation. Target versions, sealed supply
and custody references remain claims until independently compared with their
retained evidence and actual provider state. The existing checkpoint receives
no redeployment/bootstrap authorization. Productive flags remain false, public
routes and cron triggers remain empty, and no secret value or credential is
included. Current Native disclosure/source, OP attestation, sealed host/R2/image,
active wrapping custody, actual bindings and owner consent remain required for
#200's live copy/readback/closure acceptance.

`npm run test:work-copy-bindings` runs portability, privilege/target/secret/link
substitution cases and loads every companion destination's named entrypoint in
local workerd with disabled gates. Its OP transport is a closed fixture; this
qualifies companion cold admission, not OP Wasm or any live owner/provider.

## Validation

### Closed companion configuration inputs

After reviewing a binding packet, materialize its thirteen companion Worker
configurations into a new exclusive child:

```sh
npm run prepare:work-copy-configs -- BINDING_PACKET BINDING_MANIFEST_SHA256 local/generated/work-copy-configs
npm run verify:work-copy-configs -- CONFIG_PACKET CONFIG_MANIFEST_SHA256
```

The child retains the full binding/runtime packet. Each `configs/ID/wrangler.json`
points only to those frozen bundled bytes with bundling and additional-module
discovery disabled. All productive flags remain false; routes, cron triggers,
workers.dev and previews remain closed. Existing checkpoint and OP configurations
are not emitted. `deployment-inputs.json` records the required OP changes against
its expected existing version; applying them still requires preserving the
complete existing OP configuration, services, routes, resources and secrets.
No shared checkpoint namespace is allocated or bootstrapped by this preparer.

Workflow, Artifacts namespace and private R2 bindings follow the canonical graph.
The host uses its own service name as the image repository and a digest-pinned
Cloudflare Registry reference, with the `durable_object` scheduling policy and
the SQLite `GitHostContainer` export. SSH is disabled. See [named Container
images](https://developers.cloudflare.com/containers/guides/image-management/).
Local remote resource access is disabled. Configuration verification re-derives
every field and refuses additional capabilities, mutable images, different
entry bytes, ingress, execution or rewritten checkpoint/OP claims even after
member hashes are rewritten. The inherited inventory bounds still apply.

The image digest must identify the provider's registry manifest. A Docker image
ID or build output alone is not a verified Cloudflare Registry observation.
This child includes no sealed source packs, image layers, runtime secrets or
owner authorization, and performs no provider operation. Existing target/custody
claims and all live copy/readback/closure prerequisites remain unresolved.
The binding test suite runs thirteen dry runs with the pinned Wrangler, confirms
the output entry bytes are unchanged, and generates host binding types. Cloudflare
API access is directed to a closed loopback endpoint during those tests.

The packet test restores real Git objects independently and proves history
exclusion. The product test runs the actual Rust/Wasm, D1 and SQLite checkpoint:
registration/retry, owner projection, public code-only composition, stale and
foreign authority, audit rollback and frozen/public refusal. Existing Git
disclosure and public service-boundary tests retain their coverage. These local
fixtures use disposable identities; production registration needs the qualified
deployed source and actual existing owner.

`npm run test:work-passkey-e2e` runs the complete code-only owner journey in
Japanese on a desktop viewport and English on a mobile viewport. A local HTTPS
bridge serves the product Rust/Wasm OP and its real SQLite checkpoint. Chromium's
CTAP2.1 virtual authenticator performs enrollment, a new login after logout, and
PRF Vault unlock; the test injects no credential, SSO cookie or WebAuthn result.
The private operator registers an independently verified Git snapshot for that
new owner, then the browser selects it, creates a preparation, inspects the
review and explicitly approves the copy. Database assertions bind the consent
to the actual login session and exact preparation, keep reload read-only, and
verify logout invalidation and rejection of a replay with the revoked SSO.
The final checkpoint matches D1. Copy jobs, provider credentials, task
repositories, grants and runs remain absent. External Artifacts copying and AI
execution are outside this journey. The required `work-product` CI lane runs it
alongside the existing component and failure-path tests and retains browser
failure traces for these disposable local fixtures.

`npm run test:work-code-copy` runs real local Native source registration and
code-only public composition, then restores the sealed host packs independently.
It verifies original-history and unselected-object exclusion, source binding and
stale/mismatched refusal, with no owner consent, provider credential or productive
effect. The case also runs in the Work product CI lane.
