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
their committed project inputs, dependency lockfiles and tool versions. Project
modules are read against the selected Git commit during bundling. Every bundle
has only the Cloudflare runtime import remaining. Keep the returned source and
manifest digest outside the packet; verification requires those exact values
and rejects changed, missing, additional, linked or source-substituted members.

This is a local byte inventory, not a signed release, target configuration or
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

## Validation

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
