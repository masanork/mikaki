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
