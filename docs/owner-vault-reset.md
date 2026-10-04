# Owner Vault reset preparation (#121)

Status (2026-10-05): source retirement is in progress on
`feat/issue-121-native-vault-retirement`, based on main `95ab1c1`, which includes
merged PR #105 and PR #125. The browser/API slice removes the legacy Vault UI
and 13 v1 HTTP routes while keeping OwnerWorkspace archive/import/search and the
record editor mounted under shared VaultSession. The native OAuth slice now
removes Vault consent, token issuance and Tauri ciphertext operations while
retaining ordinary OIDC/Identity and historical token-isolation guards. Agent v1,
historical tables/migrations, and stored data remain for later slices. No
production reset, service deletion, migration renumbering, or release is
authorized here.

## Source and ordering prerequisites

[Issue #121](https://github.com/masanork/mikaki/issues/121) replaces the historical
Vault with Owner Vault and creates a fresh deployment; it does not upgrade
existing accounts or migrate their ciphertext. Its source baseline includes the
identity features from [PR #105](https://github.com/masanork/mikaki/pull/105),
merged to main as `559a73a`; migrations 0036–0044 are present. The reset remains
blocked on the remaining Vault retirement, schema/baseline choice, RP
qualification, and reviewed production inventory.

Keep #105's identity tables and issuance paths in every intermediate build.
Resolve the execution order with [#116](https://github.com/masanork/mikaki/issues/116): if its
incremental import is performed first, record that old environment, then discard
it at this reset. If reset occurs first, #116 must use the new initialization
procedure and must not import the old 0036–0044 files. Do not edit an open PR's
identity implementation in an unrelated dirty checkout or omit it silently from
the consolidated schema.

The user selected `https://docs.mikaki.org` for the initial RP. It will share
bilingual guide/FAQ content and preserve real OIDC login, session checking,
local logout and backchannel logout. Its dedicated client, database, public JWK
and `RP_PRIVATE_JWK` secret must be included in the initialization workflow.
Do not reuse the demo's client or key. The initial Docs application prototype is
saved separately while the Owner Vault refactor proceeds; it is not a deployed
or qualified RP.

### Implementation order and scope

The user confirmed on 2026-10-04 that the #121 refactor precedes live messaging.
The implementation order is:

1. Extract shared owner authentication, CSRF/origin and mutation guards from the
   historical attribute-storage module. Preserve their existing authority and
   retry semantics while current-format callers stop importing legacy storage.
2. Connect current UserInfo/selected sharing and approved agent changes to Owner
   Vault, or explicitly retire unsupported product paths. Remove legacy UI,
   fallback, compatibility endpoints, storage, SQL and their exclusive fixtures.
3. After the final main schema includes #105, consolidate the complete supported
   schema, initial policies and release/readiness checks into one `0001`.
4. Qualify the initial Docs RP and replacement registration, retire the demo,
   rehearse the reset, then perform the separately reviewed production cutover.

### Future Docs inquiries

Guides, FAQ and published Q&A remain readable without authentication. Later
individual inquiries will be private to their author and named support
participants, with both sides able to reply. Operators will summarize and
generalize useful answers into separately reviewed public Q&A articles, without
making the original private thread or message history public.

Live E2EE messaging and inquiry submission are **follow-up work, not a #121
prerequisite or completion condition**. Do not implement a temporary plaintext
inquiry store or advertise the current encrypted owner archive as live E2EE.
The intended later application uses Mikaki's common messaging capability;
protocol/device-key binding, cryptographic state, delivery/retry and recovery
require their own implementation and qualification. See the
[messaging boundary](federated-messaging.md) and
[Vault product model](vault-product-model.md#live-e2ee-owner-archive-and-ai-recipients).

## Offline review

Run from this checkout with its pinned Node/dependencies:

```sh
node scripts/plan-owner-vault-reset.ts
node --test scripts/plan-owner-vault-reset.test.ts
```

The planner reads the checked-in production configs and applies each configured
database's SQL to disposable in-memory SQLite. It returns source/config/migration
digests, tables/indexes/triggers/views, legacy table dependencies, missing identity
tables, routes, cron schedules, bindings, and secret **names**. It never loads
secret values, connects to Cloudflare, exports user data, or changes migration
files. Exit code 2 means prerequisites remain; the JSON is a review inventory,
not a deployable baseline or evidence of the live environment. A dirty checkout
is labeled explicitly. Unknown action flags such as `--apply` are rejected.

Before production approval, obtain a fresh metadata inventory of deployed Worker
versions, service consumers, D1 IDs and ledger/schema, R2 buckets, routes/custom
domains/DNS, secret names, and scheduled writers. Use the existing
[Worker inventory implementation](../scripts/production-worker-inventory.ts) and
[release procedure](release-and-recovery.md). Check bindings for every deployed
version that can receive traffic, not only repository config. Record the
reviewed inventory's digest and timestamp. Offline configuration cannot establish
the absence of additional agent, identity-verifier, or RP deployments.

## Configuration inventory at the starting SHA

Cloudflare account: `4b749427a0c80c547e726a42aff4b6fc`.

| Resource           | Configured target                                        | Planned disposition                                                                                                         |
| ------------------ | -------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| OP Worker          | `mikaki-auth`, `auth.mikaki.org`                         | Preserve name/domain/bindings; stop writers during cutover; redeploy qualified baseline artifact                            |
| OP D1              | `mikaki-auth`, `f9299d62-2dbf-4bae-ae49-8b75674572d4`    | Reset all application state and old `d1_migrations` ledger                                                                  |
| Vault R2           | `mikaki-auth-vault`                                      | Remove all objects and any recoverable object versions/state applicable to the actual bucket; verify empty before reopening |
| Claim Worker       | `mikaki-auth-claims`                                     | Preserve key boundary; redeploy Owner Vault-only claim release                                                              |
| Claim DB authority | OP `ClaimStore` service binding                          | No separately configured claim D1; reset authority with OP DB                                                               |
| Demo Worker/domain | `mikaki-demo-rp`, `demo.mikaki.org`                      | Revoke client, stop serving/cron, then retire Worker and dedicated routes/DNS                                               |
| Demo D1            | `mikaki-demo-rp`, `ce11d383-758b-4574-8bcc-7febc505a408` | Discard sessions, transactions, logout tombstones and unused ticket data; retire dedicated DB                               |
| Demo OP client     | `77551450-ec73-4222-972d-cd912d9493d4`                   | Disable before retirement; omit from fresh seed                                                                             |
| FAQ RP             | Unresolved                                               | Provision separate RP storage/key and initialize an active OP registration                                                  |

Configured OP schedules are `* * * * *` and `*/10 * * * *`; demo cleanup is
`*/15 * * * *`. Suspend all actual writers, including older traffic-bearing
versions, before touching either DB or R2. An HTTP maintenance page alone does
not suspend scheduled events or service binding calls.

Preserve OP `OP_PRIVATE_JWK` and `MIKAKI_READY_TOKEN`, public signing metadata,
runtime policy input, MDS trust/configuration, UserInfo Secrets Store
`VAULT_USERINFO_MLKEM_A` (store `0297c270b4b74bb19f6d8d513fd280f5`), and independently
provisioned identity/agent keys and trust settings. Re-register matching public
keys after reset; do not rotate keys as a side effect of this issue. The demo's
`RP_PRIVATE_JWK` is dedicated retirement material and must not become the FAQ key.
Do not delete a shared Secrets Store when retiring a Worker.

Discard accounts, roles, credentials, invitations, enrollments, SSO and RP
sessions, authorization codes/PAR, tokens/replay state, consent/grants, Vault
heads/wraps/mutations/blobs, AI proposals/drafts/snapshots, identity documents and
wallet grants, GC cursors/candidates, and old migration ledgers. Reproduce required
public registrations, policies and trust inputs from reviewed configuration,
not from an account-data restore. Record any recovery bookmark/backup location
separately from the fresh baseline; restoring old data reverses the reset.

## Implementation boundaries before consolidation

The source retirement is staged by boundary. The default `/vault` entry mounts
`OwnerWorkspace` inside shared `VaultSession`; the v1 profile, note, passkey
transfer and AgentPanel components are removed. Thirteen v1 resource/share/release
and attribute routes return 404, including `/vault-api/attributes/:attribute`.
The native OAuth slice also removes both `/vault/oauth/consent` methods, old
Vault authorization-code issuance and Tauri ciphertext commands. Ordinary OIDC,
Identity and token-class isolation remain. Historical tables, migrations, GC
protections and live data are untouched, so this is not a completed Vault cutover.
The unmounted `OwnerVault`/`OwnerVaultSession` name-and-note qualification
preview, its exclusive browser test and the unused v1 attribute-commit UI helper
are removed in the Native follow-up. `VaultSession` and the default
`OwnerWorkspace` browser and record-commit coverage remain active.

| Surface            | Required change                                                                                                                                                                                                                             | Retain                                                                                                                   |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| Vault entry and UI | Done in this slice: remove `storage=legacy-v1` / `storage=owner-v2` selection, `VaultRouter` fallback and old profile/note/passkey/AgentPanel components                                                                                    | `OwnerWorkspace`, shared `VaultSession`, record editor, conversation archive/search, lock/draft/visibility controls      |
| OP storage         | Done in this slice: remove `/vault/attributes/*`, v1 share/release/recipient-key routes, `/vault-api/attributes/*`, and their attribute handlers                                                                                            | Owner-key wraps, opaque record heads and ciphertext storage, record release revoke and atomic commit proof               |
| UserInfo           | Record-only ClaimStore selection and recipient-secret boundary are done in merged #125; the Native retirement follow-up branch removes legacy issuance while retaining the historical-token cross-authority denial fence until expiry/reset | Recipient directory/secret boundary, record envelope, exact consent/source/authority fences and disclosure audit         |
| Agent              | Reject v1 grants and authorization details; remove legacy capability/proposal/commit routes and source predicates                                                                                                                           | Record grant/disclosure, explicit record approval, owner/session authorization, OAuth and per-operation freshness checks |
| GC                 | Remove historical attribute-prefix cleanup only with the later baseline/reset; this browser/API slice does not change GC or old data                                                                                                        | Owner record candidates and, while legacy heads remain, the live-head R2 deletion guard                                  |
| Native Vault OAuth | Done in this slice: remove consent routes, `vault.read` authorization/code issuance, old OIDC Vault profile and Tauri ciphertext commands; reject legacy inputs and preserve historical-token isolation                                     | Ordinary native OIDC/PKCE, Identity wallet/presentation, generic DPoP checks and historical retention/schema guards      |
| Demo RP            | Remove login-only mode/config/generated types, demo-only fixtures/tests and product links                                                                                                                                                   | Helpdesk/FAQ shared OIDC, CSRF, logout tombstones, session checks and help code                                          |

Do not remove a shared helper merely because its file currently has an attribute
name. The first refactor extracts owner authentication, Origin checking,
conditional revision parsing, operation IDs, hashing and authorization helpers
into `vault_http.rs`, with page/session/asset serving in `vault_ui.rs`. Owner
record and login callers no longer import these from `vault_attributes.rs`.
The removed attribute and native-consent endpoints stay absent; remaining Agent v1
protocol branches are retired in a later slice. `vault_approved.rs` supplies approval-header parsing used by
record commits. `vault-crypto.ts` supplies base64 helpers, while
`agent-crypto.ts` supplies recipient-key validation used by record snapshots.
Split those shared parts before removing old-format persistence/crypto.

Replace migration-upgrade and legacy compatibility fixtures with fresh baseline
and record-only tests. Keep denial tests for retired URLs, v1 grants/envelopes,
and old callback/token use; removing obsolete happy-path tests must not remove
the evidence that old authorization is rejected.

## Baseline contract

Consolidate the OP schema to `0001_owner_vault_initial.sql` after all source
dependencies and record-only changes are qualified. Consolidate the FAQ RP's
separate schema independently to its own `0001`; never apply RP SQL to OP D1.
The claim and agent services with OP-owned storage get no additional DB baseline.
Include every retained table/index/trigger/view and singleton policy/initial
registration. Preserve bootstrap enrollment, auth retention/capacity, Owner Vault
atomicity and revocation triggers, and the merged identity profiles.

Apply final DDL directly, rather than concatenating historical `ALTER TABLE`
files. Compare the retained schema and defaults against the frozen main schema,
and exercise its triggers with real record/share/approval fixtures. SQL must
contain no private JWK, secret seed, participant account, or ciphertext.

Fresh initialization must install the schema, reviewed environment public
registrations and active policy, and FAQ registration in one documented workflow.
RP client public key, exact callback and logout settings must be installed before
the initialized environment is declared ready. FAQ's private key belongs only
in the RP secret. Additional manual SQL or a separate enable step after successful
initialization is a failure of this issue's acceptance condition.

Reject any target with an old application table or migration ledger before
applying the baseline. Renaming `0001` or changing a ledger table is not an
upgrade: neither method permits applying fresh DDL to an old DB. The planner's
`assertFreshBaselineTarget` is tested against old ledgers, old and new Vault
tables, and unknown internal-looking tables. It is preparation for a future
executor; no current deploy command invokes it.

Update readiness/schema markers, release manifest SQL digests, upload/deploy
gates, all local fixture initializers and CI at the same boundary. Retire the
0031 reconciliation workflow/script and its incremental assumptions, and mark
old import/recovery instructions historical. Do not merge an auto-promoted
baseline artifact while production still requires the old schema. Coordinate
the existing production concurrency gate with the approved reset window.

## Cutover sequence to review before execution

1. Freeze source SHA and qualified/attested OP, claim, agent, identity and FAQ
   artifacts. Complete the fresh-empty-DB tests and source/config/resource digest
   review. Obtain explicit approval for the named D1/R2/demo destruction targets.
2. Record deployed versions, resource IDs, retained public registrations/config,
   secret references and recovery bookmark/location. Pause automatic promotion
   and all live/scheduled/service-bound writers. Verify they cannot use the DB
   or write R2 during cutover.
3. Revoke demo client authority and close its public endpoint. Discard old OP,
   RP and related session state, including migration ledgers; empty Vault R2;
   verify reset targets are fresh. Prevent participant traffic until initialization
   and every dependent artifact are ready.
4. Apply each DB's single baseline and environment public configuration/active
   policy. Initialize FAQ client and provision its dedicated RP key/config. Rebind
   preserved services if database IDs changed. Keep unknown or unconfigured
   identity profiles disabled until their actual keys/trust inputs are supplied.
5. Activate matching artifacts with maintenance still in effect; check readiness,
   full schema/ledger equality, empty old account/grant/blob state, and FAQ's
   active registration. Retire demo DB/Worker/custom domain and dedicated DNS
   only after inventory confirms they are dedicated resources.
6. Reopen traffic and schedules. Verify first enrollment/login, unified Vault
   create/save/update/search, record UserInfo/selected RP disclosure and withdrawal,
   AI review/commit and revocation, FAQ authentication/session-check/logout,
   retired demo callback/token rejection, enabled identity/wallet profiles and
   production smoke. Record actual source SHA, versions, timings and outcomes.

Before reopening, a failed cutover stays in maintenance. After reopening, rollback
must not silently restore revoked participant data or old Vault authority. A
recovery snapshot restores a complete compatible environment and must be an
explicitly reviewed separate operation. Never combine an old DB with new baseline
Workers or treat a historical production version as compatible without inspection.

## Evidence and remaining work

The initial offline rehearsal and planner tests cover current-main schema
reproduction, legacy/identity detection, configuration target separation and
fresh-DB rejection. They do not establish D1 migration execution, live writer
quiescence, actual resource deletion, first-use browser/device behavior, or FAQ
and identity interoperability. GitHub issue #121 is closed; baseline/reset/cutover
acceptance remains unverified and is tracked by this runbook and follow-up issues.

Initial verification (2026-10-04): all 56 release/migration tests passed, including
five new planner tests; strict TypeScript
checking of the planner and its tests passed; repository Markdown destination
and heading checks passed. No live metadata or participant-state inspection was
performed in this preparation step.

First dependency-extraction verification (2026-10-04): Wasm-target
`cargo check --locked --offline --target wasm32-unknown-unknown -p mikaki-worker`
passed; all 70 owner-record SQL authority/atomicity tests and five reset-planner
tests passed. Rust formatting, diff whitespace and Markdown links/headings passed.
This is a source refactor with unchanged handlers and guards; it does not retire
legacy URLs or establish browser/production cutover evidence.

Record-only UserInfo refactor (2026-10-04): the OP ClaimStore no longer selects
format-1 attributes or accepts format-1 disclosure audits. The claim Worker
removes its format-1 decoder, validation endpoint and direct D1/R2 local-test
fallback. The recipient key, generation and service bindings are preserved.
Legacy heads/grants/consent are ignored before any recipient secret or blob is
read. The superseded format-1 live suite is replaced by record-v2 qualification,
including real local Secrets Store, Node/browser encryption, selected RP consent,
postdecrypt withdrawal, audit failure, missing key binding, broken authority,
transport outage, and altered/missing ciphertext. These changes affect source
behavior only; they are not a production deployment or reset.

Verification for this slice: 133 owner-record/UserInfo SQL tests, three recipient
Rust tests and five actual-Worker/browser/service-boundary tests passed. The full Worker-contract suite (40 tests) and record sharing/approval
suite (42 tests) also passed after aligning recipient-directory and readiness
fixtures with the same named authority. OP and
recipient release artifacts and the conformance recipient artifact built.
Service-authority and targeted strict Node TypeScript checks passed. The broad
Node check requires the separate probe dependencies and browser Wasm/generated
policy outputs, which are not installed/generated in this worktree; no errors
were reported for the changed files. The browser/API retirement and record-only
ClaimStore are complete in source. At the time of this record-only UserInfo
verification, remaining work included native Vault authorization/consent, Agent
v1 grant/proposal paths, the later baseline/reset, and production verification.
The current native OAuth retirement is recorded below; remaining source work is
Agent v1 retirement, followed by baseline/reset qualification and production
verification.

Browser/API retirement verification (2026-10-05, branch
`feat/issue-121-legacy-vault-retirement`): release Worker artifacts regenerated
with `worker-build --release crates/worker`; `worker-ui.test.ts` and
`vault-owner-workspace-browser.test.ts` passed (3 tests), preserving the default
OwnerWorkspace profile/record flow, conversation import/search, deletion and
scope clearing, session lock/reopen, and reload behavior. `product-journey.test.ts`
and `legacy-vault-retirement.test.ts` passed (2 tests), including a real
Passkey/PRF journey and 13 retired-route 404 assertions. `npm run
check:worker-ui` passed with zero errors or warnings. This slice changes source
only: no production deployment, database reset, historical migration change, or
live participant-data deletion was performed.

Native OAuth retirement verification (2026-10-05, follow-up branch
`feat/issue-121-native-vault-retirement`, not merged/deployed): source removes the
old consent routes, `vault.read` authorization/code issuance and native Tauri
ciphertext operations while retaining ordinary OIDC/Identity and historical
token-class isolation. `worker-build --release crates/worker`, Tauri host and
Android native-dpop host checks, and focused Native/DPoP/Identity/mobile UI
contracts passed. This branch change has not deployed, reset a database, or
removed historical Vault tables or stored data.

Unused UI cleanup in the same follow-up removes 459 lines of unmounted preview
and legacy commit source plus 1,118 lines of exclusive tests. Worker UI type/Svelte
checks passed with zero errors or warnings; source boundaries and documentation
checks passed. The mounted Workspace, shared controller and v2 approval suite
remain. The integrated Native source also passed all 259 SQL contracts.
