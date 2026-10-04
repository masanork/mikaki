# Owner Vault reset preparation (#121)

Status: preparation only. No production reset, service deletion, migration
renumbering, or release is authorized by this document. The implementation branch
starts at main `967cbc52d639fc2499b65137626680b2e0e0cc37` (2026-10-04).
The existing development checkout is untouched.

## Source and ordering prerequisites

[Issue #121](https://github.com/masanork/mikaki/issues/121) replaces the historical
Vault with Owner Vault and creates a fresh deployment; it does not upgrade
existing accounts or migrate their ciphertext. Its source baseline must include
the identity features from [PR #105](https://github.com/masanork/mikaki/pull/105).
At the starting main SHA, #105 is still open and identity migrations 0036–0044
are absent. Main has 0001–0035 and 0045–0046. A successful rehearsal of those
37 files is not proof that the identity schema is included.

Integrate and qualify #105 before freezing the reset baseline. Resolve the
execution order with [#116](https://github.com/masanork/mikaki/issues/116): if its
incremental import is performed first, record that old environment, then discard
it at this reset. If reset occurs first, #116 must use the new initialization
procedure and must not import the old 0036–0044 files. Do not edit an open PR's
identity implementation in an unrelated dirty checkout or omit it silently from
the consolidated schema.

The FAQ RP has no identified production configuration in the starting main.
Before building its seed, establish the exact HTTPS origin, client ID, separate
D1 database, redirect URI, logout/session-check destinations, public JWK, and
private-key secret reference. The current Helpdesk implementation includes help
articles and ticket routes; confirm whether this is the intended FAQ application.
An invented FAQ domain, placeholder key, or reuse of the demo client is not a
production registration.

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

| Resource | Configured target | Planned disposition |
| --- | --- | --- |
| OP Worker | `mikaki-auth`, `auth.mikaki.org` | Preserve name/domain/bindings; stop writers during cutover; redeploy qualified baseline artifact |
| OP D1 | `mikaki-auth`, `f9299d62-2dbf-4bae-ae49-8b75674572d4` | Reset all application state and old `d1_migrations` ledger |
| Vault R2 | `mikaki-auth-vault` | Remove all objects and any recoverable object versions/state applicable to the actual bucket; verify empty before reopening |
| Claim Worker | `mikaki-auth-claims` | Preserve key boundary; redeploy Owner Vault-only claim release |
| Claim DB authority | OP `ClaimStore` service binding | No separately configured claim D1; reset authority with OP DB |
| Demo Worker/domain | `mikaki-demo-rp`, `demo.mikaki.org` | Revoke client, stop serving/cron, then retire Worker and dedicated routes/DNS |
| Demo D1 | `mikaki-demo-rp`, `ce11d383-758b-4574-8bcc-7febc505a408` | Discard sessions, transactions, logout tombstones and unused ticket data; retire dedicated DB |
| Demo OP client | `77551450-ec73-4222-972d-cd912d9493d4` | Disable before retirement; omit from fresh seed |
| FAQ RP | Unresolved | Provision separate RP storage/key and initialize an active OP registration |

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

| Surface | Required change | Retain |
| --- | --- | --- |
| Vault entry and UI | Remove `storage=legacy-v1` / `storage=owner-v2` selection, `VaultRouter` fallback and old profile/note panels | `OwnerWorkspace`, owner session/lease, local conversation search, lock/draft/visibility controls |
| OP storage | Remove `/vault/attributes/*` and attribute-only persistence/transfer/approved-commit handlers | Owner-key wraps, opaque record heads and ciphertext storage, conditional retries and atomic commit proof |
| UserInfo | Remove attribute SQL/decryption branch and legacy claim-release handlers; select only explicit record grants | Recipient directory/secret boundary, record envelope, exact consent/source/authority fences and disclosure audit |
| Agent | Reject v1 grants and authorization details; remove legacy capability/proposal/commit routes and source predicates | Record grant/disclosure, explicit record approval, owner/session authorization, OAuth and per-operation freshness checks |
| GC | Remove attribute-prefix cursor/head/mutation queries and triggers | Owner record candidates, serialized deleting state, bounded cleanup and head-install guards |
| Native Vault preview | Remove the old attribute-read resource and its consent/profile authorization; reject the retired audience | Native OIDC login, DPoP and common client/session authentication; any new record read profile needs its own explicit contract |
| Demo RP | Remove login-only mode/config/generated types, demo-only fixtures/tests and product links | Helpdesk/FAQ shared OIDC, CSRF, logout tombstones, session checks and help code |

Do not remove a shared helper merely because its file currently has an attribute
name. `vault_attributes.rs` supplies owner authentication, Origin checking,
conditional revision parsing, operation IDs, hashing and authorization helpers
used by the record handlers. `vault_approved.rs` supplies approval-header parsing
used by record commits. `vault-crypto.ts` supplies base64 helpers, while
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
and identity interoperability. #121 remains open until the source changes,
new baseline, approved production reset and recorded smoke/E2E all complete.

Initial verification (2026-10-04): all 56 release/migration tests passed, including
five new planner tests; strict TypeScript
checking of the planner and its tests passed; repository Markdown destination
and heading checks passed. No live metadata or participant-state inspection was
performed in this preparation step.
