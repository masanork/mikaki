# Work delegation implementation plan

**Status:** M1–M4, M5 owner inspection/composition/consent/copy progress and M6a–M6f credential custody, recovery/refusal, fixed Git copies, evidence composition and sealed private Git-host provisioning are locally integrated. Product source `5cf46162a08b3496ae1b49eda1a7e9f024e6a0e6` combines Workflow, public composition, session-bound approval and partial-progress authority checks. Isolated Git-host source `0b47be3` verifies private cold/warm readiness and R2 supply on Cloudflare; extension `1e0ef8e` verifies an independent stopped-state restart, natural shutdown and retained results. Source `c8f26a1` verifies the original IDs and all-state token inventories of the six protected Artifacts allocations, 2026-10-10 JST. The original third host outcome and three initial-effect outcomes remain unknown. Current remote OP has no Work/checkpoint bindings. Enrolled remote authority, productive Artifacts exchange and delegation retain their gates. No production activation is included.

Keep [ADR 0016](adr/0016-personal-context-and-workload-delegation.md) as rationale, [authorization](workload-authorization.md), [domain profile](workload-profile-v1.md) and [UI](work-request-ui.md) as contracts, and this file as delivery/qualification order.

## Production review and next code trial, 2026-10-12 JST

[PR #185](https://github.com/masanork/mikaki/pull/185) makes control-plane operator
separation optional while retaining the mandatory independent storage checkpoint.
[PR #187](https://github.com/masanork/mikaki/pull/187) qualifies the exact bounded
populated-schema preflight. The production Work schema and checkpoint were then
enrolled without resetting existing Owner accounts, Passkeys or Vault keys.
[PR #189](https://github.com/masanork/mikaki/pull/189) activates owner/source and
preparation review; final CI, deployment and checkpoint equality passed.
The earlier statements about an unbound production OP below are historical.

The next increment adds [operator code registration](work-code-source-registration.md)
and owner composition/explicit copy consent. The user selected mikaki as the
first source. Its original history exceeds the bounded Work capacity, so this
trial uses the exact selected main tree in a separately labeled parentless code
snapshot. No old protected Artifacts resource or unknown effect is reused.
Productive copy and real AI issuer/launcher qualification remain separate work.

## Main delivery, 2026-10-11 JST

Integrate the retained history in four qualified increments: portable rules from
`7acf884`; combined storage, checkpoint and initial-effect authority from
`da44a81`; owner review, consent, copy orchestration and sealed-host composition
from `c17bd4b`; then private infrastructure qualification and offline authority
preparation through `6a7dc99`. Storage and independent admission are combined
because their failure and recovery contracts must be qualified together.

The first increment was composed with main `a429bee` and integrated in
[PR #178](https://github.com/masanork/mikaki/pull/178), including its parallel CI
and current dependency locks. It exports portable rules and adds no Worker
route, production binding, migration or external operation. The later increments
remain on the retained Work branch until their composed revisions pass current
checks. The historical local qualification below does not qualify these new
compositions. Preserve frozen packets, provider journals, unknown outcomes and
their original source identities throughout delivery; source integration does
not authorize a new allocation, mint, enrollment or feature activation.

The second composition preserves the current single-email invitation transaction
and frames its complete guarded batch through the independent OP authority.
The opt-in migration rehearsal now also retains waiting-list rows and policy over
the complete current production baseline. Work adapter types and real
Wasm/D1/R2/checkpoint/effect qualification run in separate authority and effect CI
lanes; the common `verify` gate requires both as well as core, Worker contracts and
browser verification. The original main-only candidate signing and deployment
gates remain intact. This source delivery provisions no Work resource or binding.

Current composed local qualification passes all **162** retained backend/Git
cases, the production Worker public/raw-RPC/unenrolled refusal case, and the
extended current-baseline waiting-list retention case. Production Wasm build and
Clippy with warnings denied, Node/service/adapter types, formatting, source checks,
documentation and all **46** release regressions pass. The full backend run takes
about eight minutes locally; CI partitions its test files between authority and
effects without dropping or duplicating a file. Remote CI and the normal main
release must qualify the committed composition before this increment is complete.

The second increment is integrated by
[PR #179](https://github.com/masanork/mikaki/pull/179). Its complete PR CI passes.
Main verification exposed a waiting-list browser assertion that assumed the
registered applicant was the first list entry; equal creation timestamps permit
the other applicant to appear first. The ID-based regression fix is qualified
separately before the next main delivery.

The third composition merges retained `c17bd4b` while preserving the current
waiting-list and invitation UI, translations and production migration baseline.
It adds owner source review, composition, explicit session-bound consent, copy
Workflow progress and sealed Git-host contracts. The fixed `work-product` CI lane
qualifies browser, Workflow and Linux-container fixtures; the common `verify`
gate now requires all six lanes. All fixtures use isolated synthetic resources.
No production Work enablement flag, companion binding or Work migration is added.

Local qualification runs 130 authority, 181 effect and 117 product cases. Four
cases initially failed with socket errors during a long host interruption. Their
focused reruns pass, including all 18 copy-consent cases, restored credential
revocation and unknown Git-attempt retention. All other cases passed in the broad
run. UI, Node and adapter types, formatting, source and documentation checks pass.
Full PR CI and the normal main release qualify the committed composition; these
local results do not replace those gates or the retained activation evidence.

The third increment is reviewable in
[PR #181](https://github.com/masanork/mikaki/pull/181); the list-order regression
is fixed by [PR #180](https://github.com/masanork/mikaki/pull/180), whose local
single-email invitation/browser flow passes both cases.

The fourth composition preserves all retained history through `6a7dc99` and adds
private-host readiness/restart qualification, read-only provider inspection,
offline packet/deployment preparation and once-only bootstrap/allocation
contracts. These tools retain their original frozen packet identities and
unknown acknowledgments. No live operator command is executed by integration.
Current packet preparation includes the complete fifteen-file production/Work
chain. Verification separately retains the original fourteen-file chain and
plan; neither can silently acquire or lose the waiting-list migration.

Local qualification passes **39** packet/allocation/deployment/inspection cases,
including exact retained/current inventory and immutable-byte refusals; **10**
actual D1/SQLite DO bootstrap/recovery cases; and **17** host provisioning,
readiness and restart cases. Types, full formatting, source/docs checks and
actionlint pass. CI keeps packet/operator unit contracts in core, moves actual
bootstrap runtime cases into the authority lane and adds the host qualification
file to product. The authority/effect partition covers all nineteen backend
files exactly once, and product covers all eighteen selected files exactly once.
Original unknown provider outcomes and independent operator/origin/signing,
real owner enrollment and productive-effect qualification remain activation
gates after source integration. Complete CI and the normal main release still
qualify each committed composition before delivery is complete.

## Preserved work and main baseline

The old `feat/agent-vault-oidc-qualification` branch at `d441ce0a4583ebcf1ae54627e2ca3df29e2f20a9` had no commits outside main and was 156 commits behind at the initial catch-up. Replaying its committed history adds no work.

Uncommitted work is preserved by stash commit `ea733061aefa6a3cb3262908aa685eb3337bc40d`, labeled `pre-main-catchup-20261008: preserve local work and qualification evidence`; its additional-file tree is `ceb868a163c1f21df9af3391c288bf672431ffa8`. Keep the stash until selected work/evidence is fully accounted for. It includes unrelated earlier changes and generated files; applying the whole stash is not the integration unit.

The root checkout was already clean on main at `8d48ba93fef64f4802627939ec63235eeef6aa68`. A fresh GitHub main-ref read matched that commit. New local branch `feat/work-delegation-main` starts there and retains main's newer dependencies, Owner Vault implementation and schema.

Main uses migrations `0001_owner_vault_initial.sql` and `0002_owner_key_wrap_operations.sql`. Retained work used the historical chain through `0047`–`0056`. Port additive work schema and current OP admission paths explicitly; do not restore retired migrations, obsolete Agent/Vault callers or old dependency locks to satisfy the old fixture.

Ignored `local/generated/work-*` evidence/state remains in place. Initial-effect journals account for **six empty development repositories**, including unresolved allocations. Empty inventory cannot close an unknown attempt. This integration neither resets those records nor deletes, recreates, remints for or adopts their resources.

## Main integration order

| Increment                       | Outcome and qualification gate                                                                                                                                                                                                                                              | State                                                                                                                                                                                                                                                                                                                                           |
| ------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| M1: Portable rules/decisions    | Restore ADR/AuthZEN/ABAC choices and Rust rules with main's dependencies. Native tests and Wasm compilation pass.                                                                                                                                                           | Complete locally: 35 unit cases plus one compile-fail case.                                                                                                                                                                                                                                                                                     |
| M2: Fresh-schema authority      | Port WorkStore/SQL, bounded budgets and custody onto the fresh baseline; exercise current owner/session/source checks, exact retry, audit rollback and concurrency in actual Wasm/D1/R2.                                                                                    | Complete locally: 96 current-main qualification cases, including the reconciled M2 boundary cases.                                                                                                                                                                                                                                              |
| M3: Checkpoint/OP framing       | Port independent release floors and admission for current OP mutations; rehearse D1 restore and key/account/session/policy revocation while preserving safety reconciliation.                                                                                               | Complete locally: 16 checkpoint cases; activation gates remain.                                                                                                                                                                                                                                                                                 |
| M4: Initial effects/maintenance | Reconnect initial-create gate, read-only lookup and attenuating broker; requalify one-time admission, lost replies, immutable IDs, refusal and runtime RPC/binding limits. Resume protected remote journals without replacement creates.                                    | Complete locally: 50 effect/capability cases. Read-only remote identity/token inventory of all six protected allocations passes; three unknown outcomes remain charged and retained. Enrolled remote effects remain pending. |
| M5: Source/product review       | Integrate source selection, separate copy/delegation consent and owner projections into current product components; requalify Japanese/English UI and stable operation identity.                                                                                            | Integrated source `5cf4616` passes 43 copy/Workflow/host/API/browser cases, including public composition through sealed-host verification and partial-progress authority loss. The 400-case broad regression and 2 Vault browser cases have their separate scopes below. Delegation, activity/result controls and deployment remain pending. |
| M6: Upload/readback             | Native authority fixes repository, scope, expiry and operation digest. Independently admit each mint and Git exchange once before I/O; unknown outcomes cannot replay. Capture plaintext only into encrypted custody. Independent full readback checks the actual Git copy. | M6a–M6f include mint/custody, recovery, bearer refusal, fixed Git exchange, both-role evidence and sealed provisioning locally. Isolated Cloudflare cold/warm startup, R2 supply, independent stopped-state restart, natural shutdown and result retention pass. Enrolled remote authority, productive Git, missing custody and release remain pending. |

Preserved pre-main qualification passed 160 combined delegation cases, including 50 initial-effect/reconciliation/capability cases. Earlier UI qualification had 22 cases. Actual Artifacts initial creation, lost-create safety reconciliation and process restart were exercised using protected journals. These identify reusable work; they are **not current-main or production qualification**. The exact prior notes/fixtures remain in the stash.

Record selected source, implementation, checks and remaining gates for each increment. Commit reviewable units, then refresh Artifacts from a selected qualified commit. Old CI/release inventory or workspace overlays do not qualify new source.

M1 qualification passes `cargo test --workspace --offline --locked` (**209 cases**, including doctests), the auth Wasm target check, auth all-target Clippy with warnings denied, workspace formatting, product-source and documentation checks. Native workspace tests do not exercise the unported work HTTP/D1/Artifacts paths or production Workers. No prior Worker/browser qualification is counted as a current check.

M2 is integrated on `feat/work-authority-main-integration`, isolated from concurrent edits in the root checkout, after merging main through `1f0dd3c` (owner-selected v2 records for local Codex). Selected WorkStore, SQL, owner/source transport, credential custody and candidate archive code came from the preserved stash. Main's dependencies and the two production baseline migrations are retained. The [separate work migration ledger](../crates/worker/work-migrations/README.md) applies eight additive migrations explicitly in local fixtures; migration qualification verifies existing OP/Owner Vault records remain intact. Product review screens and production bindings are not activated.

Current M2 qualification: `npm run test:work-delegation` passes **94 cases**, including real Rust/Wasm/workerd/D1/R2 restart, concurrent single admission, exact retries, current session/source/policy checks, audit rollback, credential-key floors and independently checked Git archives. Node and source-Worker type checks, product-source and documentation checks pass. This is local evidence with synthetic workload-verifier facts. The pure owner projection module is included for the prepared-authority contract; the owner screens remain M5. Independent checkpoint/OP framing and new external effects remain M3/M4 gates.

## Product delivery backlog

The first usable outcome is one owner, one non-sensitive disclosure, one managed run, one candidate and one exact code adoption into an experimental development target. Code adoption and saving a decision require separate confirmations.

| Card  | Outcome and prerequisites                                                                                                |
| ----- | ------------------------------------------------------------------------------------------------------------------------ |
| WD-00 | Verified committed Artifacts development baseline and bootstrap cleanup; refresh from a newly selected qualified source. |
| WD-01 | Bounded workload profile and component ownership; M1 restores the portable portion.                                      |
| WD-02 | Durable request/grant/run/approval/operation authority; M2/M3.                                                           |
| WD-03 | Actual context/snapshot/history review and copy consent; WD-01/02, M5.                                                   |
| WD-04 | Controlled launch and instance/client/key-bound exchange; WD-01/02 and named launcher/issuer verification.               |
| WD-05 | Task-repository effects and credential reconciliation; WD-02, M4/M6, WD-04 before workload access.                       |
| WD-06 | One run submits a candidate with confirmed activity state; WD-03/04/05.                                                  |
| WD-07 | Exact owner adoption; WD-02/06 and independent candidate/evidence/write reconciliation.                                  |
| WD-08 | Separate permission stop, execution stop and credential cleanup; integrate through WD-06/07.                             |
| WD-09 | Separate decision adoption and next-day handoff with fresh authority; WD-03/07/08.                                       |
| WD-10 | Two-run comparison and individually qualified external clients; WD-09.                                                   |

Owner-enrolled clients, managed execution identity, Token Exchange, SPIFFE and AuthZEN HTTP retain distinct qualification gates. Internal ABAC rules do not establish issuer/PDP interoperability.

## Cloudflare CI lane

| Card  | Completion boundary                                                                                                                                          |
| ----- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| CI-01 | Test-only Artifacts-triggered Workflow: fixed committed source/ref, passing/failing runs, exact checkout, reports, duplicates/cancellation and bounded cost. |
| CI-02 | Required Rust/Wasm/contract/browser parity at the same commit; qualified toolchain/cache identity and immutable reports/build bytes.                         |
| CI-03 | Isolated staging and trusted publisher: exact approval, binding/schema/secret inventories, upload/activation reconciliation.                                 |
| CI-04 | Trusted provenance, recovery fencing, compatible rollback and one authoritative write direction before canonical migration.                                  |

CI-01 can proceed separately once its exact source/resources are selected. Deployment credentials stay in the publisher boundary; a Workflow event, identity token or successful test does not grant production promotion.

M3 qualification passes **16 checkpoint cases** and **13 current OP regression cases** (production service/RPC boundary, bootstrap enrollment, ingress/retention and Queue logout). Production Worker build and OP authority packaging, Node/service/checkpoint-Worker type checks and production Wasm Clippy with warnings denied pass. Six pre-existing Worker Wasm style warnings exposed by the current dependency/toolchain were fixed in a separate commit. The [checkpoint note](work-authority-checkpoint.md) records the covered paths and remaining recovery/operator/release gates. The local fixture uses main's Queue-aware logout handler, with its actual event context.

The current production Chromium enrollment regression also passes: real virtual Passkey enrollment, additional credential/invitation flow, login retries and Owner Vault PRF behavior remain compatible without the opt-in work schema.

M4 qualification passes the complete **160-case** delegation suite (M2 94 + M3 16 + M4 50), using actual Rust/Wasm/workerd/D1/R2/RPC/DO and synthetic Artifacts/Git. Current production shim/facade, enrollment, Chromium Passkey/Vault, Queue and ingress/retention regressions pass (14 cases across selected files). The initial final regression run and a single-file repeat encountered a connection reset while the pre-existing fixture seeded 1200 SQL statements in one D1 RPC. Bounded seed calls now retain and assert the same 1200-row GC backlog, and the case passes. Product GC code and its convergence assertions remain intact.

Final validation also passes native workspace tests (**209 cases**), workspace all-target Clippy and production Wasm Clippy with warnings denied, Worker build/OP packaging, Node/service/source/checkpoint/effect type checks and full formatting. The OP Wasm is within its existing byte budgets (5,854,173 raw bytes; 2,077,741 gzip estimate). CI includes the new Worker type checks, the full delegation suite and production RPC boundary case. The [initial-effect note](work-artifacts-effect-gate.md) records the capability and recovery limits. These are local results; no remote CI result or production/Artifacts activation is claimed.

Next: qualify the private Git host in an isolated Cloudflare environment, then reconcile existing protected development allocations against their original identities before another real Artifacts trial. Delegation needs qualified issuer/launcher contracts. Owner composition, approval and productive Workflow copying are now locally connected.

Parallel M2 commit `ed7535d` is reconciled into this history. Its portable WorkStore/SQL matches the selected current implementation; current checkpoint, owner/source, effect and fixture changes extend it. The unified opt-in ledger preserves the root branch's numbering: work `0003`–`0010`, checkpoint `0011`, OP frames `0012`. Production baseline `0001`/`0002` and production configuration remain intact. Duplicate migration chains are removed; compatibility fixture names use the same tested implementation. The original [M2 checkpoint note](work-store-main-integration.md) is retained as historical evidence.

The reconciled current suite passes **162/162 cases** (M2 96 + M3 16 + M4 50). It preserves both parallel M2 ingress/enrollment boundary cases and checks the entire additive chain against existing schema definitions and Owner Vault rows. Node/Worker types, full formatting and documentation checks pass after reconciliation; the production-baseline/Owner-schema/release-inventory subset passes **11/11**. The fixture output is consistently `local/generated/work-store-main/`; pre-main `work-store/` output and protected remote journals are not rewritten.

A final main-ref read found `f03d656583f934ffe290bd45c81f73fa927a06a4`: one automatic metrics-only commit after `1f0dd3c`. Its three metrics files are included; it changes no application source, dependency or migration.

M5a adds authenticated source inspection with current product components, a shared display/session lease and separate bounded UI bundles. Current Japanese/English browser evidence covers actual selected Git content, keyboard/mobile/focus, CSP, stale membership, transport substitution, reload, lock/reopen and hidden-page late replies. The authority/effect/source-browser/lease run passes **178 cases**; the final bundle separation repeats the 15 UI/lease cases. Source page/asset/lease cold and owner boundaries are tested, including absent-checkpoint and release-floor refusal. The [UI note](work-request-ui.md) records scope and the remaining copy/delegation gates. The remote main ref was rechecked and remains `f03d656`; no history catch-up remains for this increment. No binding, production migration, deployment, provider token or protected remote journal is changed.

## M6a: One-shot mint and Native custody

The [mint gate](work-artifacts-mint-gate.md) connects the six fixed credential slots to Native plans and independent one-time mint admission. The current checkpoint, closed initial effect, immutable repository, purpose/scope, deadline and wrapping key are fixed before provider I/O. Permanent slots survive a whole primary restore; unknown or lost replies cannot remint. Matching plaintext enters only encrypted Native service custody. Historical custody is distinguished from current OP metadata synchronization; neither supplies copy verification or workload release.

The standalone mint suite passes **28 cases** over the actual Rust/Wasm, D1 and persistent Workers RPC/SQLite runtime with synthetic Artifacts. Frozen Native batches remain fenced while the independent ledger preserves known cleanup observations. Unknown mint recovery, productive Git upload/readback and copy/delegation controls still require subsequent qualification. No remote mint trial, protected journal change, production binding or deployment is performed.

The combined current backend/Git run passes **191/191 cases** (the previous 163 plus 28 mint cases). Production OP/service boundaries and baseline/Owner-schema/release-inventory regressions pass **13/13**. The production Worker build, named OP packaging, Wasm Clippy with warnings denied, Node/effect/checkpoint types, full formatting and documentation links pass. Existing UI budgets remain unchanged; OP Wasm is 5,936,405 raw bytes / 2,103,885 gzip estimate, within the existing 8 MiB / 3 MiB budgets.

Latest main `407f50e` is integrated by merge `f00c49d`, preserving the qualified work-port history. Its UserInfo fixture changes do not change product source. The current default UserInfo qualification passes **2/2 cases** after rebuilding the previously stale ignored conformance Claim Worker with the exact CI command, `worker-build --release -d build-conformance crates/userinfo-claim-worker --features conformance-gate`. Both actual workerd and browser v2 recipient/sharing/consent/withdrawal flows pass. No new profile benchmark or production-capacity claim is made. Node types, full formatting and documentation links pass after the merge.

## M6b: Safety-only known-ID mint recovery

The [recovery note](work-artifacts-mint-recovery.md) connects a retained unknown
mint to a read-only physical broker and a separately bound safety reconciler.
Durable cleanup intent fences late custody; exact stored token metadata supplies
the only revocable ID. ID-specific positive acknowledgement or a matching fresh
revoked inventory entry can retain control-plane cleanup evidence. A missing ID,
elapsed time, expired state or empty inventory supplies no attribution or proof.
Repeated proof synchronization and process restart do not replay provider I/O.

The new suite passes **33 recovery cases**, including all role/purpose pairs,
failed/lost revoke and custody replies, inventory loss after acknowledgement,
identity/metadata substitution, unobserved outcomes, empty/expired inventory,
in-flight custody fencing, Native disablement/restore/key absence and independent
checkpoint freeze/pending/floor refusal. New Native batches remain fenced;
metadata already present can still be confirmed without another batch. Recovery
does not close the charged obligation, certify a copy or issue a workload grant.

The combined backend/Git regression passes **224/224 cases** (191 previous plus
33 recovery cases). Production OP/service boundaries and baseline/Owner-schema/
release-inventory regressions pass **13/13**. Node/effect/checkpoint type checks,
full formatting, product-source checks and documentation links pass. Rust and UI
product source are unchanged in this increment; the M6a build/browser results
above remain historical evidence, rather than newly rerun checks.

The remote main ref is rechecked at `407f50e`; the existing merge remains current.
New Workers are wired only in the synthetic local fixture. Production settings,
baseline migrations, protected journals and real Artifacts repositories/tokens
are untouched. Strong bearer-refusal closure, unobserved-token operator recovery,
productive fixed Git upload/readback and owner copy/delegation composition remain
the next gates.

## M6c: Native bearer refusal and independent closure

The [closure note](work-artifacts-mint-closure.md) connects retained encrypted
revocation-pending custody to a fixed, private refusal-only HTTP transport. Native
decrypts the exact bearer under the existing key floor; the transport checks the
independent cleanup record and immutable Artifacts identity before and after a
concrete Git upload-pack refusal. The separately bound closer retains exact
Native proof outside D1 before asking Native to close that obligation.

The **23 closure cases** qualify both roles/purposes, loss/restore/freeze, missing or
substituted wrapping authority, guarded ciphertext writes, failed/redirected Git,
identity/inventory substitution, audit rollback, cancellation and private-capability
limits. Native closure erases its encrypted credential and releases that charge;
the independent permanent slot remains. This supplies no copy verification or
workload authority. Production and protected remote evidence remain untouched.

Implementation `bf2a170` is followed by main integration `811f503`, bringing in
main `9022fb2` and retaining the work-port history. Main's Babel-based static SQL
extractor and pinned dependencies replace the retired application compiler
adapter; the exact 64-statement product catalog remains unchanged. SQL extraction
and reset-plan regressions pass **12/12 cases** on the installed merged lockfile.
The additional native-client, JOSE and Android/JVM CI lanes are retained; no new
result from those lanes or remote CI is claimed here.

The combined actual Rust/Wasm/workerd/D1/R2/RPC regression passes **247/247 cases**
(224 previous plus 23 closure cases), with synthetic Artifacts/Git. Production
OP/service boundaries and baseline/Owner-schema/release-inventory regressions
pass **13/13**. Default production Wasm Clippy with warnings denied, Worker build,
named OP packaging, Node/service/effect/checkpoint types, full Rust/TypeScript
formatting, product-source checks and documentation links pass. OP Wasm is
5,985,079 raw bytes / 2,113,840 gzip estimate, within the existing 8 MiB / 3 MiB
budgets. Product UI source/budgets are unchanged; no new browser claim is made.

The next productive increment is fixed Git upload and independent readback,
followed by owner copy/delegation composition. Missing/unobserved custody and
independent-ledger/operator recovery still require qualification before remote
activation. No real mint, refusal/revocation trial or production deployment is
performed.

## M6d: Fixed Git upload and independent readback

The [Git gate note](work-artifacts-git-gate.md) connects current Native custody to
fixed commit/ref plans, independent one-shot admission/consumption and a private
identity-checked Artifacts bridge. The trusted registered-source Git host emits
one create-only receive-pack POST, then a separate read credential obtains a
bounded complete pack in a fresh bare database after strong upload-token closure.
Strict indexing, independently hashed inventories, exact refs/tree/history and
fsck establish the readback. Neither result promotes preparation or issues a grant.

The new local qualification passes **24 Git gate cases and three pack cases**.
Git CLI's internal retry after a lost push reply was detected and replaced by
explicit no-retry smart HTTP. Corrupt/oversized packs are checked before Git
indexing; real REF/OFS delta reconstruction is exercised. Results cover accepted
reply loss, restart/whole D1 restore, primary and independent authority loss,
repository/token substitutions, cleanup intent, private capabilities, selected
snapshot isolation and concurrent one-send admission.

The Git host factory is implemented and qualified as a private Node host service.
Its Cloudflare execution environment and registered-source provisioning still
need deployment qualification. Existing production configuration, migrations,
UI source, protected journals and real Artifacts resources remain unchanged.
Both-role preparation evidence, copy/delegation UI and workload release are next.

The full integrated regression passes **274/274 cases** (247 previous plus 27 Git
cases). After sharing the same no-retry HTTP primitive between production and the
loopback fixture, the **24 Git gate cases pass again**. Production OP/service
boundaries and baseline/Owner-schema/worker-roster/release-inventory regressions
pass **29/29**. Node/service/effect/checkpoint types, full formatting, product
source checks and documentation links pass. Default production Wasm Clippy with
warnings denied and the Worker build pass. These remain local results; no remote
CI or provider compatibility claim is made.

Implementation is committed as `c95a64d`. The production Worker is rebuilt with
that exact source revision after detecting stale embedded revision metadata in
the first size-check attempt. Named OP packaging preserves the 64-statement
static Agent SQL catalog. The production boundary/schema/roster/release subset
passes **29/29 again** against that rebuilt Worker. Served UI and both Wasm size
budgets pass; OP Wasm is **6,101,707 raw bytes / 2,146,047 gzip estimate**, below
the existing 8 MiB / 3 MiB ceilings. Rustfmt, default production Wasm Clippy with
warnings denied, Node/service/effect/checkpoint types, Prettier, product sources
and documentation checks pass. No new product browser or remote CI evidence is
claimed, and no push, deployment or real Artifacts I/O is performed.

## M6e: Both-role preparation evidence

[Preparation evidence composition](work-preparation-evidence.md) connects the
task and snapshot uploads/independent readbacks and all six Native credential
closures to the existing framed `dispatched → verified` transition. The private
trigger accepts only a preparation ID. A separately bound read-only independent
ledger returns fixed retained metadata; Rust validates every Native binding,
closure, Git commitment and matching complete inventory before constructing the
payload/custody commitments. No credential is decrypted for this step.

The local cases cover exact retry/concurrency/restart, missing or substituted
metadata, closed credentials without copy proof, unknown upload outcomes, lost
verify acknowledgement, stale D1 restoration, checkpoint/owner/source/policy loss
during evidence retrieval and capability isolation. Verified remains historical
preparation evidence; this increment creates no task, grant or run and releases no
workload credential. Copy/delegation UI and Cloudflare Git-host/source-registry
deployment remain the next integration gates. Production flags, bindings and
baseline migrations, protected remote journals and real Artifacts are unchanged.

M6e implementation source is `b4e3b010212240ef4c7692df0149e5605d110c11`.
The combined local work lane passes **289/289 cases**, including **15 composition
cases**, and the production OP/service boundary, baseline/Owner-schema,
worker-roster and release-inventory subset passes **29/29** against the Worker
rebuilt with that exact revision. Native default-production Wasm Clippy with
warnings denied, Rustfmt, Node/service/effect/checkpoint types, Prettier, product
sources and documentation checks pass. Named OP packaging retains 64 static
Agent SQL statements. Served UI and both Wasm budgets pass; OP Wasm is
**6,225,033 raw bytes / 2,186,597 gzip estimate**, below 8 MiB / 3 MiB.
Product UI source is unchanged; no new browser or remote CI result is claimed.

## Unified mint, Git and preparation evidence

The canonical registered-source Git host and both-role Native evidence composer
from `b4e3b01` are reconciled with `fc135aa`'s mint-only authority, absolute issuance
expiry, known-plaintext safety observations and fixed local Git copy core.
Separate Native facades expose `/effect`, `/mint-effect` and `/git-effect`; other
facades and raw RPC cannot widen them. Productive Git plans bind the concrete
credential expiry, while the independent mint record retains its fixed issuance
bound. Evidence composition compares that bound against the exact closed Native
observation and deadline before verification.

The alternate buffered broker candidate is retained on
`feat/work-git-broker-candidate` (`2c20b99`) for history. Its runtime path is
superseded by the opaque registered-source Git gate; no duplicate productive
protocol remains. The independent 17-case copy core remains as a separate local
validation utility. This integration does not activate production or alter
protected remote allocations, journals or the preserved stash.

Unified implementation/qualification source is
`f53357e68974e60d97b448106da818a4c22a0c84` on
`feat/work-mint-reconciliation`, including the scoped-authority merge `70d8f5a`.
The package's complete work test-file list is covered in two serial groups:
**89 mint/custody/cleanup cases and 222 remaining cases (311 total)**. The first
mint run passed 88/89; empty-inventory recovery encountered an internal Miniflare
response-hydration assertion and passed its same-source isolated rerun (1/1).
The remaining group passed 222/222. No application change or test relaxation was
made for that harness retry.

Rust workspace tests pass **209/209**. Default-production Wasm Clippy with
warnings denied, Rustfmt, Node/checkpoint/effect/service types, full Prettier,
product sources and documentation checks pass. Production OP/service/enrollment/
logout boundaries pass **13/13** against the Worker rebuilt with the exact
qualification source; baseline/Owner-schema, worker-roster, release-inventory,
reset-plan and static SQL regressions pass **34/34**. Named OP packaging retains
64 static Agent SQL statements. Served UI and both Wasm budgets pass; OP Wasm
measures **6,255,865 raw bytes / 2,189,644 gzip estimate**, below 8 MiB / 3 MiB.
Build metadata and the budget artifact both identify the clean `f53357e` source.

The root branch separately advanced with native owner preparation/disclosure
review (`a0eb5ef`) during qualification. That work is preserved and is outside
these exact-source results. The next integration combines this scoped-authority
branch with the owner UI work before connecting copy/delegation actions and
requalifying their composed build. This record adds documentation only. No new
browser, remote CI, real Artifacts or production-activation result is claimed.

## Owner review and scoped evidence integration

Integration source `79304b04c13e91287254bcf44ffa51baceda1712` combines the
qualified scoped mint/Git/evidence branch with owner preparation/disclosure
review through `3450ca5`, preserving its Wasm-only module guard. Both local Git
copy and preparation-UI test commands remain available. The actual both-role
Git/effect composition now also feeds the product's strict owner reader: the
Native paged list, preparation and disclosure match the verified destinations
and selected context while reporting no materialization or current execution
authority. It still creates no task, grant or run.

The complete work command passes **311/311** in one serial run. Preparation/source
owner Native/browser/display-lease qualification passes **30/30**, and the existing
Owner Vault browser lane passes **2/2** separately. Browser display-state evidence
remains explicitly synthetic; the added reader integration uses real local Git
copies/readbacks and all six closed Native credential records with synthetic
Artifacts. Japanese/English and 375px screenshots were visually inspected. No
assertion, timeout or capability boundary was relaxed.

Rust workspace tests pass **209/209**; default-production Wasm Clippy denies all
warnings. Rustfmt, full Prettier, Node/Worker UI/service/effect/checkpoint types,
the 600-key bilingual catalog, product sources and documentation checks pass.
Production OP/service/enrollment/logout boundaries pass **13/13** against the
Worker rebuilt from the clean integration source. Baseline/Owner-schema,
worker-roster, release-inventory, reset-plan and Agent SQL regressions pass
**34/34**. Named OP packaging retains 64 static product SQL statements.

Served UI and both Wasm budgets pass. OP Wasm is **6,262,962 raw bytes /
2,191,815 gzip-estimate bytes**; the budget artifact and embedded revision identify
the clean `79304b0` source. Preparation JavaScript is **184,053 / 58,467**, within
192 KiB / 64 KiB, and served Vault JavaScript is **302,958 / 87,015**. Gzip sizes
are local estimates. This qualification record adds documentation only.

Copy/delegation confirmation and productive owner mutations, issuer/launcher
contracts, activity/result controls and Cloudflare Git-host/source-registry
deployment remain the next gates. At that integration source, the production
public Router still omitted the work surface. No production flag, binding or
baseline migration was activated.
Protected Artifacts resources/journals and the preserved stash remain untouched;
no push, deployment, remote CI or real provider mutation was performed.

## Opt-in product entry qualification

Source `3cc41420fca4dcd3ba15396b05eb97a40630f06a` composes the existing owner
transport into the default-production Rust Router, after the native callback-host
guard. The owner flag still returns closed, no-store JSON 404 responses before
work-schema access. Source and preparation screens retain their additional
flags; enabled access needs the opt-in schema, live SSO, an enrolled matching
independent checkpoint and the private reader for plaintext inspection. No
deployment configuration enables these paths.

Actual product-entry tests found source/request lists lacking checkpoint checks.
Native lists and every owner record projection now check the independent
checkpoint before their final live-SSO SQL selection. An absent enrolled marker
is stale authority, rather than a missing-resource result. Freeze, pending intent,
release-floor increases, mismatched checkpoints and missing bindings refuse
review; a pending intent introduced inside source RPC prevents plaintext release.
The work ingress budget is charged once, and callback hosts expose no work routes.

The product and qualification compilations are tested separately with identical
unenrolled data: only the qualification build has its pre-enrollment exemption.
`LOCAL_WORK_QUALIFICATION=true` cannot activate it or fixture endpoints in the
product. Synthetic initial SSO is seeded before enrollment; subsequent session
revocation uses the actual product's named Native admin authority and checkpoint
frames. No SQL guard, assertion or timeout is weakened.

The exact-source rebuild passes **134/134** in one serial run: **111** existing
work/source/preparation/browser/display-lease/checkpoint/evidence cases, **10**
enabled product-entry cases and **13** existing cold OP/service/enrollment/logout
cases. The existing Owner Vault browser lane passes **2/2** separately.
Baseline/Owner-schema, Worker roster, release/reset and Agent SQL cases pass
**34/34**. Rust workspace tests pass **209/209**, with default-production Wasm
Clippy denying warnings. Host Worker checking, Node/Worker UI/service/source
types, Rustfmt, full Prettier, the 600-key bilingual catalog, product-source and
documentation checks pass. The prior complete 311-case work result is historical;
this increment does not claim a rerun of every mint/recovery lane.

All served UI/Wasm budgets pass. The budget artifact and embedded Worker revision
identify clean `3cc4142` source. OP Wasm is **6,863,268 raw / 2,382,004 gzip-estimate
bytes**, within 8 MiB / 3 MiB. Served source JavaScript is **173,744 / 55,396** and
preparation JavaScript **184,053 / 58,467**, within 192 KiB / 64 KiB; private styles
stay within their existing budget. Vault JavaScript remains **302,958 / 87,015**.
Gzip figures are local estimates. Japanese/English and 375px screenshots were
visually inspected. Browser preparation verification remains explicitly
synthetic; the Native composition lane uses actual local Git copies/readbacks
and all six closed credential records with synthetic Artifacts.

`test:work-preparation-ui` builds both entries; `test:work-owner-product` runs the
enabled and cold boundaries. Existing CI and PR browser jobs include the new
product/preparation checks. No remote CI result is claimed. Copy/delegation
confirmation, productive owner actions, issuer/launcher contracts and deployment
remain pending. Production flags, bindings, baseline migrations, protected
Artifacts resources/journals and the preserved stash remain unchanged. No push,
deployment or real provider mutation was performed. This record adds
documentation only; the selected Worker source remains `3cc4142`.

## Explicit copy consent for reserved preparations

Selected source `311886a3c37d3bdb4bb76253f7e461384e2e1ba9` adds explicit owner
consent for an existing reserved preparation. Native Rust creates the exact
review digest from the immutable preparation/disclosure, fixed Cloudflare
Artifacts operator/account and absolute deadline. The dedicated opt-in
`GET/POST/DELETE /work/preparations/:id/copy-consent` transport uses live owner
SSO, the independent checkpoint and same-origin, closed, bounded JSON. The
browser supplies only the review digest; it cannot choose an actor, account,
source, repository, credential or receipt.

Additive migration `0013` retains approval and withdrawal without backfilling
consent. Each mutation commits with its owner audit and Native transaction frame.
Current consent requires the original approving SSO, active account/credential,
matching epoch, current source bindings and policies. The copy deadline cannot
exceed the approving SSO lifetime; both Native review and the D1 commit guard
enforce that bound. Exact retries add no audit or authority, and withdrawal
cannot reactivate the same consent. Historical consent does not prevent normal
SSO garbage collection.

Fresh Native preparation/credential dispatch and initial-create, mint and Git
plans require current consent. New plans bind the configured Artifacts account;
the independent external gates reject a missing or different account before
provider I/O. Native evidence composition also checks that account in each
retained plan. Older account-less journals remain readable for historical
verification and cleanup; they cannot authorize fresh external effects. The
qualification-only, explicitly pre-0013 schema exemption is absent from product
builds. Withdrawal preserves existing effect identities and safety cleanup;
it does not establish that an already admitted effect has stopped.

The preparation screen requires actual content inspection and a fresh explicit
acknowledgement before approval. Japanese/English review shows operator/account,
destinations, selected contents/history and expiry. Consent, copy completion and
workload authority remain distinct. Selection, refresh, hidden state, session
replacement, expiry and lock discard the acknowledgement and inspected text.
A late successful POST cannot revive a locked view; reopening reads the durable
result. Visual inspection covers Japanese and English at 375px; keyboard and
accessibility checks pass. Approval creates no repository, token, task, grant or
run. Productive copying still needs its owner orchestration.

The complete combined backend/product/UI regression run passes **372/372** at
`aa8f604`, including the strict account-bound evidence fix. After the SSO deadline
hardening, the clean selected `311886a` build passes **167/167** in one serial run,
covering the new consent/API/browser cases and existing owner/source/preparation,
checkpoint, evidence, delegation and cold OP/service/enrollment/logout cases.
The deadline case also supplies a matching transaction-local frame and proves
that captured SQL fails the deadline guard without changing the checkpoint.
The existing Owner Vault browser lane passes **2/2** separately. These final
results do not claim a second full rerun of every mint/recovery lane.

Rust workspace tests pass **209/209**, including doctests; the work HTTP/D1 paths
are exercised separately in actual Rust/Wasm/workerd fixtures. Production Wasm
Clippy denies warnings. Node/Worker UI/service/source/effect/checkpoint types,
Rustfmt, full Prettier, the **612-key** bilingual catalog, product-source and
documentation checks pass. The unchanged baseline/Owner-schema, Worker roster,
release/reset and Agent SQL lane passes **34/34** during this increment.

The budget artifact and embedded Worker revision identify clean `311886a`
source. OP Wasm measures **6,909,751 raw / 2,395,657 gzip-estimate bytes** within
8 MiB / 3 MiB. Served preparation JavaScript is **190,643 / 60,370** and source
JavaScript **173,744 / 55,396**, within 192 KiB / 64 KiB. Vault JavaScript remains
**302,958 / 87,015**; all existing served UI/Wasm budgets pass without adjustment.
Gzip figures are local estimates. Existing CI/PR preparation checks include the
new consent cases, and `test:work-copy-consent` provides a focused local command.

Owner compose and productive copy orchestration are the next increment;
delegation needs the named issuer/launcher contracts. Production work flags and
bindings remain disabled; the production baseline migrations are unchanged. Protected Artifacts
resources/journals and the preserved stash remain intact. No push, deployment,
remote CI qualification or real provider mutation was performed. This record
adds documentation only; the selected Worker source remains `311886a`.

## Owner selection composition and separate approval

Selected source `14e7b4a72750371f6bab0bd2ec25030eed592099` adds the closed,
separately gated `POST /work/preparations` transport and its owner UI. The owner
chooses one registered code source and inspected context paths with an absolute
deadline. Rust resolves current source/access revisions through the fixed
read-only private RPC and repeats checkpoint/source guards. Operator settings
fix destination namespace/account and planning recipient/workload identifiers;
no caller-provided Git receipt, actor, destination or credential is accepted.
[The composition decision](work-preparation-compose.md) records the contract.

Native verification checks both SHA-256 content and actual Git blob identity.
Rust computes the planned parentless snapshot tree/commit using the existing
fixed snapshot recipe; independent ordinary Git materialization matches those
names. Unicode/directory ordering, empty snapshots and collision refusal have
pure Native vectors. These are planned object names, not stored Git objects,
upload receipts or proof that a copy completed. No plaintext is persisted in the
disclosure/preparation.

Exact retries and competing isolates retain one preparation and reservation
charge. An audit failure leaves at most safe disclosure metadata and rolls back
the preparation/charge; an exact retry finishes the same selection. Deadlines
remain within the live SSO. Changed sources/checkpoint authority refuse the
operation. The bounded browser acknowledgement checks the exact selection digest
and deadline before exposing a review link.

The source screen supports code-only preparation and Japanese/English copy
composition. A link opens a fresh Native preparation projection; it cannot
approve or dispatch a copy. Actual content inspection and a fresh acknowledgement
are required again for approval. Selection/validity changes discard the link;
failed unchanged retries retain the absolute deadline. Hidden state, lock and
session replacement reject late replies. Browser checks cover keyboard, 375px
layout, accessibility, substituted/oversized replies and a committed creation
whose response arrives after lock. Japanese/English screenshots under
`artifacts/work-preparation-compose/` were visually inspected.

The clean selected Worker and separate qualification Worker were rebuilt before
the serial regression run. It passes **195/195**, including **14** new Native/API
composition cases, **5** new browser cases and the prior **167**
owner/preparation/consent/checkpoint/evidence/delegation/OP/service/enrollment/
logout/display-lease cases plus **9** existing source-browser cases. Source SSO
and provider mappings are synthetic local facts; Git bytes are real. This scope
does not claim another full mint/recovery run or real Artifacts qualification.
The existing Owner Vault browser lane passes **2/2** in a separate isolated run.

Rust workspace tests pass **213/213**, including doctests. Auth all-target and
production Wasm Clippy deny warnings. Node/Worker UI/service/source/effect/
checkpoint types, Rustfmt, full Prettier, the **619-key** bilingual catalog,
product-source and documentation checks pass. Baseline/Owner schema, Worker
roster, release/reset and Agent SQL checks pass **37/37**. Existing source UI
CI/PR jobs now build both product/qualification entries and include composition;
`test:work-preparation-compose` provides a focused local command.

The budget artifact and embedded Worker identify clean `14e7b4a`. OP Wasm is
**6,996,534 raw / 2,424,736 gzip-estimate bytes**, within 8 MiB / 3 MiB. Served
source JavaScript is **179,999 / 57,247** and preparation JavaScript
**191,189 / 60,548**, within 192 KiB / 64 KiB. Vault JavaScript remains
**302,958 / 87,015**. All existing budgets pass without adjustment; gzip figures
are local estimates.

Productive copy orchestration is next, followed by qualified issuer/launcher
delegation. Approval still leaves the preparation reserved and creates no
repository, credential, task, grant or run. Production flags/bindings and the
two baseline migrations are unchanged. Protected Artifacts resources/journals
and the preserved stash remain intact. No push, deployment, remote CI claim or
real provider mutation is included. This record changes documentation only; the
selected Worker source remains `14e7b4a`.

## Approved copy orchestration and owner progress

Selected product source `34f31ca347c7f848fbf0552039f98d157fc15b86`
combines the Native job/UI integration at `f489d80` with terminal Workflow queue
reconciliation, instance-ID validation and retained progress after consent
withdrawal. [The orchestration note](work-copy-orchestration.md) records the
closed transport, fixed sequence, safety behavior and activation requirements.
The separate opt-in migration 0014 creates no jobs automatically.

Rust queues and audits one job for the exact approved preparation before
notifying the private starter. Each of 19 phases has covered primary admission
and completion; fixed gates keep their independent permanent admission. The
Workflow transports only the preparation ID and ordinal. Its identity is
`copy-<preparation_id>` and it validates the actual event instance ID. Productive
step retries are disabled. A lost notification is recovered by the bounded
scheduled drain. A completed, errored or terminated instance with a remaining
queue is reconciled through Native safety; it is never restarted.

One owner start drives two real loopback Git copies, four synthetic scoped mints,
all six credential closures and independent full-copy verification. It creates
no request, prepared task, grant or run. An accepted push with a lost reply or an
already-inflight step retains a stop and known-ID cleanup without another Git
send. Cancel also fences a custodied mint before Git. Frozen Native authority
retains independent cleanup evidence and the charged unresolved Native
obligation; it does not claim closure or copy completion. No observed token ID
is invented, and blocked jobs cannot be deleted or reactivated.

The authenticated progress bundle adds explicit start acknowledgement,
read-only refresh and stop/credential cleanup. It distinguishes saved queue,
running, blocked/unknown and verified status. Hidden state, lock and navigation
discard acknowledgement; a start committed before its response arrives after
lock does not restore the view. Japanese/English, keyboard, accessibility and
375px rendering are checked. Screenshots in `artifacts/work-copy-job/` were
visually inspected. Withdrawal preserves the progress link for existing copies
without offering another start. Completion states that delegation remains
unperformed.

Qualification scopes are deliberately separate:

| Selected source / check                                    | Result and scope                                                                                                                                                                                                                                                                                                 |
| ---------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Clean `f489d80`, broad serial regression                   | **423/423** across existing work authority, checkpoint, custody/effects, mint/recovery/refusal, fixed Git/readback/evidence, owner/source/preparation/consent/composition UI, new copy driver, OP/service boundaries, enrollment, logout and display lease.                                                      |
| Clean `34f31ca`, final serial copy regression              | **26/26** covering Native/product API, real Workflow engine and Git, queue/step audit rollback, concurrency, source/session/checkpoint loss, lost accepted push, cleanup, flags, closed projections, terminal queue recovery, wrong Workflow ID, browser progress and continued access after consent withdrawal. |
| Clean `34f31ca`, isolated Owner Vault browser lane         | **2/2**, after the copy run completed.                                                                                                                                                                                                                                                                           |
| Native workspace                                           | **213/213**, including doctests; production Wasm Clippy denies warnings.                                                                                                                                                                                                                                         |
| Baseline/Owner schema, roster, release/reset and Agent SQL | **39/39**.                                                                                                                                                                                                                                                                                                       |

The final refinements change Workflow transport and the progress link after
withdrawal, with dedicated fixture/browser coverage. Native Rust is unchanged
from the broad regression. Both product and qualification Workers were rebuilt
for clean `34f31ca`, and OP packaging finished before the final runtime tests.
Node/Worker UI/service/source/effect/checkpoint/
Workflow types, Rustfmt, full Prettier, the **634-key** bilingual catalog,
product-source and documentation checks pass. CI/PR preparation lanes include
the copy driver and progress browser cases; `test:work-copy-job` is the focused
build/test command.

The budget artifact and embedded Worker identify clean `34f31ca`. OP Wasm is
**7,335,952 raw / 2,518,529 gzip-estimate bytes**, within 8 MiB / 3 MiB. Served
source/preparation/progress JavaScript is respectively **179,999 / 57,145**,
**191,626 / 60,596** and **167,516 / 52,744**, within 192 KiB / 64 KiB per
entry. Vault JavaScript remains **302,958 / 87,015**. Existing budgets are
unchanged; gzip values are local estimates.

This is local qualification with synthetic SSO/provider identity and real Git
bytes. Registered source materialization and trusted Git-host deployment must
be provisioned and qualified before enabling actual dev Artifacts copies.
Qualified issuer/launcher delegation and activity/result controls remain later
gates. Production flags/bindings, the two baseline migrations, protected remote
resources/journals and preserved stash are unchanged. No push, deployment,
remote CI execution or real provider mutation is included. This delivery record
changes documentation only; selected product source remains `34f31ca`.

## M6f: Sealed source registration and private Container Git host

Selected host/provisioning source is clean
`96b33df86dc4db254dd8685ac0ea4cb71ad38502`.
[The host note](work-git-host.md) records the operator inputs, runtime trust,
private R2 layout, fixed ports, resource bounds and remote qualification order.
Native Rust, product UI, production configuration and migrations are unchanged
from the previously qualified product source `34f31ca`.

The local operator tool consumes an authenticated Native disclosure export and
exact configured source capabilities. It checks current source/access revisions,
code history and object inventory, selected content hashes and Native's planned
snapshot commit/tree before registering two sealed packs. The task retains its
reviewed reachable code history; the snapshot contains one deterministic
parentless commit with only selected context. Source paths are operator inputs;
an owner request cannot choose a path or URL. An exported file is data, not an
authority token or independently signed Native attestation.

The generated Linux image contains the bundled trusted program and Dockerfile
only. Source packs stay outside image layers and enter the ephemeral Container
from a pinned private R2 package. The Worker checks the registry digest before
provisioning; Linux checks pack size/hash, strict Git indexing, exact reachable
objects and full fsck before activation. Wrong pins, tampered packs, symlinks,
extra objects and changed Native/source facts are refused. An activated process
cannot accept another registry or expose source content through an API.

The named `WorkGitHost` entrypoint is available only through the private binding;
its public default handler stays 404. The actual Durable Object Container API
uses a stable authority/disclosure name and immutable SQLite configuration frame.
Four permanent role/purpose slots are synchronized before Container/provider
I/O. Lost replies, competing delivery, fresh attempt IDs and runtime restart
cannot resend a charged call. A per-process Linux fence also refuses duplicate
TCP delivery. None of these records supplies Native approval, custody, copy
verification or delegation authority.

The final serial regression passes **64/64** with clean selected host source:

| Check                                                 | Result and scope                                                                                                                                                                                                      |
| ----------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| New host/provisioning cases                           | **11/11**: exact Native materialization, selected-only packs, private bounded listener, immutable SQLite/restart admission, real local R2 provisioning, sealed-host Workflow/Git and the explicit Linux Docker image. |
| Existing copy/Workflow/progress and OP boundary cases | **26/26**, using the unchanged product/qualification bundle built from clean `34f31ca`.                                                                                                                               |
| Existing permanent Git gate and independent readback  | **24/24**, with real Git bytes and synthetic provider identity.                                                                                                                                                       |
| Existing pack preflight/strict indexing               | **3/3**.                                                                                                                                                                                                              |

The TAP report is
`local/generated/work-store-main/git-host-96b33df.tap`.
The Docker receipt in `artifacts/work-git-host/container.json` pins the bundled
program, Dockerfile and built image; the image runs on `linux/amd64` with a
1 GiB memory cap and one CPU. It covers cold refusal, wrong package/pack refusal,
exact activation and absence of rebinding/source routes. This is not a capacity
or Cloudflare cold-start latency claim.

Node and Git-host Worker type checks, generated binding types, full Prettier,
product-source, documentation and diff checks pass. Wrangler 4.148.0 packages
the clean host Worker with `deploy --dry-run --containers-rollout none`:
**782.06 KiB raw / 123.33 KiB gzip**. This checks Worker/configuration packaging;
the separate Docker lane qualifies the Linux image locally. Neither checks
remote R2 resources or actual Cloudflare Container scheduling/TCP routing.
CI/PR preparation lanes include the host/R2/restart cases and explicit Docker
lane. No remote CI result is claimed.

This run reuses the exact unchanged `34f31ca` Native/UI bundle and does not claim
a new Rust workspace, full 423-case or Owner Vault/budget qualification. Their
earlier results and selected sources remain recorded above. Runtime host code
is bundled from `96b33df` during these tests.

Next: qualify private ingress, cold provisioning and operation latency in an
isolated Cloudflare environment using owner-authorized non-sensitive sources;
then reconcile the original protected development allocations before a real
Artifacts trial. The six protected repositories/journals and preserved stash
remain intact. No push, remote deployment, provider create/mint or production
activation is included. This delivery record changes documentation only;
selected host source remains `96b33df` and Native/UI source remains `34f31ca`.


## Integrated composition, consent, Workflow and sealed host

Selected product source is clean
`5cf46162a08b3496ae1b49eda1a7e9f024e6a0e6`. It merges the qualified
Workflow/progress changes and Git-host provisioning without replacing their
independent permanent admissions. The previous browser-driven bounded-copy
candidate remains preserved; this integrated product uses the Workflow engine.

The public composition API creates a new preparation without approval or job
side effects. Its exact Native disclosure then supplies the sealed host package.
Separate owner approval and explicit start drive both real Git copies, six
credential closures and final Native verification. Mint completion now also
requires explicit OP synchronization; the verifier response must identify the
same preparation and verified state alongside the actual Native verified record.

Additional tests complete the first initial effect before withdrawing consent,
raising the release floor, changing the provider account, removing the wrapping
key or reaching the real session/deadline expiry. Each fences the next effect
without creating another repository, minting or sending Git. Persistent restart
retains one queued job; a replacement same-owner login cannot adopt its original
session-bound consent. SSO fixtures are seeded before enrollment, and expiry
uses elapsed time instead of direct protected-row mutation.

| Check | Result and selected scope |
| --- | --- |
| Existing authority, checkpoint, custody, effects, mint/recovery/refusal, fixed Git and evidence | **311/311** at `1849e00`; Native production Rust is identical to the selected source. |
| Existing owner/source/preparation/consent/composition UI, lease and OP/service/enrollment/logout regressions | **89/89** at `1849e00`. |
| Final integrated copy/Workflow/progress, OP boundary and host/provisioning suite | **43/43** against the clean rebuilt `5cf4616` product and fresh qualification entry. |
| Isolated Owner Vault browser lane | **2/2** against `5cf4616`, after the integrated run completed. |
| Native workspace and production Wasm Clippy | **213/213**, including doctests; warnings denied. |
| Baseline/Owner schema, roster, release/reset, Agent SQL, static SQL and budget-unit checks | **45/45**. |

These are **445 passing runtime cases across the recorded scopes**, not a
single-source rerun of all previous checks. The final rerun changes only the
test fixture action to the actual `raise-floor` protocol; production source
stays `5cf4616`. The Node/Worker UI/service/source/effect/checkpoint/Workflow/
Git-host type checks, Rustfmt, full Prettier, product-source, **634-key** bilingual
catalog and documentation checks pass. Japanese/English and 375px copy progress
screenshots were visually inspected. The explicit Docker image lane remains
qualified at its recorded unchanged host source `96b33df` above.

The budget artifact and embedded Worker both identify clean `5cf4616`.
OP Wasm measures **7,339,046 raw / 2,518,742 gzip-estimate bytes** and Claim Wasm
**708,537 / 234,998**. Served source/preparation/progress JavaScript measures
**179,999 / 57,145**, **191,626 / 60,596** and **167,516 / 52,744** respectively.
Vault JavaScript remains **302,958 / 87,015**. All existing budgets pass without
adjustment; gzip figures are local estimates. The integrated TAP report is
`local/generated/work-store-main/workflow-integration-5cf4616.tap`.

Next remains isolated Cloudflare private-host ingress, cold provisioning and
latency qualification, followed by reconciliation of the original protected
allocations before a real dev Artifacts trial. Qualified issuer/launcher
contracts and activity/result controls follow for delegation. No push, remote
deployment, provider create/mint, production binding/migration change or remote
CI claim is included. Protected journals/resources, old branches and the
preserved stash remain intact. This delivery record changes documentation and
a test action only; selected product source remains `5cf4616`.

## Isolated Cloudflare host: verified startup and retained restart gap

Selected infrastructure source is clean
`0b47be3a58cc705701848c18cce6bff33b362a1d`. It adds an infrastructure-only Worker
sharing the productive host's startup, private-port readiness and R2 provisioning
code. Its private RPC accepts no arguments, disables Internet/Git and permanently
charges at most three attempts before I/O. The SQLite frame fixes the selected
account, namespace, artificial authority, disclosure and registry. No copy grant,
Artifacts create/mint/Git, run or delegation authority is supplied by this probe.

The actual Native, OP and qualification fixture bundles were rebuilt from clean
`0b47be3` before final qualification and packet materialization. Native production
Rust/UI are identical to integrated `5cf4616`; the older `34f31ca` build was not
used for the final selected results. The final serial regression passes **76/76**:

| Check | Result and selected scope |
| --- | --- |
| Host, Linux, provisioning and infrastructure RPC/retention | **16/16**, including actual qualification classes and real local R2; local Container capabilities remain synthetic where identified. |
| Integrated copy/Workflow/progress and OP boundary cases | **33/33** against the rebuilt integrated product, including the public composition/consent flow and partial-progress authority loss. |
| Permanent Git gate and independent readback | **24/24** with real Git bytes and synthetic provider identity. |
| Pack preflight and strict indexing | **3/3**. |

The TAP report is `local/generated/work-store-main/git-host-0b47be3-rebuilt.tap`.
This run does not claim another full 445-case, Rust workspace or Owner Vault
qualification. Their earlier selected-source results remain recorded separately.
The Linux Docker receipt pins its actual bundled program and Dockerfile; the
separately published Cloudflare image has its own immutable digest below.

The existing environment API token supports this lane. The installed CLI's saved
Artifacts OAuth scope check was bypassed by selecting the dedicated qualification
profile, not by changing the token or adding an OAuth grant. Fresh inventory
confirmed the selected Worker/Container names and R2 bucket were absent before
creation. Only the separate qualification resources were allocated:

| Selected resource | Provider observation |
| --- | --- |
| Account | `4b749427a0c80c547e726a42aff4b6fc` |
| Worker and Container application name | `mikaki-work-git-host-qualification` |
| Worker version | `0e787e82-1ad5-49a1-86be-aedb9d2fadc1` |
| Container application / SQLite namespace | `7ce0a33510eb45379d20361d84b7f350` |
| Private R2 bucket | `mikaki-work-git-host-qualification`, APAC / Standard; R2.dev disabled, no custom domains. |
| Registry digest | `bd7b5c0ab282aefb7babaef312cd34ae724e1da95cd9c2ca90b3c31ceabef911` |
| Artificial disclosure digest | `5fea0f22bce6a743ebcc60944599b64a9a32d61c0b24eec7e324558cb51f968f` |
| Cold readiness | **8,236 ms**, ordinal 1, new start, exact image/registry/disclosure. |
| Warm readiness | **19 ms**, ordinal 2, existing process, same pins. |

The published image is
`registry.cloudflare.com/4b749427a0c80c547e726a42aff4b6fc/mikaki-work-git-host-qualification-githostqualificationcontainer-host@sha256:2e34ccaed798efe7da7072ee4ea46619cab2b254f0c008fa52c995c468595afa`.
The frozen packet is
`local/generated/work-git-host-qualification/git-registry-g1ACm0`.
Its three R2 objects—814-byte registry, 480-byte task pack and 327-byte snapshot
pack—were uploaded once and independently read back with exact byte equality.
Provider metadata verified the private service binding, fixed image and bucket,
with `WORK_GIT_HOST_ENABLED=false` and `WORK_GIT_PROVISION_ENABLED=true`.
Workers.dev and previews are disabled; no public route was deployed.
Worker packaging measures **809.72 KiB raw / 125.05 KiB gzip**. These measurements
cover a small artificial Native disclosure and do not qualify remote enrollment,
personal content, production capacity or Git egress.

The original third call followed a 75-second wait with the authenticated proxy
still open. Its intent is retained, but qualification stopped before saving its
reply. The cause and remote admission/outcome cannot be reconstructed from the
journal. Later read-only inspection at `2026-10-10T05:27:20.226Z` found the same
named DO without an instance mapping in the legacy dashboard listing; scoped
telemetry returned no events. These observations prove neither native Container
stop nor successful restart during the third call. No fourth `prepare()` call,
replacement packet, new authority, slot reset or resource deletion followed.

Client source `40ad040074f710a20e92005935a8c19a70a44a38` corrects the probe: release
the proxy after warm readiness, wait 225 seconds, reconnect for the third call,
and retain closed responses before checking selected expectations. Arbitrary
fields/strings are refused without being persisted. The Container's 60-second
grace follows DO inactivity; waiting 75 seconds from the last call was not a valid
stop assumption. A longer wait is still not proof of stop, so a warm third reply
continues to fail. The **8/8** focused tests at that clean client source verify
actual RPC/SQLite retention, connection release, mismatching response evidence,
missing-reply stop and invalid-response redaction. Their report is
`local/generated/work-store-main/git-host-qualification-40ad040.tap`.
This client correction was not rerun against the retained remote sequence and
does not change the deployed Worker/image or the three-slot contract.

Node and Git-host Worker type checks, full Prettier, product-source, documentation
and diff checks pass. Retain all selected packet metadata and original journals.
The extension below implements retained inspection/outcome handling and an
independently bounded restart against the existing qualification, preserving the
original attempts.
Enrolled Native authority and reconciliation of the six protected development
allocations precede productive Artifacts exchange. No Git push, production binding
or migration change, remote CI claim or productive activation is included. The
preserved stash and protected Artifacts resources/journals remain intact.

## Isolated Cloudflare host: retained outcomes and independent restart

Clean source `1e0ef8ee4fd0d00513558d62118a87186ab799d7` extends only the
infrastructure qualification Worker and client. The original immutable frame and
three `prepare()` slots stay unchanged. New immutable outcomes are synchronized
before replying; older missing outcomes remain `null`. Private `status()` reads
the frame, admissions, outcomes and Container running attribute without startup,
TCP, Linux/R2 access or a probe charge. Its constructor creates additive schema.

A separate, fixed `inactive_restart_v1` slot requires the retained frame, all
three original admissions and an available Container reporting `running=false`.
Its admission is synchronized before I/O; ready/failure results are synchronized
before the reply. Unknown or failed outcomes cannot rearm the slot. The client
retains a closed reply before validation, checks it against a read-after-result,
and preserves the original attempt rows. Read-only inspection can reconcile a
retained success without replaying startup. This grants no productive authority.

The final selected-source serial suite passes **17/17** in **6,118.84 ms**:
15 qualification RPC/SQLite/retention and client cases, plus two shared startup/R2
cases (parent and subtest). It executes the actual qualification classes through
workerd/RPC/SQLite, with explicitly synthetic Container capabilities locally;
shared provisioning uses real local R2 and Linux bootstrap. Its report is
`local/generated/work-store-main/git-host-restart-1e0ef8e.tap`. Node and Git-host
Worker type checks, full Prettier, product-source, documentation and diff checks
pass. This does not claim a new full 76/445-case, Native/UI or Rust workspace run.
Shared productive startup/Linux/source code remain identical to `0b47be3`, whose
Native/UI match integrated `5cf4616`.

The frozen revision is the original packet's exclusive `restart-qualification`
child. It pins the original hashes, existing resources/image, new clean source
and Worker bundle. Fresh provider reads verified the selected authentication,
exact account/resource IDs, private bindings and disabled R2 public access.
Only the qualification Worker was deployed; no new resource identity, source
pack upload or Linux image build/push occurred:

| Observation | Verified result |
| --- | --- |
| Worker version | `2c713309-af9b-4c86-9232-61a5212e64e0`, replacing `0e787e82-1ad5-49a1-86be-aedb9d2fadc1`. |
| Worker bundle SHA-256 | `dc9a522ff12d512e471d1ce0d4dede07bf6b75ba7284ce532f1a925174523bd0` |
| Worker package/startup | **815.29 KiB raw / 125.95 KiB gzip**, **14 ms** provider startup. |
| Namespace / Container application | Unchanged `7ce0a33510eb45379d20361d84b7f350`; same DO name and immutable image above. |
| Before restart | Actual private RPC returned `running=false`, three original admissions and no restart admission. |
| Independent restart | Exactly one RPC; ready in **2,127 ms**, `started=true`, exact image/registry/disclosure. |
| Result retention | Read-after-result matches the immutable ready reply; all original attempt rows unchanged. |
| Natural stop | Native instance metadata: start `2026-10-10T11:37:58.036Z`, stop `2026-10-10T11:40:15.463Z`. |
| After stop | Actual private `status()` returns `running=false` with the same retained ready result and original rows. |

The client disconnected after its read-after-result. Subsequent lifecycle reads
used the provider API without calling or stopping the DO. The native running
interval was **137,427 ms**; it is a fixture observation, not an idle-timeout or
performance guarantee. The original stored outcomes remain `null`, and this
separate success does **not** qualify the original third attempt.

The legacy `/containers/dash/applications/<application>/instances` endpoint and
installed Wrangler 4.148.0 instance listing omit native mappings even while the
Container runs. An initial observer inferred stop from that absence; a private
status read contradicted it. The observation and correction are retained, and
absence was rejected as shutdown proof. The correct native endpoint is
`GET /accounts/<account>/containers/applications/<application>/instances`:
verify the exact DO ID/name, image, `status.state` and transition timestamps.
Native stopped metadata and the later private `running=false` result independently
agree. The latter read can wake the DO but does not start the Container.

The exclusive child retains deployment/provider receipts, `restart-run.jsonl`,
inspection files, native runtime/lifecycle observations, the legacy correction
and a hash-linked `qualification-outcome.json`. The original frozen packet and
journal are unchanged. Internet remains disabled, Git dispatches remain zero,
and no Artifacts create/mint/Git, production activation, remote CI qualification
or protected-allocation change is included.

Next are enrolled remote Native/checkpoint authority and read-only reconciliation
of the six protected development allocations before a productive Artifacts copy
trial. The stash and protected repositories/journals remain intact. The
[qualification protocol](work-git-host-qualification.md) records the fixed
admission, inspection and lifecycle procedure.

A subsequent independent read-only status RPC again returned `running=false`,
the identical **2,127 ms** retained restart result and all three original
admissions with their outcomes still `null`. The original packet hashes and
hash-linked restart evidence also match. The additional check performs no
startup or productive Git call; its receipts are
`artifacts/work-git-host/restart-independent-verification.json` and
`artifacts/work-git-host/restart-final-status.log`.

## Protected Artifacts allocations: current read-only inspection

Clean selected source `c8f26a1fcf375d4d8dd09533136f0f5700e81159` adds an operator
inspector for the six existing allocations. It pins the exact bytes of the three
original journals, checks plan/result/ledger identities, and projects only the
original attempt/repository IDs, names, state and token observations. There is no
ledger import, state settlement, productive adoption or new checkpoint identity.
The [effect note](work-artifacts-effect-gate.md#read-only-protected-allocation-inspection)
records the fixed GET routes, bounded pagination, secret omission and receipts.

The actual remote run completed from `2026-10-10T14:25:53.410Z` to
`2026-10-10T14:26:00.246Z`. Its **21 GET requests** comprise the OP settings read,
initial/final complete namespace inventories and metadata/token/metadata for
each protected allocation. The namespace contains seven repositories: the six
protected allocations and the historical `mikaki` bootstrap copy. No bootstrap
token or Git endpoint was accessed. All six selected repositories matched their
original ID/name/remote, reported `status=ready`, and had stable metadata before
and after the all-state token read. The final namespace inventory matched.

| Original journal / role | Original repository ID | Current token inventory | Retained state |
| --- | --- | --- | --- |
| `probe-09Ae4P` / task | `b0vt3pbxrvm0bram` | One write token, revoked; retained token ID matches. | `closed` |
| `probe-09Ae4P` / snapshot | `tmtcnyg5hmrc19o7` | One write token, revoked; retained token ID matches. | `outcome_unknown` |
| `probe-jYdl3a` / task | `qv9hbgpm7dastf4y` | One write token, revoked; retained token ID matches. | `closed` |
| `probe-jYdl3a` / snapshot | `2g2ai4k3xhztc2g9` | One write token, revoked; original journal had no token observation. | `outcome_unknown` |
| `probe-zgwc8e` / task | `ou3gvryxvx1vlpzg` | One write token, revoked; retained token ID matches. | `closed` |
| `probe-zgwc8e` / snapshot | `aop5yrrfwwyzb1um` | One write token, revoked; retained token ID matches. | `outcome_unknown` |

There are **zero active tokens** among the six protected repositories. The newly
observed `probe-jYdl3a` snapshot token ID is retained only in the new inspection;
the original journal is unchanged. All six report `last_push_at=null`, but this
is metadata, not independent Git content/readback evidence. Revoked-token
metadata does not reconstruct a lost create reply or qualify fresh bearer
refusal. All three unknown initial-effect outcomes remain unknown and charged;
historical closure records are neither downgraded nor newly certified.

The existing environment API token successfully reads current `mikaki-auth`
settings; the separate saved Artifacts OAuth credential successfully reads
Artifacts. A diagnostic Artifacts GET with the environment token returned 401,
so it is not used for that control plane. No OAuth consent, grant or token
configuration changed. Only binding names/types are retained from OP settings,
with no values. Current OP has **no `WORK_` bindings**, including no
`WORK_AUTHORITY_CHECKPOINT`; no Native/checkpoint authority RPC or remote D1
operation was invoked. This establishes the missing connection, not enrollment
or a broader production authority audit.

Final focused qualification at this clean source passes **11/11** in
**437.73 ms**. It covers fixed v4 GET target selection, both cursor and observed
offset pagination, stable counts, duplicate/replacement/changing identities,
secret omission and preservation of unknown journal states using synthetic
HTTP/provider responses. Actual GET receipts separately establish the selected
remote observations. The report is
`local/generated/work-artifacts-inspection/inspection-c8f26a1.tap`. Node types,
formatting, product-source, documentation and diff checks pass; the new focused
test is registered in CI, without claiming a new remote CI or full product run.

The complete receipt directory is
`local/generated/work-artifacts-inspection/inspection-loAfNJ`. Its exclusive
`result.json` has SHA-256
`52e129ea44f0909400f3acc35b6f3209a2fc10d29e80de370a3cd9ebd7eeb298`;
the synchronized `inspection.jsonl` has SHA-256
`ad97795e772b67a751774da98f135226ae6ece31b4659f14864a56a2e66b9b27`.
Earlier incomplete read-only attempts remain separately retained. A v4-path
admission error was corrected, and the deployed REST API's additional ready
status/offset pagination were explicitly qualified. No failed observation was
treated as a complete inventory. The original three journal hashes are unchanged.

Next prepare an isolated Native/OP and independent checkpoint connection with
dedicated D1/R2 identities, a reviewed clean source/schema/binding inventory and
actual owner enrollment/consent. Verify source registration, current owner/session
authority and revocation refusal before productive Artifacts mint/Git. The old
synthetic checkpoints and unknown admissions must not be imported as authority
for this new environment. Existing OP production configuration, migrations,
Git-host resources, repositories, tokens, journals and stash remain unchanged.

## Isolated authority preparation and frozen-module qualification, 2026-10-11 JST

The [isolated authority note](work-authority-qualification.md) fixes the proposed
dedicated Native/OP, D1, Owner Vault R2, logout Queue/DLQ and independent SQLite
checkpoint. The OP receives only `WorkCheckpointService`; operator bootstrap,
floor/freeze and OP authority administration are separate unresolved transports.
Resource IDs, HTTPS origin, owner, source reader and initial marker remain
unresolved. Templates disable public Workers URLs, cron writers, composition,
copy, initial effects, mint and Git. There is no production-resource fallback,
provider bearer, Artifacts binding or imported authority.

Clean selected source `4d0870acfe5d3a99ed1178c1f0c275f88fdd1890` generated
`local/generated/work-authority-qualification/authority-nMECMX` using locked,
offline production Rust, current OP service packaging and the checkpoint bundle.
The complete **35-member** packet contains fourteen frozen migrations: the exact
two-file Owner Vault baseline plus Work `0003`–`0014`. In-memory SQLite verifies
foreign keys, **449 schema objects** and empty authority tables. The schema digest
is `8b8b09afbc7454ac8da1dfd62db08e687e280e6b0cdab7588786ac1c16c4b1b1`.
The manifest digest is
`5b06b4588934813995f965bf5e76da9c44d7e08c98045519192f888bdd2a02d3`.
Wasm is **7,336,255 bytes**, with a **2,518,660-byte gzip estimate**, and contains
the selected commit. This is a local byte/build inventory, not signed provenance.
The selected frozen OP Wasm passes its existing **8 MiB raw / 3 MiB gzip**
budgets using the shared measurement function; its receipt is
`local/generated/work-authority-qualification/wasm-budget-4d0870a.json`.
The full current-HEAD budget command refused the older selected build's source
identity after qualifier-only commits. No full current-HEAD UI/claim budget run
is claimed from that refusal or the focused frozen-Wasm measurement.

Packet/schema rejection tests pass **8/8** and are registered in CI. They cover
baseline changes, silently enrolled migrations, missing files, unexpected files,
bundle/schema substitution, source mismatch, production D1 substitution,
symlinks and file bounds. Actual Wrangler 4.148.0 dry-run discovers the complete
generated ESM/Wasm module tree and reports **8,037.70 KiB total / 2,599.67 KiB
gzip**; it uploads nothing. The unbundled test-harness path initially omitted the
Rust shim. The qualifier now uses explicit Miniflare module roots/list matching
the frozen upload and manually follows the same-origin enrollment redirect.

Clean qualifier `5573245f7aefd44769527260db11453dfc9a14e5` loads these frozen
modules in actual local workerd with disposable D1/SQLite DO. It applies the
packaged fourteen migrations, observes no owner/checkpoint authority, serves
`/enroll`'s 302 and its actual login page, refuses unauthenticated `/work/session`
with 401, refuses fixture/admin HTTP routes and checkpoint default HTTP with
404, observes 409 for the uninitialized checkpoint service, and refuses bootstrap
through that OP service with 400. No account or checkpoint is enrolled.
The exclusive receipt is
`local/generated/work-authority-qualification/runtime-4d0870a.json`, SHA-256
`13fce28e6826c44dee5725534e0d6833873b39358fb56e42c8207de0bb961899`.

Next qualify bounded operator allocation/materialization and one-time authority
bootstrap, plus framed source registration, before opening actual owner ingress.
Separate deployment/restore ownership, fresh signing-key custody, real Passkey/
PRF completion, current source/policy mapping, owner consent and revocation remain
remote gates. Primary D1 and independent enrollment have no distributed atomic
commit; bootstrap keeps all writers quiescent until exact matching state is
observed. Unknown replies never authorize another epoch, reset or replacement.
The original three protected journal digests still match their retained pins;
unknown admissions remain unknown and charged. No remote allocation, migration,
deployment, provider/Git effect, production activation or new remote CI result
is claimed by this increment.

Node types, full formatting, product-source and documentation checks pass. The
focused packet cases and the existing three budget-checker cases pass; these
are local results rather than a new remote CI or full product regression run.

An independent preparation from the same clean `4d0870a` produced
`local/generated/work-authority-qualification/authority-Of8NYc`, also with 35
members and the identical schema. Comparison with the selected `authority-nMECMX`
finds only `build-1.log` different; all packaged modules, migrations, templates
and other inputs match. Its manifest SHA-256 is
`6aca4caae16dbf73b197cb35ea16e2a3bc9db1e831664f283fbf0cbfdb5006f7`.
Clean qualifier `ecb3f9c` successfully repeats the frozen-module runtime check,
with no account/checkpoint enrollment or remote operation. The additional
receipt is `artifacts/work-authority/independent-qualification-ecb3f9c.json`.

## Bounded initial authority enrollment, 2026-10-11 JST

The [isolated authority sequence](work-authority-qualification.md#bounded-initial-operator-protocol)
now has a narrow `WorkCheckpointBootstrap` capability and a bounded operator
library. The new capability accepts one closed reviewed-packet/resource plan,
checks the deployment's packet pin and exact object, and retains that plan with
the initial marker in one synchronized SQLite transaction. Its two RPC methods
return JSON data strings; default/named HTTP and framing, effects, floor/freeze
or reset calls are unavailable through this capability. Legacy state cannot be
adopted as a new packet enrollment. OP retains only `WorkCheckpointService`.

The primary operator derives schema and all seed rows from the frozen fourteen
migrations. It checks the complete ordered migration ledger, schema, foreign
keys and every application table; marker insertion repeats schema/ledger/row
guards in one D1 batch. The first local attempt exposed the pinned runtime's
expression-depth limit; balanced predicates now permit the complete guard to
execute. The private operator configuration fixes account, dedicated D1 and
named checkpoint binding, with Workers public/preview URLs disabled.

An exclusive child journal is synchronized before each independent write.
Unknown replies consume that run; read-only inspection never resumes either
write, substitutes an epoch or resets authority. Exact initial agreement can
be observed after a lost primary reply, while pending, frozen, raised-floor,
legacy or changed-primary state cannot complete. Completion enables no writers.
The remote executor still needs a shared account/authority reservation across
child packets and linked checkouts, retained provider/module/config/version
observations and independently reviewed deployment/recovery ownership. Plan
IDs and review digests alone do not establish those facts or quiescence.

Actual local workerd/D1/SQLite DO tests pass **10/10**, covering both lost replies,
restart, exact initial agreement, one-time concurrent admission, private method
refusal, legacy state, primary changes between preflight and insertion, and
pending/floor/freeze refusal. The existing Rust OP/checkpoint regression passes
**16/16**, including D1 restore refusal and framed revocations. Frozen packet
tests remain **8/8**. The new suite is registered in CI; these are local results,
not a new remote CI or actual owner-enrollment result.

The old reviewed `authority-nMECMX` packet is preserved. Its checkpoint bundle
does not contain the new entrypoint/pin, so a new clean packet and a provider-
verified child deployment must be reviewed before remote enrollment. The
bootstrap increment performs no remote migration, checkpoint enrollment,
owner ingress opening or Artifacts/Git effect. Next connect the bounded remote
operator to verified retained resource identities, then qualify framed source
registration and actual Passkey/PRF owner enrollment under those gates.

## Partial closed authority resource allocation, 2026-10-11 JST

The once-only allocator pins the original `authority-nMECMX` manifest and shares
one exclusive account/lane reservation across linked checkouts. Private numbered
records and their parent directory are synchronized before each provider create.
Complete inventories are read twice; existing names refuse allocation rather
than being adopted. Twelve local rejection/acknowledgment cases and the eight
frozen-packet cases pass. The allocator is registered in CI; no remote CI result
is claimed.

Clean source `9f106f66d26d6f7ab0cf0ee0092df1d664520c18` sent exactly three
create requests in `local/generated/work-authority-allocation/allocate-kHIGYa`.
The dedicated D1 `mikaki-work-authority-qualification`, ID
`b2d340cd-bcc2-4a96-94a2-83edb93ff627`, and R2
`mikaki-work-vault-qualification` were acknowledged and their identities read
back exactly. The DLQ create returned HTTP 200 and API success, but the original
parser required optional attachment metadata before retaining its identity.
That parse failure consumed the DLQ slot as `create_outcome_unknown` and stopped
the sequence. The main logout Queue has no create intent and remains unattempted.
This was a tool error; it did not authorize a retry or replacement allocation.

The parser now retains the minimal acknowledged Queue name/ID/time first and
checks attachment counts in a separate read. Additional tests cover sparse
create responses and failure after preserving the acknowledged ID. The old
partial run and reservation remain unchanged. A later complete stable read
observes the DLQ name at ID `4f95485d3880458b9a14a8168b836498`; that list fact is
not adopted as its lost original acknowledgment. The audit API query for the
original request interval succeeded but yielded no matching evidence. The DLQ
create outcome remains unresolved and no further create was issued.

The original 236 records are inventoried in the private
`local/generated/work-authority-allocation/partial-allocation.json`, SHA-256
`496e39a4d6abf9970890ae1a63ee00c0fa4aa3b1c040400bb6a2f0bbc702ea4f`.
The retained reservation SHA-256 is
`5da004865d86681838b5935c3fb26b07466bbfa3f3c65cd6fbe2c777a9ca673a`.
Read report `inventory-sHCJeq/0043.json` SHA-256 is
`b5faaa57f321e680b8c746b911dddb391916dd6ab392e93b2f31464d379df88a`;
the audit receipt SHA-256 is
`a0eaf2368ab157cb36e4b03c4495a3d662a1152db3d159ab544d4af27ec910ff`.
All three protected Artifacts journal hashes still match their original pins.
No Artifacts/Git or production mutation was issued. Neither authority Worker
exists; no remote migration, checkpoint bootstrap or actual owner enrollment
has occurred.

Resolve the same DLQ admission with positive provider/operator evidence before
completing the remaining allocation or binding it into a child deployment.
Do not remove the reservation or reissue any consumed create. HTTPS origin and
OP/checkpoint deployment/recovery ownership remain unresolved; real Passkey/PRF
owner completion still requires the intended person. The new bootstrap library
is local qualification and must use a newly reviewed packet, not replacement
bytes inside the preserved parent packet.

While those remote gates remain unresolved, clean source
`be76c028b2d9862cae02f89bcb53994155e6ecc2` prepares a new frozen packet at
`local/generated/work-authority-bootstrap-qualification/authority-zFCHDp`.
It contains the new private bootstrap entrypoint, 35 members and the identical
449-object schema; the original packet and partial allocation are preserved.
Its manifest SHA-256 is
`101e4405e6eb3dfd40e50e46a1bdeaf6d8b886ec294f735b913864a943d53849`.
The frozen product/checkpoint local workerd qualifier passes all existing
empty-authority, fourteen-migration and public/service refusal checks, with
zero remote operations and no owner enrollment. Its receipt
`local/generated/work-authority-bootstrap-qualification/runtime-be76c02.json`
has SHA-256
`e16e2f1d6e91af1a78b01cd319445ed1b6decb7b7f116c58140afbad2c63f52c`.
The saved bootstrap source independently repeats **10/10** local D1/SQLite DO
cases without RPC disposal warnings. Node types, full formatting, product
sources and documentation checks pass. This is an offline preparation and
local runtime check, not a child deployment, remote enrollment, full current-
HEAD product budget/regression result or remote CI result.

## Offline authority deployment child gate, 2026-10-11 JST

The [child packet materializer](work-authority-qualification.md#offline-child-deployment-packet)
now derives closed Worker and local bootstrap-operator configurations from a
pinned parent, complete once-only allocation evidence and an externally pinned
origin/ownership/signing-custody review. It copies the frozen product, checkpoint
and migration members unchanged; parent and child manifests are retained
separately. Verification needs only the child and its externally reviewed digest.
Even a rewritten child inventory cannot substitute frozen parent bytes or add
the bootstrap capability to the OP. Both public routes and previews remain
closed, crons stay empty and productive execution flags stay disabled.

The journal reader follows the common-repository reservation, verifies consecutive
record membership and a stable read, and retains acknowledgments separately from
exact readbacks. Unknown or absent acknowledgments consume their original slot;
later reads, reports and replacement create intents cannot grant completion.
The current CLI cannot adopt the observed DLQ or reinterpret the stopped original
run. Positive recovery evidence and a separately reviewed append-only reconciler
remain necessary before completing that allocation.

Local inspection reads the original **236** records and verifies the fresh
`authority-zFCHDp` parent. It reports D1/R2 acknowledged and verified, DLQ unknown,
main Queue unattempted, and **no child materialized / zero remote calls**. The
private receipt is
`local/generated/work-authority-deployment/inspection-20261011/gate.json`;
its allocation evidence digest is
`e23cdb9bc1be812f11d7c5200ba6f9f56ef6feebadd49a002ed369487fb8f0dd`.
This digest inventories the original reservation and numbered record bytes in
the new evidence format; it does not replace the retained partial-allocation seal
or provider acknowledgment. No Worker deployment, remote migration, bootstrap,
owner enrollment, ingress or Artifacts/Git effect occurred.

The new **6/6** local materialization/rejection cases pass, together with **20/20**
existing allocation/frozen-packet cases and **10/10** actual local D1/SQLite DO
bootstrap cases. Node types, formatting, product-source and documentation checks
pass. The new suite is registered in CI; no remote CI, deployment/binding
qualification or full current-HEAD product budget/regression result is claimed.
Next resolve the same DLQ admission with positive evidence, then qualify the
remaining allocation and remote version/config observations under the retained
reservation. Shared bootstrap reservation and the bounded remote executor remain
separate outstanding gates.

## Positive DLQ creation recheck, 2026-10-12 JST

A read-only recheck identifies the original DLQ create in Cloudflare's legacy
[`audit_logs` API](https://developers.cloudflare.com/api/resources/audit_logs/methods/list/).
The earlier inspection used only the v2 audit endpoint and missed this record.
Both endpoints were queried over `2026-10-10T21:50:00Z` through
`2026-10-10T22:10:00Z`: v2 returns one unrelated create, while v1 returns the
DLQ `create_queue` with `action.result=true`. Direct lookup of audit ID
`bee80ee1-8440-46c3-b762-eff0a6d5f0e1` repeats the same single record.

The provider record matches account `4b749427a0c80c547e726a42aff4b6fc`, Queue
ID `4f95485d3880458b9a14a8168b836498`, and the metadata name
`mikaki-work-logout-qualification-dlq`. Its event time
`2026-10-10T21:57:50.458616Z` falls between the retained original DLQ create
intent (`21:57:49.291Z`) and its HTTP 200 observation (`21:57:50.515Z`).
The Queue creation time (`21:57:49.42237Z`) also falls inside that original
request interval. This is positive provider creation evidence for the same
allocation, rather than an inference from a later name listing.

Queue details read before and after the audit queries agree exactly. Producer
and consumer counts and their returned lists are all zero; the provider's
modification time still equals its original creation time. The original 236
records, reservation digest, partial seal and three protected Artifacts journal
digests remain unchanged. No provider write, retry, replacement, deployment or
bootstrap was issued.

The private receipt is
`local/generated/work-authority-allocation/recheck-wn8aMy/result.json`, SHA-256
`ef7bad9ee257da2641587a5f7e9b7d4da1b73ff3b2e4e8fdf93110d74df22c52`.
Its source is preserved beside it as `source.mjs`, SHA-256
`145392500eae3da7e15cf0c53c8be5a06c2d085a2ef2aa8e8ed941030cebdc30`.
The receipt contains the direct audit match and request-time checks without
actor identity, bearer or unrelated raw audit payloads.

The DLQ creation fact is now confirmed. The original journal still retains its
historical `create_outcome_unknown`; the deployment gate is not silently
rewritten or bypassed. A reviewed append-only reconciler can consume this
positive evidence before the unattempted main Queue allocation and child
deployment proceed. No new DLQ create is needed or authorized by this recheck.

## Audited reconciliation and completed authority allocation, 2026-10-12 JST

The [completion executor](work-authority-qualification.md#recovery-of-the-audited-dlq-and-completion-of-the-remaining-queue)
pins the original allocation/reservation and positive DLQ audit receipt. It
re-reads the provider audit and dedicated resource identities, reserves one
canonical shared completion directory, and retains recovery separately from
the original unknown outcome. Each numbered record and its parent directory
are synchronized before the one remaining create. The deployment reader now
validates both journals and their combined digest; partial or lost replies
cannot gain completion through a later list, repeated create or forged report.

Clean source `aa54f4b48af4e79ff8a489b4752efe332a203105` completed the run at
`local/generated/work-authority-completion/complete-KQTgO7`. Exactly one provider
create was sent: `mikaki-work-logout-qualification`, ID
`1c31bf78590749df87cd407aa02072b7`, created at
`2026-10-11T23:55:25.834808Z`. The acknowledgment, exact ID readback and complete
stable final inventories agree. D1/R2 retain their original identities, and
the DLQ is recovered by its original successful provider audit without another
DLQ create. Both Queues have zero producers/consumers; both proposed authority
Workers are absent.

The six completion records are retained under
`local/generated/work-authority-allocation/completion-v1`. The original 236
records, reservation, partial seal and three protected Artifacts journals still
match their retained digests. The combined evidence is
`complete-KQTgO7/allocation-evidence.json`, SHA-256
`dc05a94c13a04f07838324c9fe4185e9eedc70be01eec1541a350a1880393d26`;
the run receipt SHA-256 is
`ca35676884d55eaef77de39a05aabc99fb856781b6aa9029567fb5492b6761ad`.
Current allocation inspection reports **complete=true**, all four verified,
no current unknown/unverified/unattempted resources, and explicitly retains
`original_unknown=[logout_dlq]` with the audit recovery relationship.

The separate offline gate receipt is
`local/generated/work-authority-deployment/inspection-completed-20261012/gate.json`,
SHA-256 `c77639885b776229793c1e0a9a0715627ad212464033cb7f83c7af16d2b1306e`.
It verifies the frozen bootstrap parent and completed allocation and leaves
only origin/operator/recovery/signing-custody review before child preparation.
A local `deployment-review.draft.json` beside that receipt carries the fixed
packet/allocation/reservation digests and unresolved review fields; it cannot
be used as an approved deployment review.

The new **9/9** completion cases pass, together with **18/18** existing
allocation/materialization cases. Node types, affected-file formatting and
documentation checks pass; the new suite is registered in CI. No remote CI,
full product regression, migration, Worker deployment, checkpoint bootstrap,
actual owner enrollment, or production/Artifacts/Git mutation is claimed.
Next resolve the isolated HTTPS origin, separate OP/checkpoint deployment and
recovery ownership, and fresh signing-key custody, then prepare the closed
deployment child from these retained identities.
