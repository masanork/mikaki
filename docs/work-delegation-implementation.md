# Work delegation implementation plan

**Status:** M1–M4, M5a/M5b source/preparation inspection, owner selection composition, explicit copy consent and M6a–M6e mint/custody, recovery, Native bearer refusal, fixed Git upload/readback and preparation evidence composition are locally integrated on `feat/work-delegation-main` through `14e7b4a`, 2026-10-10 JST. Fresh-schema WorkStore, owner/source transport, independent checkpoint/OP framing and the bounded Git exchange are integrated. Productive copy orchestration, delegation, Cloudflare Git-host deployment and remote activation retain the next gates. No production activation is included.

Keep [ADR 0016](adr/0016-personal-context-and-workload-delegation.md) as rationale, [authorization](workload-authorization.md), [domain profile](workload-profile-v1.md) and [UI](work-request-ui.md) as contracts, and this file as delivery/qualification order.

## Preserved work and main baseline

The old `feat/agent-vault-oidc-qualification` branch at `d441ce0a4583ebcf1ae54627e2ca3df29e2f20a9` had no commits outside main and was 156 commits behind at the initial catch-up. Replaying its committed history adds no work.

Uncommitted work is preserved by stash commit `ea733061aefa6a3cb3262908aa685eb3337bc40d`, labeled `pre-main-catchup-20261008: preserve local work and qualification evidence`; its additional-file tree is `ceb868a163c1f21df9af3391c288bf672431ffa8`. Keep the stash until selected work/evidence is fully accounted for. It includes unrelated earlier changes and generated files; applying the whole stash is not the integration unit.

The root checkout was already clean on main at `8d48ba93fef64f4802627939ec63235eeef6aa68`. A fresh GitHub main-ref read matched that commit. New local branch `feat/work-delegation-main` starts there and retains main's newer dependencies, Owner Vault implementation and schema.

Main uses migrations `0001_owner_vault_initial.sql` and `0002_owner_key_wrap_operations.sql`. Retained work used the historical chain through `0047`–`0056`. Port additive work schema and current OP admission paths explicitly; do not restore retired migrations, obsolete Agent/Vault callers or old dependency locks to satisfy the old fixture.

Ignored `local/generated/work-*` evidence/state remains in place. Initial-effect journals account for **six empty development repositories**, including unresolved allocations. Empty inventory cannot close an unknown attempt. This integration neither resets those records nor deletes, recreates, remints for or adopts their resources.

## Main integration order

| Increment | Outcome and qualification gate | State |
| --- | --- | --- |
| M1: Portable rules/decisions | Restore ADR/AuthZEN/ABAC choices and Rust rules with main's dependencies. Native tests and Wasm compilation pass. | Complete locally: 35 unit cases plus one compile-fail case. |
| M2: Fresh-schema authority | Port WorkStore/SQL, bounded budgets and custody onto the fresh baseline; exercise current owner/session/source checks, exact retry, audit rollback and concurrency in actual Wasm/D1/R2. | Complete locally: 96 current-main qualification cases, including the reconciled M2 boundary cases. |
| M3: Checkpoint/OP framing | Port independent release floors and admission for current OP mutations; rehearse D1 restore and key/account/session/policy revocation while preserving safety reconciliation. | Complete locally: 16 checkpoint cases; activation gates remain. |
| M4: Initial effects/maintenance | Reconnect initial-create gate, read-only lookup and attenuating broker; requalify one-time admission, lost replies, immutable IDs, refusal and runtime RPC/binding limits. Resume protected remote journals without replacement creates. | Complete locally: 50 effect/capability cases; remote journal reconciliation remains pending. |
| M5: Source/product review | Integrate source selection, separate copy/delegation consent and owner projections into current product components; requalify Japanese/English UI and stable operation identity. | Owner selection composition and separate copy approval are integrated at `14e7b4a`; the exact-source qualification is recorded below. Prior consent qualification passes 167 work/OP/UI cases and 2 Vault browser cases at `311886a`; the complete 372-case run at `aa8f604` remains historical. Productive copy orchestration, delegation, activity/result controls and deployment remain pending. |
| M6: Upload/readback | Native authority fixes repository, scope, expiry and operation digest. Independently admit each mint and Git exchange once before I/O; unknown outcomes cannot replay. Capture plaintext only into encrypted custody. Independent full readback checks the actual Git copy. | M6a–M6e mint/custody, recovery, bearer refusal, fixed Git exchange and both-role evidence composition locally implemented; missing/unobserved custody, Cloudflare Git-host deployment and release remain pending. |

Preserved pre-main qualification passed 160 combined delegation cases, including 50 initial-effect/reconciliation/capability cases. Earlier UI qualification had 22 cases. Actual Artifacts initial creation, lost-create safety reconciliation and process restart were exercised using protected journals. These identify reusable work; they are **not current-main or production qualification**. The exact prior notes/fixtures remain in the stash.

Record selected source, implementation, checks and remaining gates for each increment. Commit reviewable units, then refresh Artifacts from a selected qualified commit. Old CI/release inventory or workspace overlays do not qualify new source.

M1 qualification passes `cargo test --workspace --offline --locked` (**209 cases**, including doctests), the auth Wasm target check, auth all-target Clippy with warnings denied, workspace formatting, product-source and documentation checks. Native workspace tests do not exercise the unported work HTTP/D1/Artifacts paths or production Workers. No prior Worker/browser qualification is counted as a current check.

M2 is integrated on `feat/work-authority-main-integration`, isolated from concurrent edits in the root checkout, after merging main through `1f0dd3c` (owner-selected v2 records for local Codex). Selected WorkStore, SQL, owner/source transport, credential custody and candidate archive code came from the preserved stash. Main's dependencies and the two production baseline migrations are retained. The [separate work migration ledger](../crates/worker/work-migrations/README.md) applies eight additive migrations explicitly in local fixtures; migration qualification verifies existing OP/Owner Vault records remain intact. Product review screens and production bindings are not activated.

Current M2 qualification: `npm run test:work-delegation` passes **94 cases**, including real Rust/Wasm/workerd/D1/R2 restart, concurrent single admission, exact retries, current session/source/policy checks, audit rollback, credential-key floors and independently checked Git archives. Node and source-Worker type checks, product-source and documentation checks pass. This is local evidence with synthetic workload-verifier facts. The pure owner projection module is included for the prepared-authority contract; the owner screens remain M5. Independent checkpoint/OP framing and new external effects remain M3/M4 gates.

## Product delivery backlog

The first usable outcome is one owner, one non-sensitive disclosure, one managed run, one candidate and one exact code adoption into an experimental development target. Code adoption and saving a decision require separate confirmations.

| Card | Outcome and prerequisites |
| --- | --- |
| WD-00 | Verified committed Artifacts development baseline and bootstrap cleanup; refresh from a newly selected qualified source. |
| WD-01 | Bounded workload profile and component ownership; M1 restores the portable portion. |
| WD-02 | Durable request/grant/run/approval/operation authority; M2/M3. |
| WD-03 | Actual context/snapshot/history review and copy consent; WD-01/02, M5. |
| WD-04 | Controlled launch and instance/client/key-bound exchange; WD-01/02 and named launcher/issuer verification. |
| WD-05 | Task-repository effects and credential reconciliation; WD-02, M4/M6, WD-04 before workload access. |
| WD-06 | One run submits a candidate with confirmed activity state; WD-03/04/05. |
| WD-07 | Exact owner adoption; WD-02/06 and independent candidate/evidence/write reconciliation. |
| WD-08 | Separate permission stop, execution stop and credential cleanup; integrate through WD-06/07. |
| WD-09 | Separate decision adoption and next-day handoff with fresh authority; WD-03/07/08. |
| WD-10 | Two-run comparison and individually qualified external clients; WD-09. |

Owner-enrolled clients, managed execution identity, Token Exchange, SPIFFE and AuthZEN HTTP retain distinct qualification gates. Internal ABAC rules do not establish issuer/PDP interoperability.

## Cloudflare CI lane

| Card | Completion boundary |
| --- | --- |
| CI-01 | Test-only Artifacts-triggered Workflow: fixed committed source/ref, passing/failing runs, exact checkout, reports, duplicates/cancellation and bounded cost. |
| CI-02 | Required Rust/Wasm/contract/browser parity at the same commit; qualified toolchain/cache identity and immutable reports/build bytes. |
| CI-03 | Isolated staging and trusted publisher: exact approval, binding/schema/secret inventories, upload/activation reconciliation. |
| CI-04 | Trusted provenance, recovery fencing, compatible rollback and one authoritative write direction before canonical migration. |

CI-01 can proceed separately once its exact source/resources are selected. Deployment credentials stay in the publisher boundary; a Workflow event, identity token or successful test does not grant production promotion.

M3 qualification passes **16 checkpoint cases** and **13 current OP regression cases** (production service/RPC boundary, bootstrap enrollment, ingress/retention and Queue logout). Production Worker build and OP authority packaging, Node/service/checkpoint-Worker type checks and production Wasm Clippy with warnings denied pass. Six pre-existing Worker Wasm style warnings exposed by the current dependency/toolchain were fixed in a separate commit. The [checkpoint note](work-authority-checkpoint.md) records the covered paths and remaining recovery/operator/release gates. The local fixture uses main's Queue-aware logout handler, with its actual event context.

The current production Chromium enrollment regression also passes: real virtual Passkey enrollment, additional credential/invitation flow, login retries and Owner Vault PRF behavior remain compatible without the opt-in work schema.

M4 qualification passes the complete **160-case** delegation suite (M2 94 + M3 16 + M4 50), using actual Rust/Wasm/workerd/D1/R2/RPC/DO and synthetic Artifacts/Git. Current production shim/facade, enrollment, Chromium Passkey/Vault, Queue and ingress/retention regressions pass (14 cases across selected files). The initial final regression run and a single-file repeat encountered a connection reset while the pre-existing fixture seeded 1200 SQL statements in one D1 RPC. Bounded seed calls now retain and assert the same 1200-row GC backlog, and the case passes. Product GC code and its convergence assertions remain intact.

Final validation also passes native workspace tests (**209 cases**), workspace all-target Clippy and production Wasm Clippy with warnings denied, Worker build/OP packaging, Node/service/source/checkpoint/effect type checks and full formatting. The OP Wasm is within its existing byte budgets (5,854,173 raw bytes; 2,077,741 gzip estimate). CI includes the new Worker type checks, the full delegation suite and production RPC boundary case. The [initial-effect note](work-artifacts-effect-gate.md) records the capability and recovery limits. These are local results; no remote CI result or production/Artifacts activation is claimed.

Next: connect productive copy orchestration to the explicit copy confirmation, then connect delegation to qualified issuer/launcher contracts and place the Git host on Cloudflare. M5a/M5b now compose and inspect selected preparations; M6a–M6e qualify the private mint/Git/evidence chain locally. Existing protected remote journals must be reconciled against their original identities before another real Artifacts trial.

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
