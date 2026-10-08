# Work delegation implementation plan

**Status:** M1–M4, M5a source inspection and M6a reconciled mint/custody, M6b known-ID recovery and M6c1 Git copy core locally qualified on current main, 2026-10-08 JST. Fresh-schema WorkStore, owner/source transport, independent checkpoint/OP framing, initial-effect maintenance, the source review screen and one-shot upload/readback credential minting are integrated. Copy/delegation composition, productive upload/readback and remote activation retain the next gates. No production activation is included.

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
| M5: Source/product review | Integrate source selection, separate copy/delegation consent and owner projections into current product components; requalify Japanese/English UI and stable operation identity. | M5a source review complete locally; copy/delegation composition and activity/result controls remain pending. |
| M6: Upload/readback | Native authority fixes repository, scope, expiry and operation digest. Independently admit each mint once before provider I/O; unknown outcomes cannot remint. Capture plaintext only into qualified encrypted service custody. Successful mint alone permits no workload release. | M6a one-shot mint/Native custody reconciled; M6b known-ID safety recovery and M6c1 fixed Git payload/readback core implemented. Private productive admission/custody use and release remain pending. |

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

Next: M6c2 connects the fixed Git copy core to independent productive admission and bounded private custody use, before M5's copy/delegation controls can complete that flow. Existing protected remote journals must be reconciled against their original identities before another real Artifacts trial.

Parallel M2 commit `ed7535d` is reconciled into this history. Its portable WorkStore/SQL matches the selected current implementation; current checkpoint, owner/source, effect and fixture changes extend it. The unified opt-in ledger preserves the root branch's numbering: work `0003`–`0010`, checkpoint `0011`, OP frames `0012`. Production baseline `0001`/`0002` and production configuration remain intact. Duplicate migration chains are removed; compatibility fixture names use the same tested implementation. The original [M2 checkpoint note](work-store-main-integration.md) is retained as historical evidence.

The reconciled current suite passes **162/162 cases** (M2 96 + M3 16 + M4 50). It preserves both parallel M2 ingress/enrollment boundary cases and checks the entire additive chain against existing schema definitions and Owner Vault rows. Node/Worker types, full formatting and documentation checks pass after reconciliation; the production-baseline/Owner-schema/release-inventory subset passes **11/11**. The fixture output is consistently `local/generated/work-store-main/`; pre-main `work-store/` output and protected remote journals are not rewritten.

A final main-ref read found `f03d656583f934ffe290bd45c81f73fa927a06a4`: one automatic metrics-only commit after `1f0dd3c`. Its three metrics files are included; it changes no application source, dependency or migration.

M5a adds authenticated source inspection with current product components, a shared display/session lease and separate bounded UI bundles. Current Japanese/English browser evidence covers actual selected Git content, keyboard/mobile/focus, CSP, stale membership, transport substitution, reload, lock/reopen and hidden-page late replies. The authority/effect/source-browser/lease run passes **178 cases**; the final bundle separation repeats the 15 UI/lease cases. Source page/asset/lease cold and owner boundaries are tested, including absent-checkpoint and release-floor refusal. The [UI note](work-request-ui.md) records scope and the remaining copy/delegation gates. The remote main ref was rechecked and remains `f03d656`; no history catch-up remains for this increment. No binding, production migration, deployment, provider token or protected remote journal is changed.

## M6a: One-shot mint and Native custody

The [mint gate](work-artifacts-mint-gate.md) connects the six fixed credential slots to Native plans and independent one-time mint admission. The current checkpoint, closed initial effect, immutable repository, purpose/scope, deadline and wrapping key are fixed before provider I/O. Permanent slots survive a whole primary restore; unknown or lost replies cannot remint. Matching plaintext enters only encrypted Native service custody. Historical custody is distinguished from current OP metadata synchronization; neither supplies copy verification or workload release.

The standalone mint suite passes **28 cases** over the actual Rust/Wasm, D1 and persistent Workers RPC/SQLite runtime with synthetic Artifacts. Frozen Native batches remain fenced while the independent ledger preserves known cleanup observations. Unknown mint recovery, productive Git upload/readback and copy/delegation controls still require subsequent qualification. No remote mint trial, protected journal change, production binding or deployment is performed.

The combined current backend/Git run passes **191/191 cases** (the previous 163 plus 28 mint cases). Production OP/service boundaries and baseline/Owner-schema/release-inventory regressions pass **13/13**. The production Worker build, named OP packaging, Wasm Clippy with warnings denied, Node/effect/checkpoint types, full formatting and documentation links pass. Existing UI budgets remain unchanged; OP Wasm is 5,936,405 raw bytes / 2,103,885 gzip estimate, within the existing 8 MiB / 3 MiB budgets.

Latest main `407f50e` is integrated by merge `f00c49d`, preserving the qualified work-port history. Its UserInfo fixture changes do not change product source. The current default UserInfo qualification passes **2/2 cases** after rebuilding the previously stale ignored conformance Claim Worker with the exact CI command, `worker-build --release -d build-conformance crates/userinfo-claim-worker --features conformance-gate`. Both actual workerd and browser v2 recipient/sharing/consent/withdrawal flows pass. No new profile benchmark or production-capacity claim is made. Node types, full formatting and documentation links pass after the merge.


## M6a reconciliation and M6c1 Git copy core

The current `token.mint` implementation retains `45a0102`'s independent initial closure and Native key fingerprint, and incorporates the separate mint-only Native facade, fixed short expiry, durable cleanup intent and ID-bound explicit refusal closure from the parallel `feat/work-productive-mint` branch. That older branch and its commits remain available; the duplicate `token.create` protocol is superseded. Frozen/pending Native batches remain fenced, including cleanup synchronization after whole D1 restore.

The reconciled authority/effect suite passes **196/196** cases, including **33 mint cases**. [M6c1](work-git-copy.md) adds **17/17** actual Git tests, for **213 locally qualified backend/Git cases** across the two runs. The copy core emits a create-only fixed ref and exactly the selected object's complete pack. Its strict upload acknowledgement remains unverified until independent readback checks refs, hashes, tree, full history and every received object. It has no network, plaintext-token, Native admission, preparation-verification or grant capability.

Production Worker build/OP packaging, production Wasm Clippy with warnings denied, Node/service/effect/checkpoint types pass. Existing production baseline/Owner-schema/resource inventory passes **20/20**; production OP/enrollment/logout boundaries pass **12/12**. The credential-backed productive broker, unknown-provider recovery, complete remote ref discovery, source export, final six-slot custody closure and owner copy consent remain the M6c2 integration gates. Protected remote journals and production resources remain unchanged.

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
are untouched. Unobserved-token operator recovery,
productive fixed Git upload/readback and owner copy/delegation composition remain
the next gates.


The combined reconciliation routes both mint and recovery through the separate
`WorkMintStore` binding. Retained explicit Git-refusal closures synchronize through
either gate with no provider replay; known-ID control-plane proof remains
revocation-pending and cannot erase its charge. The final combined validation is
recorded after reconciling `a639def` with `022eca1`.


Final reconciliation validation: **246/246** backend/Git cases pass in one
`npm run test:work-delegation` run (163 existing + 33 mint + 33 recovery + 17 fixed
copy cases). Node/service/effect/checkpoint types, production Wasm Clippy with
warnings denied, full Prettier/rustfmt, product-source and documentation checks
pass. The production OP build/packaging and exact-revision budget check pass;
OP Wasm remains within 8 MiB raw / 3 MiB gzip. Production OP/enrollment/logout/
service boundaries pass **13/13** and baseline/Owner-schema/resource-inventory
regressions pass **20/20**. These qualify this integrated source locally.

The merge preserves `022eca1`'s canonical mint/copy changes and `a639def`'s known-ID
recovery history. Subsequent concurrent root-checkout work on encrypted-custody
refusal recovery is a separate increment and is preserved without overwriting
its uncommitted files. The coherent reviewed source for this increment is
`feat/work-mint-reconciliation`; production activation and the productive Git
broker remain pending.
