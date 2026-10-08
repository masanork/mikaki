# Work delegation implementation plan

**Status:** Main integration checkpoint, 2026-10-08 JST. The reviewed ADR and portable core are restored on a topic branch based on current main. Earlier D1, Worker, UI and Artifacts work is preserved for integration with main's fresh schema. No production activation is included.

Keep [ADR 0016](adr/0016-personal-context-and-workload-delegation.md) as rationale, [authorization](workload-authorization.md), [domain profile](workload-profile-v1.md) and [UI](work-request-ui.md) as contracts, and this file as delivery/qualification order.

## Preserved work and main baseline

The old `feat/agent-vault-oidc-qualification` branch at `d441ce0a4583ebcf1ae54627e2ca3df29e2f20a9` has no commits outside current main and is 156 commits behind. Replaying its committed history adds no work.

Uncommitted work is preserved by stash commit `ea733061aefa6a3cb3262908aa685eb3337bc40d`, labeled `pre-main-catchup-20261008: preserve local work and qualification evidence`; its additional-file tree is `ceb868a163c1f21df9af3391c288bf672431ffa8`. Keep the stash until selected work/evidence is fully accounted for. It includes unrelated earlier changes and generated files; applying the whole stash is not the integration unit.

The root checkout was already clean on main at `8d48ba93fef64f4802627939ec63235eeef6aa68`. A fresh GitHub main-ref read matched that commit. New local branch `feat/work-delegation-main` starts there and retains main's newer dependencies, Owner Vault implementation and schema.

Main uses migrations `0001_owner_vault_initial.sql` and `0002_owner_key_wrap_operations.sql`. Retained work used the historical chain through `0047`–`0056`. Port additive work schema and current OP admission paths explicitly; do not restore retired migrations, obsolete Agent/Vault callers or old dependency locks to satisfy the old fixture.

Ignored `local/generated/work-*` evidence/state remains in place. Initial-effect journals account for **six empty development repositories**, including unresolved allocations. Empty inventory cannot close an unknown attempt. This integration neither resets those records nor deletes, recreates, remints for or adopts their resources.

## Main integration order

| Increment | Outcome and qualification gate | State |
| --- | --- | --- |
| M1: Portable rules/decisions | Restore ADR/AuthZEN/ABAC choices and Rust rules with main's dependencies. Native tests and Wasm compilation pass. | Complete locally: 35 unit cases plus one compile-fail case. |
| M2: Fresh-schema authority | Port WorkStore/SQL, bounded budgets and custody onto the fresh baseline; exercise current owner/session/source checks, exact retry, audit rollback and concurrency in actual Wasm/D1/R2. | Pending. |
| M3: Checkpoint/OP framing | Port independent release floors and admission for current OP mutations; rehearse D1 restore and key/account/session/policy revocation while preserving safety reconciliation. | Pending; required before new productive effects. |
| M4: Initial effects/maintenance | Reconnect initial-create gate, read-only lookup and attenuating broker; requalify one-time admission, lost replies, immutable IDs, refusal and runtime RPC/binding limits. Resume protected remote journals without replacement creates. | Pending on main. |
| M5: Source/product review | Integrate source selection, separate copy/delegation consent and owner projections into current product components; requalify Japanese/English UI and stable operation identity. | Pending on main. |
| M6: Upload/readback | Native authority fixes repository, scope, expiry and operation digest. Independently admit each mint once before provider I/O; unknown outcomes cannot remint. Capture plaintext only into qualified encrypted service custody. Successful mint alone permits no workload release. | Next new effect increment after M2–M4. |

Preserved pre-main qualification passed 160 combined delegation cases, including 50 initial-effect/reconciliation/capability cases. Earlier UI qualification had 22 cases. Actual Artifacts initial creation, lost-create safety reconciliation and process restart were exercised using protected journals. These identify reusable work; they are **not current-main or production qualification**. The exact prior notes/fixtures remain in the stash.

Record selected source, implementation, checks and remaining gates for each increment. Commit reviewable units, then refresh Artifacts from a selected qualified commit. Old CI/release inventory or workspace overlays do not qualify new source.

M1 qualification passes `cargo test --workspace --offline --locked` (**209 cases**, including doctests), the auth Wasm target check, auth all-target Clippy with warnings denied, workspace formatting, product-source and documentation checks. Native workspace tests do not exercise the unported work HTTP/D1/Artifacts paths or production Workers. No prior Worker/browser qualification is counted as a current check.

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
