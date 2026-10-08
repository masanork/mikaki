# Managed-work authority on the fresh main schema

**Status:** Original M2 checkpoint preserved from `ed7535d`, 2026-10-08 JST. Current M2–M4 qualification is recorded in the [integration plan](work-delegation-implementation.md). The topic branch includes main through `1f0dd3c` (merge checkpoint `5e1b84d`). [Portable rules](workload-profile-v1.md) and [Rust WorkStore](../crates/worker/src/work_store/mod.rs) now run against the current Owner Vault baseline. The original checkpoint covered the core authority. Owner/source transport, independent OP framing and local initial-effect admission are now integrated and separately qualified in the same history; product screens and remote activation remain gated.

## Schema and runtime boundaries

The [opt-in work profile](../crates/worker/work-migrations/README.md) adds work-only tables, triggers and bounded policies over the baseline and Owner-key wrapper migration. Its numbering continues at `0003`. Production configuration still selects `crates/worker/migrations/`; the existing readiness and release gates do not accept the additional work ledger. Migration rehearsal confirms existing OP/Vault rows and every existing schema definition are preserved, with foreign-key/integrity checks passing.

WorkStore owns primary D1 transitions, exact retry/approval consumption, audit, registered-source checks, preparation reservations, encrypted credential custody and private candidate retention. It takes trusted verifier inputs, not HTTP actor assertions. Its SQL statements and raw D1/R2 capabilities are not public service methods. The Rust module export registers no product route or Worker RPC entrypoint.

The implementation keeps the retained conditional batches and guard statements. [D1 documents whole-batch rollback on statement failure](https://developers.cloudflare.com/d1/worker-api/d1-database/#batch). Actual local D1 qualification separately exercises audit/guard failure rollback and concurrent admission; success from an in-memory domain transition is not counted as commit evidence.

The fixture requires both the `work-qualification` compile feature and a literal `LOCAL_WORK_QUALIFICATION=true` flag. The original core fixture accepted only `POST /fixture`. The unified qualification fixture additionally exercises real owner/source transport and Queue-aware logout; these fault/test entrypoints are absent from production routing. A qualification-only exemption permits primary-D1 testing without a checkpoint **only before enrollment**. An enrolled marker with no independent service rejects writes and preserves rows/audit; the marker is never reset to recover that exemption. Default production compilation has no uncheckpointed work-write exemption.

No `WORK_OWNER_API_ENABLED`, work checkpoint, Artifacts, launcher or remote source-reader binding is provisioned by this increment. Local persistent fixtures expose only D1, private R2 and synthetic service-secret bindings. Synthetic sessions, registered source facts, producer proofs and verification receipts do not qualify real owner/issuer/launcher or Artifacts integration.

## Qualified behavior

| Layer | Evidence and limits |
| --- | --- |
| Requests/grants/runs/approvals/operations | Cross-isolate reload; exact one-time approval consumption; one-winner dispatch/target claim; revocation/stale-policy/key/client/issuer denial; audit rollback; cancellation retry and retained unknown outcomes. No external write is performed. |
| Registered disclosure/preparation | Real selected Git bytes and full code-history inventory; independent digest/UTF-8 checks; current membership/version/SSO guards repeated at SQL commit; byte/row/hour ceilings; exact retry and charged unknown allocation. Git and source facts are supplied by explicit local fixtures. |
| Private credential journal | Reservation/dispatch concurrency; independent Node decryption of Native AES-GCM; process restart; key substitution/rotation/floor/retirement; nonce tombstones; late capture and cleanup after owner/policy loss; all six known slots closed before synthetic verified preparation. No provider token is minted or released. |
| Candidate preservation | Independently restored Git bundle excludes unrelated objects/refs; private R2 survives source removal and process restart; corruption/missing archive/quota/SQL-substitution refusal; audit failure retains a charged recovery obligation. Provider deletion is not performed. |
| Owner projections | Rust SQL/domain metadata projection excludes plaintext credentials, ciphertext/private token observations and archive contents. Production cookie/HTTP/no-store behavior is pending owner transport integration; it is not inferred from these fixtures. |

The separate generated output is `local/generated/work-store-main/`, using main's wasm-bindgen `0.2.129`. Earlier `work-store/` binaries, protected effect journals and the six retained development repositories are untouched. This work does not reinterpret uncertain provider outcomes or discard their liabilities.

## Validation

```sh
npm run test:work-store
cargo test --workspace --offline --locked
cargo clippy -p mikaki-worker --target wasm32-unknown-unknown --offline --locked -- -D warnings
npm run check:node
npm run check:product-sources
npm run check:docs
```

At the original `ed7535d` checkpoint, the Wasm/workerd/D1/R2/Git suite passed **65/65 cases**; native Rust workspace tests pass **209 cases including doctests**. Production-baseline, Owner-schema and release-inventory regressions pass **11/11**. Node types, production Wasm Clippy, formatting and source checks pass. Main's existing Identity code needed six semantics-preserving style fixes for the current Wasm Clippy check (conditional/range/borrow syntax); no Identity protocol behavior was changed.

These are local results. The current 160-case suite adds M3 framing and M4 local effect admission/refusal. Independent operator/checkpoint provisioning and actual provider recovery remain activation gates; rendered owner/source composition remains M5. No remote CI, migration, binding change, real credential issuance or production deployment is claimed.
