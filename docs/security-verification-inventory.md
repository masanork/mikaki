# Mikaki security verification inventory

This inventory records configuration and source anchors for the [security assurance plan](security-assurance-plan.md). The dependency coverage update is based on main `22003c1615ea010fac2a6df5b53d2e3d8261c28c`, inspected on 2026-10-21. Runtime settings, scan findings and deployed versions require their own dated evidence.

## Existing controls and next checks

| Control | Source anchor | Scope to verify next |
| --- | --- | --- |
| SonarQube source analysis | [CI](../.github/workflows/ci.yml), [setup](sonarqube-cloud.md), [historical triage](sonarqube-triage.md) | Recheck current analysis revision, enabled rules, pending hotspots/findings and scan availability. Historical counts are not a current baseline. |
| Cargo/npm/Gradle advisory job | `dependency-advisories` in [CI](../.github/workflows/ci.yml) | OSV covers all 18 tracked lockfiles; retain existing RustSec/npm checks and review exact expiring exceptions. Classify non-lockfile inputs separately. |
| Dependency update proposals | [Dependabot](../.github/dependabot.yml) | Weekly Cargo/npm/Gradle/Actions updates are configured. Verify enabled alerts and each effective graph separately from update scheduling. |
| WebAuthn fuzzing | [Workflow](../.github/workflows/webauthn-fuzz.yml), [targets](../fuzz/Cargo.toml), [fuzz contract](webauthn-fuzzing.md) | Four targets, weekly/manual, 90 seconds each; crash artifacts are retained 14 days. Add longer runs, reusable corpus, stateful/property oracles and native/Wasm regression replay. |
| Actual Worker and browser suites | [Package scripts](../package.json), [product test contract](test-quality.md) | Map individual assertions to SEC-01 through SEC-20. Confirm the actual Worker and required feature profile were built. |
| Bounded internal service authority | [Named entrypoints](../crates/worker/service/entrypoint.ts), [authority facades](../crates/worker/service/authority-admin-facade.ts), [generated Agent catalog](../crates/worker/service/agent-catalog.ts) | Check operation and owner binding, catalog drift, public denial and exact durable effects. |
| Release bundles and attestations | [Candidate build](../.github/workflows/build-release-candidate.yml), [attestation workflow](../.github/workflows/supply-chain-build.yml), [release runbook](release-and-recovery.md) | Trace reviewed source through archive/configuration digests to active runtime versions and bindings. |
| Independent WebAuthn review | [Existing brief](webauthn-security-review.md) | The brief has no recorded reviewed commit/reviewer. Confirm any newer engagement before commissioning the scoped review. |

## Dependency scan scope

There are 18 tracked lockfiles at this baseline: 12 Cargo, 5 npm and 1 Gradle. The `dependency-advisories` job discovers these paths from `git ls-files` and explicitly scans every graph with OSV-Scanner. It validates nonempty results for every requested path and fails on missing/duplicate/out-of-scope results or tool errors. Existing RustSec and npm commands remain as additional checks. A tracked standalone/vendor lockfile may not control the product build; scanning it does not imply it ships in the product.

| Lockfile | Explicit advisory-job target | Effective scope to classify |
| --- | --- | --- |
| [Root Cargo](../Cargo.lock) | OSV + `cargo audit --file Cargo.lock` | Shared workspace and its target-specific/runtime/build dependencies. |
| [Native application](../apps/mikaki-client/src-tauri/Cargo.lock) | OSV | Native Tauri client and plugins selected by its build. |
| [Proximity plugin](../apps/mikaki-client/plugins/identity-proximity/Cargo.lock) | OSV | Standalone plugin build/test graph; compare with the application's selected graph. |
| [Vendored card package](../apps/mikaki-client/vendor/civ-card/Cargo.lock) | OSV | Determine standalone development use versus the consuming application's lockfile. |
| [ES256 probe](../design/probes/es256/Cargo.lock) | OSV | Isolated cryptographic interoperability probe. |
| [JOSE probe](../design/probes/jose/Cargo.lock) | OSV | Isolated JOSE provider graph. |
| [Custom JOSE probe](../design/probes/jose-custom/Cargo.lock) | OSV | Isolated alternate JOSE provider graph. |
| [MLS probe](../design/probes/mls/Cargo.lock) | OSV | Isolated messaging protocol graph. |
| [Native Identity HTTP probe](../design/probes/native-identity-http/Cargo.lock) | OSV | Native protocol/transport and release-test tooling. |
| [PQC probe](../design/probes/pqc/Cargo.lock) | OSV + `cargo audit --file design/probes/pqc/Cargo.lock` | Isolated future-algorithm graph; retain its non-product status. |
| [Workers Rust probe](../design/probes/workers-rs/Cargo.lock) | OSV | Isolated adapter/toolchain probe. |
| [Fuzz package](../fuzz/Cargo.lock) | OSV | Parser fuzzing dependencies and sanitizer/toolchain profile. |
| [Root npm](../package-lock.json) | OSV + `npm audit --audit-level=low` | Root runtime, UI, build and test dependencies. |
| [Native application npm](../apps/mikaki-client/package-lock.json) | OSV | Tauri application tooling. |
| [Probe npm](../design/probes/package-lock.json) | OSV + `npm audit --prefix design/probes --audit-level=low` | Shared probe tools. |
| [Vault search probe npm](../design/probes/vault-search/package-lock.json) | OSV + `npm audit --prefix design/probes/vault-search --audit-level=low` | Search probe tools. |
| [Svelte checker npm](../tools/svelte-check/package-lock.json) | OSV + `npm audit --prefix tools/svelte-check --audit-level=low` | Isolated Svelte checking tools. |
| [Android attestation JVM](../services/android-attestation-verifier/gradle.lockfile) | OSV | Locked Maven distribution and test graph; OSV Gradle parser. |

Also inventory Android application/plugin resolved dependencies, pinned upstream verifier source, downloaded CI binaries, Action revisions and any deployed container image digests. Their absence from this lockfile list does not exclude them from the assessment. Preserve dependency exceptions with the affected graph/version, reason, owner, expiry and compensating control.

Reproduce the tracked-file portion with:

```sh
git rev-parse HEAD
git ls-files '*Cargo.lock' '*package-lock.json' '*gradle.lockfile'
```

After each manifest/workspace change, identify which lockfiles the build actually consumes and update this table. New supported tracked lockfiles enter the gate automatically. Review unsupported package managers or nonstandard lockfile names explicitly. See [security CI operations](security-ci.md#dependency-advisory-policy) for the exact exception policy and unresolved findings.

## Product verification entry points

These commands are existing starting points. Build the actual bundles and fixtures specified by their scripts and [test-quality instructions](test-quality.md) before interpreting their results. Some suites require generated artifacts, configured test custody, or a particular browser.

| Command | Scenario families to map |
| --- | --- |
| `npm run test:worker-contracts` | Owner/session/client separation, DPoP, invitation/administration, service boundaries and resource lifecycle. |
| `npm run test:worker-browser` | Actual served UI, browser authentication, consent, owner-key lifecycle and rendering. |
| `npm run test:vault-transfer` | Key context binding, credential wrapping, record storage and selected release. |
| `npm run test:agent-integration` | Agent storage capabilities, explicit selected-record grants and OAuth scope. |
| `npm run test:work-delegation` | Work source/disclosure, custody, checkpoint, effect, mint, Git and uncertain outcomes. |
| `npm run check:service-authority` | Catalog generation drift and internal entrypoint types. |
| `npm run test:identity-contracts` | Issuer/attester selection, presentation, consent, revocation and device preflight. |
| `npm run test:sql` | Included product SQL invariants and separately identified design models. |
| `npm run test:release` | Manifest/archive/configuration integrity, migration/recovery contracts and promotion negatives. |

Inspect assertion bodies and harness profiles for each scenario. For example, the Identity revocation suite contains independent CRL checks; that alone does not establish complete account deletion or holder-device revocation. A local model does not substitute for the Rust Worker authority.

## Candidate Wallet and Chat scope

[PR #277](https://github.com/masanork/mikaki/pull/277) was open at inspection, with candidate commit `c2eb64c41a7310b3b4af280dffe9110bf3f80854`. It is a separate assessment target from the main baseline. Refresh its revision and merge state before execution.

The subsequent security CI implementation was rebased onto main merge `2c139b07`, which includes PR #277. That revision has 18 tracked lockfiles including the MLS graph. The links below preserve the initial candidate snapshot; execute lifecycle tests against the selected current revision and retain the enabled-profile distinction.

Candidate anchors are pinned to that commit because they are absent from the main baseline:

- [Release readiness](https://github.com/masanork/mikaki/blob/c2eb64c41a7310b3b4af280dffe9110bf3f80854/docs/wallet-chat-release-readiness.md) and [product scope](https://github.com/masanork/mikaki/blob/c2eb64c41a7310b3b4af280dffe9110bf3f80854/docs/wallet-chat-mvp.md).
- [Messaging service and lifecycle code](https://github.com/masanork/mikaki/tree/c2eb64c41a7310b3b4af280dffe9110bf3f80854/crates/worker/src) and [beta enable contract](https://github.com/masanork/mikaki/blob/c2eb64c41a7310b3b4af280dffe9110bf3f80854/docs/mls-beta.md).
- [Browser device custody and state](https://github.com/masanork/mikaki/tree/c2eb64c41a7310b3b4af280dffe9110bf3f80854/crates/worker/ui/messaging).
- [MLS probes and lifecycle suites](https://github.com/masanork/mikaki/tree/c2eb64c41a7310b3b4af280dffe9110bf3f80854/design/probes/mls) for persistence, invitations, recovery, rejoin, replacement, cancellation, and stop chains.
- [MLS browser/server workflow](https://github.com/masanork/mikaki/blob/c2eb64c41a7310b3b4af280dffe9110bf3f80854/.github/workflows/mls-probe.yml) and candidate `npm run test:messaging-beta`, `npm run test:wallet-chat-product`, and `npm run test:wallet-chat` scripts.

The beta router requires both Cargo feature `messaging-beta` and `MESSAGING_BETA_ENABLED=true`. The assessment must exercise the disabled default and an isolated enabled profile with its own issuer key, schema and resources. This candidate also adds `design/probes/mls/Cargo.lock`; include its effective graph in dependency scope when reviewing or merging it.

For SEC-15/16, verify normal owner authentication, one-use enrollment, key possession, independent fingerprint confirmation, generation/revision continuity, journal/witness rollback handling, and cancellation/replacement across restart. Record the difference between synthetic fixtures, actual product adapters, supported browser engines, and physical-device qualification.

## Evidence record

Store each private assessment report with:

- Immutable source and build revisions, scanner/query/database versions, timestamp, and selected scope.
- Environment resource identifiers, enabled profiles, supported browser/device identity and test accounts represented by synthetic labels.
- Selected ASVS requirement, scenario/invariant IDs, exercised route or entrypoint, validation method, result, and evidence paths.
- Confirmed impact, uncertainty, finding disposition, fix revision, regression case and independent retest result.
- Scanner failures, missing targets, expired authentication and reviewed exclusions.

Keep tokens, cookies, PRF output, private keys, card data and real plaintext out of public logs and reports. The engagement record in the assurance plan sets the restricted destination and retention period.
