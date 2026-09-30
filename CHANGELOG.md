# Changelog

This file records user-visible project changes from 2026-09-23 onward. Mikaki has no supported release yet; earlier experiments and probes remain in the Git history and their dated test records. Entries under **Unreleased** describe work in this repository, not a production launch.

## [Unreleased]

### Changed

- Refreshed invitation administration, registration completion, and logout screens with the login visual language; localized logout in Japanese and English and added Worker browser checks for responsive layout and language switching.

- Refreshed the Vault profile and connections layout with shared product navigation, responsive cards, and visible lock state in both supported languages.

- Record source-mapped Chromium execution for the Vault, administration and registration-completion Svelte/TypeScript bundles in PR CI, matching hidden local source maps to the exact served JavaScript and retaining a content-free per-file report.

- Fail CI coverage measurement when line or branch coverage substantially regresses in five directly tested Vault/recipient TypeScript modules; retain the full report without treating the global percentage as a product quality score.

- Validate local Markdown heading fragments as well as file destinations in the CI documentation check, catching stale section links without network access.

- Added a no-body, bearer-protected `/ready` check for policy, current D1 migration, signing-key agreement and essential bindings including the internal Claim Worker. Unauthenticated probes stop before dependency checks. Version-aware production smoke now requires readiness and a separately provisioned monitoring secret; local multi-Worker regressions cover failure states.

- Run verified Worker upload preparation in the attested build, recheck its staged files, and attest the archive-to-bundle inventory alongside the two archives.

- Added an offline upload preparer for both attested Worker archives. It rechecks release inputs, stages exact members, dry-run bundles with pinned Wrangler, records hashes of the upload inputs, and detects mutations before a future version upload.

- Expose the OP's Cloudflare Worker version ID and build-source revision through a no-store `/version` response; optionally require exact version/clean-commit agreement in public smoke and retain its evidence. Artifact-byte promotion and production activation remain separate.

- Bind both Worker archives and the ordered migration bytes to a clean source revision with a separately attested release inventory and offline verifier. Add disposable migration/backup/ciphertext-reopening exercises and explicit historical-restore security gates.

- Return a confirmed registration race/replay as a client rejection after atomic rollback instead of intermittently leaking a server error; retain server errors for unrelated database failures.

- Protect unsaved name/note edits during manual lock, reload, full-page navigation, and Passkey transfer. Confirm initial deletions, preserve exact retries, and show local edit state in both languages. Automatic/security locks remain unconditional.

- Run product Worker contracts and connected enrollment/Vault/OIDC/logout browser journeys before merge; reuse those gates in the attested build. Preserve local-fixture browser failure traces/screenshots, export TypeScript coverage, and add native OIDC signature/PKCE/expiry/binding regressions with HTML/LCOV reports.

- Added an isolated DPoP sender-constraint/receipt probe with certificate-verified HTTPS and negative/replay cases, plus a FAPI 2.0 fit/gap and phased implementation plan. Persistent replay authority, PAR, confidential-client/profile activation and full wallet applications remain separate gates.
- Added shared Rust ES256 DPoP verification, immutable opaque-token key bindings and atomic D1 replay/resource acceptance for optional OP token issuance and UserInfo. Cross-Worker/reload, capacity/cleanup, revocation and DB rollback regressions run in CI. Migrations 0020–0022 precede deployment; optional AS/UserInfo nonce challenges, authenticated PAR and code-key binding have local evidence, while required profile wiring and Final FAPI qualification remain open.

- Added local HTTPS adapters for OIDF credential metadata and nine verifier-component modules, reran current-build OIDC Basic/Config OP, and exported exact verdicts without protocol secrets. Fixed passkey prompt screenshot races and the suite image-size limit; formal certification and wallet-application E2E remain separate.

- Add a shared Vault display lifecycle: manual lock, 15-minute idle and one-hour absolute leases, suspended-tab session verification, login/logout notifications across tabs, and disposal of panels/drafts/retry state. Include real local Worker browser regressions and document memory/platform limits.

- Unified Vault, invitation administration, registration completion, and logout with the login visual design, shared header, same-origin styles, responsive layouts, and accessible native controls. Added explicit profile reload, serialized profile operations, frozen uncertain-save retries, and localized cancellation/error feedback; local UI evidence is separate from deployment.

- Migrated Python policy generation, design checks, CBOM output, product-source checks, FIDO metadata extraction, and SQLite contract tests to TypeScript 7; retained the independent Python attestation fixture generator for interoperability verification.
- Enabled `noImplicitAny` for the entire Node TypeScript project and removed the temporary per-file strict gate after typing the conformance harness.
- Extended the strict Node TypeScript gate to the D1 atomicity design probe.
- Extended the strict Node TypeScript gate to project metrics generation and chart rendering.
- Extended the strict Node TypeScript gate to recipient key and secret administration and their local D1 tests, plus WebAuthn boundary tests.
- Extended the strict Node TypeScript gate to JOSE, FIDO analysis, and Worker token exchange design probes.
- Extended the strict Node TypeScript gate to the local OP and RP handlers, including typed request and environment boundaries.
- Extended the strict Node TypeScript gate to the local Wrangler runtime and core end-to-end test harnesses, including typed browser and D1 fixture state.
- Extended the strict Node TypeScript gate to client, bootstrap invitation, and Worker policy administrator scripts; validated client registration input before treating it as typed data.
- Added a CI enforced `noImplicitAny` check for shared Node helpers, account revocation, garbage collection, logout delivery, and independent tools; typed policy access, request validation, JWT inputs, and error handling at those boundaries.
- Enabled strict null checking for the Node scripts, local harnesses, and design probes, with explicit checks for missing HTTP headers and optional claim fields.
- Migrated handwritten Node scripts, local integration harnesses, and design probes to TypeScript 7, including test entrypoints and Wrangler source entries. CI now checks these sources after the Wasm build.

### Added

- Added an isolated OID4VCI Final receipt profile for the same synthetic membership, using a pinned independent issuer protocol library, transaction-code-gated one-use issuance, separate nonce/holder proof and exact encrypted import. Forty-two receipt scenarios and the prior 28 presentation scenarios pass, including receipt-to-independent-verifier presentation; CI runs both. Product wallet/issuer, external network and real-device/recovery gates remain open.

- Repository Markdown destination checks and product browser regressions for locale, CSP/style delivery, mobile overflow, keyboard navigation, profile loading recovery, overlapping operations, and exact retries after a lost save response.
- Added an isolated OID4VP synthetic membership probe with exact encrypted issuer-artifact preservation, a separate disposable holder-key envelope, owner approval/cancellation and minimal disclosure. A pinned independent verifier library and explicit request/trust/status policy pass 28 positive/negative scenarios, now included in CI; full wallet/network/device qualification remains open; subsequent bounded OID4VCI receipt evidence is recorded separately above.
- Declared MCP output schemas and identical validated structured/text results for local read tools and all remote tools. Added explicit source revision/provenance and access-check metadata, digest-bound optional local export metadata and safe unspecified provenance for legacy exports; preserved proposal authority, scope checks and stable write receipts. Local stdio/HTTP/Chromium tests qualify schema discovery, saved-note round trips, text compatibility and denial/revocation behavior.
- Owner-facing saved-source and AI-copy revision comparison with browser confirmation times, remote grant creation/expiry, and bounded page-local plaintext download-start records. Failed or malformed checks show unconfirmed source state and retain only prior observations; downloaded files remain independent snapshots. Local HTTP/browser tests cover edits, deletion, partial outages, session confirmation, retry and unchanged local export contracts.
- Separate saved-note Passkey transfer UI reusing the existing registration and conditional transfer authority, with typed saved-content validation, source/target PRF, candidate reopening, exact retry state and owner-editor locking. Local browser/workerd tests preserve note provenance and the unchanged name while covering missing PRF, cancellation, conflicts and unsupported versions.
- Owner-selected saved-note local MCP exports with saved-content preview, separate PRF credential, exact note schema/revision checks, read-only digest-bound grants and invalidation of prepared downloads on observed selection/revision changes. Browser-to-stdio SDK tests qualify saved-only note reads, preparation failures and local revocation; remote note sharing remains outside this slice.
- Disposable pinned Codex CLI/App Server OAuth qualification: code exchange, credential persistence across fresh processes, synthetic MCP reads, narrow-scope write denial and individual token revocation; clarified the new Grok Bot hosted-plugin/account-wide integration target.
- Standalone Grok Bot hosted-plugin preparation with canonical HTTPS/public-client validation, read-only concrete MCP config, private marketplace layout, reviewable registration SQL and pending qualification records; documented distribution/account-access gates without claiming provider connection.
- Offline hosted OAuth request inspection with exact binding/PKCE/read-scope checks and content-free mismatch reports, including sanitized parser failures; preparation/redaction regressions are included in CI. Synthetic report validation remains separate from actual provider qualification.
- Bounded Rust Passkey login and return to agent OAuth consent, without an implicit delegation or OIDC app connection; local virtual-authenticator/rollback/replay coverage and an installed Codex preregistered discovery/request probe. Added RFC 9207 issuer-support metadata and documented separate Codex, Grok Build and Grok Bot gates.
- Preregistered public-client remote agent OAuth with discovery, S256 PKCE, exact callback/resource binding, owner-selected existing grants, narrowed one-hour tokens and individual revocation. Local SDK/workerd/browser tests cover concurrency, audit rollback and scope/invalidation; real client onboarding and production gates remain.
- Owner-device encryption of approved typed notes, exact candidate verification through a one-revision recipient proof, and a Rust atomic approval/head/result/audit commit with exact retry and page recovery. Local migration and injected R2/D1 failure tests qualify the bounded path; production and real-device gates remain.
- One typed owner-note proposal/decision authority for remote MCP and HTTP, with separate explicit target/revision capabilities, owner dashboard review, atomic audit and irreversible invalidation. Approval does not write Vault ciphertext; ADR 0013 records the bounded TypeScript domain exception.
- A typed encrypted owner note with versioned schema, bounded deterministic JSON, self-asserted provenance, owner editing and explicit plaintext import/export. Local HTTP/browser tests cover incompatible input, conflicts and exact retries; legacy name storage and agent scopes remain unchanged.
- Owner-session-bound same-account passkey registration and saved-name transfer to a different PRF credential with fresh ciphertext/revision, atomic transfer audit, and exact retries. Local browser tests use mocked PRF; real-device and backup recovery remain gates.
- Vault selection/PRF export, a separate encrypted-snapshot agent Worker with resource-bound bearer access, connection/audit controls, irreversible source/account/credential/recipient invalidation, and exactly approved private-draft execution. Local browser/workerd and synthetic Codex/Grok CLI probes verify the limited flow; production activation and OAuth onboarding remain.
- A local stdio MCP read adapter for owner-selected plaintext exports, with operation/recipient labels, expiry, live grant checks, export digest binding, and content-free audit; remote authentication and Vault integration remain future work.
- An agent integration backlog with production release gates and separate plans for Codex, Grok Build, and shared Grok Bot environments.
- Added a local helpdesk RP crate and Worker with public help articles, private tickets, OIDC login, and a browser integration test.
- A short project README and a documentation map that distinguish deployed behavior, local verification, accepted decisions, and proposals.
- English project-status, architecture, local-development, roadmap, and contribution guides.
- English versions of the existing architecture decision records and the RP integration guide.
- English documentation across the root, topic guides, crate and local harness READMEs, probes, and dated conformance reports.
- Restored the codebase growth and coverage links in the project README.

### Documentation

- Reviewed Vault protocol boundaries: retained MCP as an AI adapter, evaluated OpenID4VP/VCI for credentials and JMAP/FileNode for files, and made the FileNode rights mismatch and protocol adoption gates explicit in ADR 0012.
- Recorded the current production deployment limits: one administrator and real-Passkey Vault save/reopen are recorded, and narashi is registered; completed production RP login/callback and newer Vault/agent activation remain unverified.
- Kept conformance results separate from formal FIDO or OIDF certification claims.
- Marked implemented behavior separately from design proposals and historical acceptance gates throughout the topic guides.

Future entries should describe shipped behavior and migrations with a dated version or release tag. Do not move an item from **Unreleased** merely because a local probe passes.
