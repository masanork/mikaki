# Product quality and activation gates

Reviewed against repository code and local evidence on 2026-09-30. This is a bounded quality backlog, not a production-ready or certification claim. [Status](status.md) owns verified capability claims; [deployment](cloudflare-deployment.md) owns environment history.

## Implemented foundation

| Area | Current behavior and evidence |
| --- | --- |
| Visual consistency | Login, Vault, invitations, registration completion, and logout use shared branding, typography, controls, focus treatment, and responsive layouts. [Synthetic previews](product-ui-preview.md) use actual bundles. |
| Profile failure recovery | Failed loads release loading state and allow retry. Passkey cancellation is localized. Profile mutation/sharing operations serialize; uncertain mutations freeze the editor and preserve the exact operation for retry. Discard/reload warns before abandoning local edits or retry state. Share/release results appear in their own panels. A committed name/note change whose refresh fails is distinguished from an uncertain write. |
| Edit and deletion safeguards | Name/note editors expose local unsaved state; reload, manual lock, and transfer confirm affected draft disposal. Initial deletions require confirmation, exact deletion retries retain operation identity. Browser unload warnings protect full-page navigation where supported; automatic/security locks remain unconditional. Local browser tests cover cancelling/accepting, language-selector recovery, and deletion. Native unload warnings remain best effort. |
| Vault display lifecycle | Manual lock, 15-minute idle and one-hour absolute display leases dispose all Vault panels, drafts, credentials, and retry state. Hidden tabs mask the view and verify the same server session before showing it. Login/logout events notify other tabs; pagehide disposes the view. `npm run test:vault-lifecycle` covers deadlines, session replacement, verification outages, late authenticator replies, and cross-tab logout with the real local Worker. See [session lifecycle](session-lifecycle.md) for limits. |
| Browser regressions | `npm run test:product-ui` checks style delivery under CSP, both locales, mobile overflow, keyboard navigation, load/cancellation recovery, overlapping save attempts, and lost-response retries. Existing note/share/logout suites preserve their data and authorization contracts. |
| Pre-merge integration and failure evidence | PR verification runs the actual Worker contract and browser suites, including a local HTTPS Rust OP journey with virtual Passkey/PRF, code replay and logout denial. Instrumented browser suites preserve traces, screenshots and bounded diagnostics on failure. Native and TypeScript coverage reports identify gaps; five directly tested frontend modules have per-module regression floors. The product screen journey also exports source-mapped Chromium execution for Svelte/TypeScript without a broad threshold. See [test evidence and limits](test-quality.md). |
| Release and recovery rehearsal | Offline release inventory verifies both Worker archives/members, source commit and migration hashes; the attested workflow also attests the manifest. An upload preparer dry-run bundles the verified archives and inventories local upload inputs. A disposable SQLite backup/upgrade exercise preserves encrypted heads, audit and closed bootstrap, rejects missing/corrupt ciphertext, and demonstrates historical revocation resurrection. The OP can report its Cloudflare version and build-source commit for an opt-in production smoke comparison. See [runbook and limits](release-and-recovery.md); production restore, remote artifact-byte promotion and live version check remain open. |
| Read-only deployment readiness | Authenticated `/ready` checks the active OP policy, latest migration, signing secret/public key agreement, required bindings, a metadata-only R2 HEAD in a reserved namespace (three-second dependency timeout), and an internal Claim Worker schema query. Invalid or missing monitoring credentials return 404 before dependency checks; authorized checks return 204/503. Local tests cover these paths, dependency mismatches, R2 errors/timeouts and recovery; probes leave stored objects intact. Version-aware production smoke requires 204. R2 ciphertext read/write permissions and bucket identity, recipient secret usability, token writes, RP callbacks and alert delivery still need separate qualification. |
| Documentation | README/index/status/roadmap link implementation, UI evidence, and remaining gates. `npm run check:docs` checks local Markdown file/image destinations and Markdown heading fragments without fetching external pages. It does not check external URLs or truth of deployment claims. |
| Build and localization | Worker builds run TypeScript/Svelte checks; CI also runs formatting and `npm run check:i18n`. The latter validates keys and placeholders, not the quality or completeness of every visible sentence. |

## Remaining work before real-user activation

| Priority | Gate | Acceptance evidence |
| --- | --- | --- |
| P0 | Intended-device Passkey and PRF | Save/reopen and name/note transfer on supported devices, including cancellation, absent PRF, and new-device reopening. Mocked PRF is insufficient. |
| P0 | Production RP and logout | Complete the registered narashi owner login/callback and managed session/logout flow; verify durable delivery and failure bounds. Registration and `/health` alone are insufficient. |
| P0 | Session and plaintext lifecycle | Qualify the implemented local lifecycle on intended browsers/devices, including real sleep/BFCache, delayed authenticators, and denied storage/channel access. Automated local checks do not establish platform memory erasure or undo already committed writes. See [session lifecycle](session-lifecycle.md). |
| P0 | Recovery and operations | Qualify the local rehearsal and [runbook](release-and-recovery.md) on isolated Cloudflare infrastructure, establish DB/object/key backup retention and external recovery fencing, reconcile historical authority, prove monitoring, RP invalidation and rollback. All-key-loss recovery is unavailable. |
| P1 | Assistive-technology qualification | Manually exercise keyboard-only and screen-reader use on supported browser/OS combinations, including Passkey dialogs, error announcements, focus after state changes, and long translated content. Automated browser checks cover only a subset. |
| P1 | Edit and destructive-action UX | Qualify the implemented edit/deletion safeguards on supported browsers, including mobile unload limitations, validation before encryption, and guidance distinguishing uncertain outcomes from definite rejection. Deletion has confirmation and no undo; unload protection remains best effort. |
| P1 | Runtime resource and abuse limits | Establish measured frontend/Wasm budgets and slow-network behavior; verify quotas/rate limits for intended traffic and endpoints before enabling remote agent or claim access. |
| P1 | Release provenance | Promote the verified archives/inventory, identify actual runtime version/attestations, and bind smoke results to that version and schema. Local byte verification and locally built deployment history are insufficient. |

The latest UI changes do not enable profile claims or agent access in production, apply new migrations, or solve recovery. Avoid completing these gates by documentation edits alone. Record each new result with environment, date, concrete positive/negative behavior, and its practical limit.

## Routine validation

After dependencies and generated catalogs are available:

```sh
npm run test:release
npm run check:docs
npm run check:i18n
npm run check:worker-ui
worker-build --release crates/worker
npx playwright install chromium
npm run test:worker-contracts
npm run test:worker-browser
npm run test:frontend-coverage
npm run preview:product-ui
```

The UI test runs in CI after the Worker build and Chromium installation. Screenshot capture is optional manual visual review; there is no pixel-baseline or accessibility certification gate. Run the relevant note, transfer, sharing, OAuth, and other suites when their behavior changes, rather than treating one smoke test as full product qualification.
