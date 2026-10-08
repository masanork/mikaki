# Work-request UI and interaction design

**Status:** M5a source inspection is integrated with current product components and locally qualified, 2026-10-08 JST. Compose, copy/delegation consent and productive activity/result controls remain pending. The retained pre-main full work-request prototype and its earlier browser results are not current-main UI evidence.

[ADR 0016](adr/0016-personal-context-and-workload-delegation.md) and the [designer/technical review](workload-delegation-review.md) fix responsibilities. Follow the existing [product UI](product-ui-preview.md), [quality gates](product-quality.md) and [main integration plan](work-delegation-implementation.md).

## Views and confirmations

| View | Owner-visible information/action |
| --- | --- |
| Compose | Goal, acceptance, selected context, recipient and destination. Editing creates no permission. |
| Disclosure review | Actual selected versions/content, separately stated reachable code history, recipient/operator, assurance, destinations, concrete operations and absolute expiry. Editing clears consent. |
| Copy preparation | Separate confirmation before copy; durable pending/verified/cleanup state and stable preparation identity. |
| Delegate | Confirm the exact reviewed request after current verified preparation. A repository or checkbox issues no grant. |
| Activity | Separate confirmed execution, permission, cleanup and effect state, including uncertainty and next steps. |
| Result review | Exact candidate/diff, original disclosure, target/head and independently sourced checks; render agent explanations as untrusted content. |
| Adopt | Separate exact code adoption from saving a decision. Fresh owner approval can use retained results without reactivating the producer. |
| Continue | Review adopted decisions, open questions and current versions for a new recipient with fresh run authority. |

## State and recovery

| Dimension | Presentation rule |
| --- | --- |
| Execution | Stop requested is distinct from launcher-confirmed stopped. |
| Delegation | Current confirmed active/expired/revoked state controls new operations. |
| Credentials | Show expiry and qualified revocation evidence; empty inventory alone proves no revocation. |
| Effect | Preserve operation identity across dispatching/applied/rejected/unknown, reload and reconciliation. Uncertainty permits no second dispatch. |
| Disclosure | Revocation does not imply erasure of delivered copies. |

Changed context, policy, owner authority or target head requires fresh review. Explain refusal/service failure with safe next steps without revealing undiscoverable resources. Use summaries with expandable disclosure details; protocol claim names belong in diagnostics.

Integrate current OwnerWorkspace/session components instead of retired Agent panels or legacy Vault routes. Requalify keyboard/focus, screen-reader status, mobile layout, Japanese/English text, repeated clicks, reload, retained results and unknown outcomes in the actual browser/Worker fixture. Synthetic launcher/source/provider events retain explicit limits. Productive controls require qualified backend paths.

## Current source review

OwnerWorkspace links to `/work/source-review` only when both existing owner/source transport flags are enabled. Production configuration still leaves them off. The authenticated Rust page and its assets require live SSO and the current independent checkpoint. `/work/session` supplies a display identity; it rechecks SSO after checkpoint I/O and grants no source or workload permission. Each source operation independently verifies its current authority.

The [source workspace](../crates/worker/ui/WorkSourceWorkspace.svelte) uses the same [session frame](../crates/worker/ui/VaultSession.svelte) as Owner Vault, with separate entry bundles. The screen lists only owned, registered sources and pinned versions; it distinguishes reachable code history from selected context files. The [client adapter](../crates/worker/ui/work-source-view.ts) checks exact metadata, byte lengths and content hashes before displaying Native-verified file text. Text is rendered as escaped text, with expandable hash details and keyboard-scrollable long contents.

Selection changes, refresh, failure, hidden-page transition, lock and session replacement discard the inspected text. Generation checks and abort signals reject late replies; resume requires fresh selection. Selection/content is not persisted to browser storage. This screen creates no disclosure, preparation, grant, credential or external copy. Copy confirmation must bind the actual recipients, destinations and expiry once the qualified productive copy path exists; a preview or checkbox cannot supply that authority.

Local Chromium qualification covers Japanese/English, 375px layout, focus, keyboard scrolling, actual Git text, foreign-owner exclusion, no permission issuance, selection/reload, stale membership, network/verification failure, substituted response content, hidden-page late replies, manual lock/reopen and revoked SSO. It also checks CSP and accessible browser roles; it does not certify audible screen-reader output or actual Artifacts source access. Screenshot evidence is generated under `artifacts/work-source-review/`.

The combined authority/effect/source-browser/display-lease run passes **178 cases** (163 backend/Git + 9 browser + 6 display-lease cases). The final separated entry bundles repeat the 15 UI/lease cases. Existing Owner Vault browser and production gates are checked separately. These are local results; remote CI and production activation are not claimed.

Final validation also passes the existing Owner Vault browser flow, production OP/service boundaries, 11 baseline/Owner-schema/release-inventory cases, production Worker/Claim Worker builds and OP packaging, Wasm Clippy with warnings denied, Node/Worker types, formatting and documentation checks. The service-boundary fixture initially used an old ignored Claim Worker binary; rebuilding the current source restored the retired endpoint's expected refusal without weakening the assertion. All existing UI/Wasm budgets pass: Vault JavaScript is 302,057 raw bytes / 86,803 gzip estimate; the separately tested source entry is 173,179 / 55,099, within 192 KiB / 64 KiB ceilings.

[M6a mint/custody](work-artifacts-mint-gate.md) supplies the next backend prerequisite. Productive copy still requires qualified Git upload/readback and cleanup recovery; the source review screen continues to issue no copies or grants. Historical custody and current OP synchronization must be shown separately when activity controls are connected.
