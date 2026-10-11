# Work-request UI and interaction design

**Status:** Reviewed product contract carried onto main, 2026-10-08 JST. The retained pre-main Svelte/Worker prototype is not yet integrated with current product components; its prior browser results are not current-main UI evidence.

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
