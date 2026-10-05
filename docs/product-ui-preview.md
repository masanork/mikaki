# Product UI preview

The current `/vault` page mounts the OwnerWorkspace inside the shared VaultSession lease. It includes the v2 owner-key profile editor, typed personal note, imported conversation archive and local SQLite search. The connections disclosure reviews existing Agent v2 OAuth grants with exact record source and authority. This is not a general Owner recipient-selection or release workflow. The former format-1 attribute panels, transfer UI, AgentPanel and `?storage=legacy-v1` presentation have been retired.

| Vault                                  | Logout                                   |
| -------------------------------------- | ---------------------------------------- |
| ![Vault](product-ui-preview/vault.png) | ![Logout](product-ui-preview/logout.png) |

[Mobile Vault](product-ui-preview/vault-mobile.png) · [Mobile logout](product-ui-preview/logout-mobile.png) · [English Vault](product-ui-preview/vault-en.png) · [Administration](product-ui-preview/admin.png) · [Registration complete](product-ui-preview/complete.png) · [Logout complete](product-ui-preview/logout-complete.png)

[Full Vault](product-ui-preview/vault-full.png) · [Full mobile Vault](product-ui-preview/vault-mobile-full.png) · [Mobile session lock](product-ui-preview/vault-session-locked-mobile.png) · [Unsaved mobile profile](product-ui-preview/vault-draft-mobile.png)

[Owner note](product-ui-preview/vault-owner-note.png) · [Owner note, mobile](product-ui-preview/vault-owner-note-mobile.png)

[Mobile invitation management](product-ui-preview/admin-mobile.png) · [Mobile registration complete](product-ui-preview/complete-mobile.png) · [Mobile logout complete](product-ui-preview/logout-complete-mobile.png)

These are current UI captures from actual Worker/UI bundles using disposable synthetic account/data and synthetic Passkey PRF output. They do not qualify intended devices or accessibility certification.

Build with `worker-build --release crates/worker`, then run `npm run preview:product-ui` to refresh the images. Capture checks desktop/375px overflow, browser exceptions, OwnerWorkspace unlock, profile/note editing, mobile session lock and logout completion. `npm run test:worker-browser` preserves route, keyboard, responsive and lifecycle regressions. See [product quality gates](product-quality.md).

Common styles live in `crates/worker/ui/product.css`, the shared header in `ProductHeader.svelte`, and server-rendered logout in `logout.html`. `VaultSession.svelte` owns the shared display lease and disposal boundary. No database migration is needed for the visual layer; owner record and Agent v2 authority contracts are documented separately.
