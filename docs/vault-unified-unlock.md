# Unified owner unlock preview

**Status:** opt-in implementation for qualification, 2026-10-03. The ordinary `/vault` interface remains format 1. The explicit `/vault?storage=owner-v2` selection uses the new owner-key and record APIs. This change does not activate the preview as the default, migrate old records, or enable v2 sharing, AI access, proposals or passkey transfer. It has not been deployed or qualified on intended physical devices.

## Owner experience and isolation

The preview starts locked with no mounted record editors. **Open Vault with passkey** first verifies the exact current owner session, then evaluates WebAuthn PRF with required user verification and the authenticated credential ID. The returned credential ID and PRF result are checked before opening or creating the owner key. Unsupported PRF, cancellation, missing credential wrapping, unsupported formats and decryption failure never reset an existing root.

One bounded owner-key lease opens both supported records: `personal/name` with kind `name` and raw UTF-8 plaintext, and `personal/owner_note` with kind `owner_note` and the unchanged strict [typed note schema](vault-typed-attributes.md). The note remains one saved note; it is not relabeled as AI memory, a conversation archive or a general records collection. Ordinary saves, reloads and moving between these sections reuse the same nonextractable owner handle. Each saved revision still receives fresh content keys and nonces.

The preview mounts no format-1 recipient, agent, proposal or transfer panels and makes no request to the old attribute endpoints. A visible limitation notice explains the unavailable v2 adapters. Header navigation retains the explicit preview selection. Returning to the ordinary route is a separate navigation; format-1 storage and behavior are unchanged. Login does not implicitly open the new Vault.

## Lease and async boundaries

[`OwnerVaultController`](../crates/worker/ui/vault-owner-controller.ts) owns one [`OwnerKeySession`](../crates/worker/ui/vault-owner-session.ts) in the existing 15-minute idle/one-hour absolute [`VaultScope`](../crates/worker/ui/vault-lifecycle.ts). A separate Svelte owner context supplies that controller to the two editors. It exposes no raw owner-key handle or content-key export callback. Future recipient methods must separately authorize exact saved sources and return only their narrowly required encrypted outputs.

Hiding the document masks/inerts the UI and suspends the lease. Returning verifies the exact account, credential and session tag before resuming without PRF. Manual lock, pagehide, external logout/lock, expiry, failed verification and observed owner-authority changes dispose the lease and unmount/clear record editors and pending state. Voluntary lock/reload confirms disposal of local drafts; automatic/security locks do not wait for confirmation. Unsaved work has a browser unload warning where supported.

Controller generation checkpoints guard PRF results, record reads, decryption, sealing and mutation responses. Bootstrap also checks the generation after asynchronous WebCrypto and immediately before submitting a new root. A cancellation before submission cannot cause a late bootstrap write. Cancellation cannot roll back an already submitted or committed server mutation; an existing root is reopened rather than replaced after an uncertain attempt. The bootstrap helper still reconciles a lost response against the exact encrypted candidate while its initiating scope is current.

There is no key/PRF/plaintext persistence to localStorage, sessionStorage, IndexedDB or browser caches. Dropping handles and clearing arrays is bounded lifetime management, not a guarantee of physical browser-memory erasure.

## Records, failures and exact retry

[`OwnerRecordStore`](../crates/worker/ui/vault-owner-record-store.ts) pins owner, origin, Vault, generation, current root-registry revision, collection, record ID, kind and record revision, and verifies the response ETag. The registry revision is a live authority fence; it is not historical record content identity or content AAD. Missing and tombstoned records stay distinct. Unknown kinds/versions, malformed metadata, unreadable ciphertext and unsupported note documents remain unavailable and cannot be overwritten through the editor.

An immutable prepared write fixes method, prior revision, operation ID and exact serialized JSON body. Svelte retains it as raw immutable state, preserving the record client's identity guard. Retrying never reseals or changes those bytes. Inputs are frozen while an uncertain operation is pending; explicit reload confirms discarding local retry state and rereads the authoritative head. Conflict does not overwrite a newer version. A successful historical exact retry is followed by a new head read, so a later edit/deletion is shown instead of falsely restoring the older value. A confirmed write whose refresh fails is labeled confirmed-but-unchecked and requires reload before further editing.

Delete uses a conditional tombstone write. Saving after a tombstone explicitly shows deletion/recreation context and requires confirmation of a new revision, fresh operation and fresh ciphertext using the tombstone revision as `If-Match`. Reading missing/deleted data never recreates it. The server's bounded storage, mutation limits and cleanup rules remain those in the [owner-key and record contract](vault-owner-key-contract.md#bounded-owner-record-api).

Observed `owner_key_changed` or `owner_key_unavailable` errors drop the entire lease. An ambiguous `record_changed` response first rechecks the exact SSO session and root authority; a simple head race can then leave unrelated drafts available, while lost/replaced authority locks the Vault. This is reactive validation, not a push-revocation or background registry-polling guarantee.

## Evidence and rollout gates

The Node [controller/record-client tests](../local/conformance/vault-owner-controller.test.ts) locally cover one ceremony across both records/repeated writes; fresh ciphertext; exact retry bytes; historical retry after deletion; explicit tombstone recreation; conflicting revisions; suspended/late reads and PRF; cancellation during post-PRF encryption; missing/changed authority; and exact-session replacement during revalidation. Existing crypto, owner-bootstrap and v1 Worker regressions remain applicable.

The [new Worker/Chromium suite](../local/conformance/vault-owner-ui-browser.test.ts) is wired into `test:worker-browser`. It specifies first-open/repeated-save ceremony counts with synthetic PRF, actual v2 storage, note/name independence, exact lost-response retry against a later tombstone, recreation confirmation, malformed-record protection, mobile/keyboard semantics, hidden return, draft disposal, replacement SSO, late responses, cancellation/wrong/missing PRF, pagehide and idle expiry. The existing [actual virtual-Passkey HTTPS journey](../local/conformance/product-journey.test.ts) also visits the preview, verifies one real virtual WebAuthn/PRF assertion for repeated name/note saves and another on a fresh page, then verifies the original format-1 name remains unchanged.

Local browser execution in this task was blocked before browser startup: system Chromium's required local singleton socket returned `Operation not permitted`, including after the supported execution escalation. No local DOM/visual/virtual-authenticator pass is claimed for these additions. Exact-head CI must run these browser gates before readiness; physical intended-device PRF and recovery remain separate gates. A successful build/type check is not browser evidence.

Default activation remains gated on coherent, tested v2 recipient/AI/proposal/transfer behavior. Those adapters must bind the complete v2 source/target tuple and current authority, never fall back silently to old format-1 values or receive the owner root. Conversation/archive/search work is a subsequent slice, not part of this two-record preview.

The draft [selected v2 disclosure foundation](vault-selected-record-disclosure.md) adds separately versioned preparation and local-adapter contracts. It does not mount sharing controls or enable remote/recipient/proposal authority in this preview.
