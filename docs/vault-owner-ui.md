# Owner Vault UI

New Vaults use the v2 owner-key and record APIs through `OwnerWorkspace.svelte`, the shared `OwnerVaultController` and canonical `OwnerRecordStore`. The workspace adapter adds bounded collection discovery for archives; it does not define another record-crypto or mutation authority. The page selects a presentation using an escaped, fixed `data-vault-format` value; this is not permission to access data. Each API still checks current owner/session/credential/root authority.

One explicit Passkey PRF evaluation initializes or opens the parent key. Profile reads, edits, saves, explicit deletion/recreation, archive import, archive reads and reloads reuse the nonextractable handle within the existing 15-minute idle/one-hour absolute display lease. They do not prompt again. A reload/new page or manual/expired lock requires a new unlock. Visibility suspension hides the workspace, invalidates pending crypto results, and verifies the owner session before resuming the retained key. Lock/unmount removes profile, archive, search and pending-write state and disposes the handle. JavaScript strings cannot promise physical memory erasure.

The client pins the root and checks returned owner/origin/Vault/generation/root revision, collection/record/kind/content revision and ETags before decrypting. Missing records and tombstones remain distinct. A saved mutation candidate keeps the exact ciphertext/body, operation ID and base revision if the response is lost. Retry commits that same candidate; reloading explicitly discards a pending candidate after confirmation. Imported records have random IDs and never automatically recreate a tombstone.

## Personal data and conversations

- `personal/name`, kind `name`: the canonical encrypted UTF-8 display name (1–256 characters on save), shared with the unified-unlock preview and selected-disclosure contract. It is a personal assertion, not verified identity.
- `personal/owner_note`, kind `owner_note`: the canonical typed owner note, rendered through the same `OwnerRecordEditor` as the unified-unlock preview.
- `threads/<random ID>`, kind `thread-archive`: encrypted imported conversation JSON. Titles, speakers, message text and timestamps are encrypted together. The first importer takes a file no larger than 24,000 bytes; the record crypto limit remains 24 KiB including encryption framing. Unicode normalization can change serialized size, so encryption performs the final bound check.
- The UI reads at most six metadata pages (50 entries/page, current storage admission cap 256 total records/account). It then decrypts bounded archives locally. A nonempty search lazily loads a dedicated in-memory SQLite Worker, with literal AND terms, NFKC/case normalization, short Japanese matching, bounded results and exact message navigation. Loading/failure/no-match/truncation are distinct. The index covers the loaded snapshot and is discarded on archive changes, mutation activity, hidden visibility or lock. There is no persistent index or server-side plaintext query. See [search behavior and evidence](vault-thread-search.md).

Accepted archive example:

```json
{
  "format_version": 1,
  "title": "Application discussion",
  "messages": [
    { "speaker": "Alice", "actor": "human", "text": "What should I prepare?", "timestamp": "2026-10-03T00:00:00.000Z" },
    { "speaker": "Assistant", "actor": "ai", "text": "Let's list the required information.", "timestamp": "2026-10-03T00:01:00.000Z" }
  ]
}
```

This version supports 1–200 messages and human/AI actor labels. Only the shown fields are accepted; unknown fields and unsupported versions are rejected rather than silently discarded. Timestamps use canonical UTC ISO strings with milliseconds. Imports are owner-supplied copies, not evidence that a sender delivered a message or an authority accepted an application. It does not create live E2EE transport, authenticate imported speakers, call an AI endpoint or register an official application/approval receipt. Those require distinct schemas and trust contracts.

## Scope and compatibility

The owner confirmed that no existing data assets need migration. No importer is a rollout dependency. All accounts open this workspace by default, including accounts with existing v1 name/note records and no v2 parent head. Old records never choose the default presentation or prevent new-format initialization. The existing attribute panels remain available explicitly without rewriting data. Its connection section links to the explicit `?storage=legacy-v1` presentation, so retained v1 name/note data is still accessible when both formats coexist. That fixed presentation selector does not alter any API authorization and does not embed v1 mutation controls into the v2 workspace.

Existing connection management and explicit agent OAuth review remain available through the existing agent panel. The panel explicitly receives `connectionsOnly`: legacy exports, grant creation, draft decisions, note capabilities/decisions and note commit/retry controls are absent, and the mutation handlers reject those paths. Only existing-connection metadata, revocation and explicit OAuth review remain. The new owner-authorized `/vault/agents/connections` projection skips legacy proposal/draft and note reads rather than returning their plaintext to hidden controls; `/vault/agents/status` remains unchanged for the legacy panel. The flag defaults to false for legacy callers, preserving their actions; v2 profile/conversation data is not supplied to that interface. New-format selected disclosure/proposal handling, extra-credential wrapper registration, recovery and staged rotation activation remain separate follow-ups. The owner key never becomes agent authority.

## Integration boundary

The explicit `?storage=owner-v2` qualification preview remains available and uses the same controller, `personal/name` and `personal/owner_note` APIs as the default workspace. The two presentations differ in archive/connection UX, not personal-data schema. The earlier unmerged `personal/profile` JSON format is neither read nor converted automatically; any synthetic records produced from that branch remain untouched. There is no deployed-format migration in this change.

Archive import/read/local SQLite search are already implemented here. Later archive work should extend this schema and UI rather than add a second store or importer. Selected disclosure and AI adapters must still be explicitly wired to this workspace; the owner key and archived conversations are never automatically shared. Persistent search snapshots, archive provenance/authenticity, richer schemas and device qualification remain separate work.

## Evidence

[`vault-owner-workspace-browser.test.ts`](../local/conformance/vault-owner-workspace-browser.test.ts) exercises the served UI against actual workerd/D1/R2 with synthetic PRF: one unlock across profile save, lost-response exact retry, archive import/read/search and reload; manual lock clears the workspace; a fresh page reopens the same records; profile deletion/recreation uses tombstone revision; visibility suspension resumes without PRF, failed session confirmation removes plaintext, and mobile accessibility is checked. This is not physical-device WebAuthn qualification. The test is part of `test:worker-browser`. It also supplies an active legacy grant, pending and approved note proposals, a pending draft and a populated credential, checks that legacy mutation controls/routes remain unreachable before and after unlock/refresh, and verifies that revocation still works. Cross-presentation save/reopen checks use the same name/note records and retain the imported archive.

The underlying crypto/API race and atomicity evidence remains in the [owner-key contract](vault-owner-key-contract.md). Intended-device Passkey/PRF and search performance tests, persistent snapshots and end-to-end selected sharing remain outstanding.

[`product-journey.test.ts`](../local/conformance/product-journey.test.ts) also exercises the new workspace through actual HTTPS and Chromium virtual WebAuthn/PRF: invite registration, one credential call across initial unlock/save/reload, fresh-page decrypt, RP code exchange and logout/history denial. It does not qualify a physical phone or security key.
