# Owner Vault UI

New Vaults use the v2 owner-key and record APIs through `OwnerVault.svelte` and `OwnerRecordStore`. The page selects a presentation using an escaped, fixed `data-vault-format` value; this is not permission to access data. Each API still checks current owner/session/credential/root authority.

One explicit Passkey PRF evaluation initializes or opens the parent key. Profile reads, edits, saves, explicit deletion/recreation, archive import, archive reads and reloads reuse the nonextractable handle within the existing 15-minute idle/one-hour absolute display lease. They do not prompt again. A reload/new page or manual/expired lock requires a new unlock. Visibility suspension hides the workspace, invalidates pending crypto results, and verifies the owner session before resuming the retained key. Lock/unmount removes profile, archive, search and pending-write state and disposes the handle. JavaScript strings cannot promise physical memory erasure.

The client pins the root and checks returned owner/origin/Vault/generation/root revision, collection/record/kind/content revision and ETags before decrypting. Missing records and tombstones remain distinct. A saved mutation candidate keeps the exact ciphertext/body, operation ID and base revision if the response is lost. Retry commits that same candidate; reloading explicitly discards a pending candidate after confirmation. Imported records have random IDs and never automatically recreate a tombstone.

## Personal data and conversations

- `personal/profile`, kind `profile`: encrypted JSON containing a display `name` (1–256 characters on save). It is a personal assertion, not verified identity.
- `threads/<random ID>`, kind `thread-archive`: encrypted imported conversation JSON. Titles, speakers, message text and timestamps are encrypted together. The first importer takes a file no larger than 24,000 bytes; the record crypto limit remains 24 KiB including encryption framing. Unicode normalization can change serialized size, so encryption performs the final bound check.
- The UI reads at most six metadata pages (50 entries/page, current storage admission cap 256 total records/account). It then decrypts bounded archives locally. Search is a case-insensitive substring over titles and message text in those loaded archives. It is not SQLite FTS, a persistent index or a server-side plaintext query.

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

The owner confirmed that no existing data assets need migration. No importer is a rollout dependency. For accounts that do have existing nondeleted v1 name/note records and no v2 parent head, the existing attribute panels remain available without rewriting data. New/empty accounts and accounts with a v2 parent head use this workspace.

Existing connection management and explicit agent OAuth review remain available through the existing agent panel. Its old attribute data-source actions are locked in the v2 workspace; v2 profile/conversation data is not supplied to that interface. New-format selected disclosure/proposal handling, extra-credential wrapper registration, recovery and staged rotation activation remain separate follow-ups. The owner key never becomes agent authority.

## Evidence

[`vault-owner-ui-browser.test.ts`](../local/conformance/vault-owner-ui-browser.test.ts) exercises the served UI against actual workerd/D1/R2 with synthetic PRF: one unlock across profile save, lost-response exact retry, archive import/read/search and reload; manual lock clears the workspace; a fresh page reopens the same records; profile deletion/recreation uses tombstone revision; visibility suspension resumes without PRF, failed session confirmation removes plaintext, and mobile accessibility is checked. This is not physical-device WebAuthn qualification. The test is part of `test:worker-browser`.

The underlying crypto/API race and atomicity evidence remains in the [owner-key contract](vault-owner-key-contract.md). SQLite projection, intended-device Passkey/PRF tests and end-to-end selected sharing remain outstanding.

[`product-journey.test.ts`](../local/conformance/product-journey.test.ts) also exercises the new workspace through actual HTTPS and Chromium virtual WebAuthn/PRF: invite registration, one credential call across initial unlock/save/reload, fresh-page decrypt, RP code exchange and logout/history denial. It does not qualify a physical phone or security key.
