# Owner Vault UI

New Vaults use the v2 owner-key and record APIs through `OwnerWorkspace.svelte`, the shared `OwnerVaultController` and canonical `OwnerRecordStore`. The workspace adapter adds bounded collection discovery for archives; it does not define another record-crypto or mutation authority. The default `/vault` entry uses the shared `VaultSession` lifecycle around `OwnerWorkspace`; legacy presentation selection has been removed. Each API still checks current owner/session/credential/root authority.

One explicit Passkey PRF evaluation initializes or opens the parent key. Profile reads, edits, saves, explicit deletion/recreation, archive import, archive reads and reloads reuse the nonextractable handle within the existing 15-minute idle/one-hour absolute display lease. They do not prompt again. A reload/new page or manual/expired lock requires a new unlock. Visibility suspension hides the workspace, invalidates pending crypto results, and verifies the owner session before resuming the retained key. Lock/unmount removes profile, archive, search and pending-write state and disposes the handle. JavaScript strings cannot promise physical memory erasure.

The client pins the root and checks returned owner/origin/Vault/generation/root revision, collection/record/kind/content revision and ETags before decrypting. Missing records and tombstones remain distinct. A saved mutation candidate keeps the exact ciphertext/body, operation ID and base revision if the response is lost. Retry commits that same candidate; reloading explicitly discards a pending candidate after confirmation. Imported records have random IDs and never automatically recreate a tombstone.

## Personal data and conversations

- `personal/name`, kind `name`: the canonical encrypted UTF-8 display name (1–256 characters on save), available to the OwnerWorkspace and exact-source Agent v2 grant contract. It is a personal assertion, not verified identity.
- `personal/owner_note`, kind `owner_note`: the canonical typed owner note, rendered through the same `OwnerRecordEditor` in OwnerWorkspace.
- `threads/<random ID>`, kind `thread-archive`: encrypted imported conversation JSON. Titles, speakers, message text and timestamps are encrypted together. The first importer takes a file no larger than 24,000 bytes; the record crypto limit remains 24 KiB including encryption framing. Unicode normalization can change serialized size, so encryption performs the final bound check.
- The UI reads at most six metadata pages (50 entries/page, current storage admission cap 256 total records/account). It then decrypts bounded archives locally. A nonempty search lazily loads a dedicated in-memory SQLite Worker, with literal AND terms, NFKC/case normalization, short Japanese matching, bounded results and exact message navigation. Loading/failure/no-match/truncation are distinct. The index covers the loaded snapshot and is discarded on archive changes, mutation activity, hidden visibility or lock. There is no persistent index or server-side plaintext query. See [search behavior and evidence](vault-thread-search.md).

Accepted archive example:

```json
{
  "format_version": 1,
  "title": "Application discussion",
  "messages": [
    {
      "speaker": "Alice",
      "actor": "human",
      "text": "What should I prepare?",
      "timestamp": "2026-10-03T00:00:00.000Z"
    },
    {
      "speaker": "Assistant",
      "actor": "ai",
      "text": "Let's list the required information.",
      "timestamp": "2026-10-03T00:01:00.000Z"
    }
  ]
}
```

This version supports 1–200 messages and human/AI actor labels. Only the shown fields are accepted; unknown fields and unsupported versions are rejected rather than silently discarded. Timestamps use canonical UTC ISO strings with milliseconds. Imports are owner-supplied copies, not evidence that a sender delivered a message or an authority accepted an application. It does not create live E2EE transport, authenticate imported speakers, call an AI endpoint or register an official application/approval receipt. Those require distinct schemas and trust contracts.

## Scope and compatibility

The deployed application now uses one OwnerWorkspace entry. Historical v1 attributes and encrypted objects were not imported into the fresh baseline and are unavailable through current product APIs or UI. No conversion or legacy fallback runs during unlock. This boundary does not establish restoration of historical data; any future import requires its own reviewed source and verification contract.

The mounted connection section supports explicit OAuth review for exact v2 Owner-record grants. It displays the selected record source and authority and resets consent when selection changes. The ordinary scope-only OAuth profile remains available only when the owner selects and approves an active v2 grant; supplied authorization details must match the full record source and authority. Format-1 grant/proposal routes are retired. Generic agent private-draft tools remain separate from Owner-approved encrypted record commits. Owner-selected recipient sharing/release UI, additional wrapper registration, recovery and staged rotation activation remain follow-ups; the owner key never becomes Agent authority.

## Integration boundary

The former `?storage=owner-v2` qualification preview is no longer a separate presentation. The default OwnerWorkspace uses `personal/name`, `personal/owner_note` and imported thread-archive record-v2 APIs. No older `personal/profile` or format-1 attribute payload is read or converted automatically. There is no deployed-format migration from historical database rows in the fresh baseline.

Archive import/read/local SQLite search are implemented here. Owner-side record recipient selection and release, archive provenance/authenticity, live E2EE messaging, richer schemas and device qualification remain separate work. The current recipient-side v2 consent and Agent OAuth review do not provide a general Owner share/release workflow.

## Evidence

[`vault-owner-workspace-browser.test.ts`](../local/conformance/vault-owner-workspace-browser.test.ts) exercises the served UI against actual workerd/D1/R2 with synthetic PRF: one unlock across profile save, lost-response exact retry, archive import/read/search and reload; manual lock clears the workspace; a fresh page reopens the same records; profile deletion/recreation uses tombstone revision; visibility suspension resumes without PRF, failed session confirmation removes plaintext, and mobile accessibility is checked. This is not physical-device WebAuthn qualification. The test is part of `test:worker-browser`. It also verifies the current OwnerWorkspace lifecycle and archive/search behavior. Agent v2 OAuth source selection and consent are covered separately by the paired-worker `agent-oauth.test.ts`; these tests do not qualify an Owner share/release UI or old v1 data access.

The underlying crypto/API race and atomicity evidence remains in the [owner-key contract](vault-owner-key-contract.md). Intended-device Passkey/PRF and search performance tests, persistent snapshots and end-to-end selected sharing remain outstanding.

[`product-journey.test.ts`](../local/conformance/product-journey.test.ts) also exercises the new workspace through actual HTTPS and Chromium virtual WebAuthn/PRF: invite registration, one credential call across initial unlock/save/reload, fresh-page decrypt, RP code exchange and logout/history denial. It does not qualify a physical phone or security key.
