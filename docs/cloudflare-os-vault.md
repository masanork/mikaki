# Cloudflare OS copies and workspace snapshots in Owner Vault

As of **2026-10-20**, this integration is hidden from the normal product UI.
Separate Vault unlock/review windows and transfer deadlines do not yet provide
the intended seamless experience, and physical mobile qualification is incomplete.
The receiver components mount only when an operator explicitly sets
`CLOUDFLARE_OS_VAULT_UI_ENABLED=true`; the local interoperability fixture opts in.
The CFOS installation also leaves `VITE_MIKAKI_VAULT_URL` empty to hide its sender
controls. Existing encrypted records and the snapshot/transfer implementation are
retained. The procedures below document the experimental path.

The first integration is an owner-reviewed browser handoff from an authenticated
Cloudflare OS conversation to Mikaki's existing Owner Vault. It needs no export
file. The isolated hosted installation is **https://cfos.mikaki.org**, using
**https://auth.mikaki.org/vault** as its receiver. Owner login, managed Workers
AI chat and a reviewed save/restore roundtrip with a physical Passkey have
been verified on a synthetic desktop fixture.

## First user journey

1. In Cloudflare OS, open a conversation and choose **Save conversation to Vault**.
2. Mikaki's `/vault` opens in a popup. Use the existing Mikaki Passkey sign-in if
   needed, then unlock the Owner Vault.
3. Review the source origin, title and messages; choose **Encrypt and save this
   copy**. The canonical Owner record store commits ciphertext.
4. Cloudflare OS reports completion only after Mikaki confirms that write. The
   saved copy can be reopened and searched with other thread archives.

The copy contains human/AI text from the current history page, after its latest
context-compaction boundary. It is a text segment, not a full backup. Reasoning,
attachments, tool/operation logs, generated files and app database state are
excluded. Limits are 200 text messages and 24,000 serialized UTF-8 bytes; an
oversized segment fails rather than silently truncating.

Each deliberate save adds a snapshot under a random Owner record ID. Automatic
source synchronization/reconciliation and suppression of old revisions are not
implemented. An uncertain write in the same review reuses the exact canonical
mutation, operation ID, target and ciphertext. A new transfer after losing the
entire review may create another copy; it is not a deduplicated retry.

## Authentication and custody

The hosted installation uses Mikaki OIDC sign-in with an explicit issuer and
pairwise-subject identity. It does not manufacture an email or merge an older
email-keyed Cloudflare OS account. The app and Vault still have separate
sessions and authority: app login does not unlock the Vault or release its
keys. Other Cloudflare OS installations may retain their existing authentication
gatekeepers; this browser save does not replace their sign-in.

`mikaki-archive-v1` pins the popup/opener, exact origin and random transfer
channel. HTTPS is required except for loopback development. A receiver requests
one payload only after its authenticated Owner workspace is unlocked. It accepts
a bounded validated archive with matching source origin. Wrong windows,
origins/channels, expired handoffs and unsupported archives cannot produce
writes. Only the owner's explicit Save commits data.

Archive format 2 encrypts source origin, workspace/chat identity, sequence range,
per-message sequence IDs, title, speakers and text together. Source assertions
are not sender signatures. Legacy format-1 manual archives still work. No Owner
key, cookie, access token, read grant or Vault content is returned to the app.
Source text already exists in Cloudflare OS's server/AI processing boundary;
saving does not establish live E2EE against that service.

## Source state and Artifacts

The inspected Cloudflare OS checkout stores chat metadata/history in its
workspace Overseer Durable Object and gadget code in that DO's Git object
store. Gadget runtime data uses separate DO storage. Context Library optionally
reads Git-backed document collections from Artifacts; this is not an Artifacts
backup of all conversation history and app state.

Mikaki's [repository-work direction](adr/0016-personal-context-and-workload-delegation.md#data-placement-and-visibility)
also distinguishes ordinary context/code repositories from sensitive
Wallet/Vault records. The bounded workspace snapshot contract below now covers persisted gadget data,
chat history, attachments and Git-backed code alongside the text-only copy.

## Configuration and qualification

Set the Cloudflare OS frontend's build-time `VITE_MIKAKI_VAULT_URL` to an exact
Mikaki `/vault` URL without query/fragment. The button is absent if unset/invalid.
Local fixtures use synthetic conversations and Passkey PRF; no real conversation
or production Vault is accessed.

Sender tests cover text/source mapping, limits, destination validation, exact
peer/origin, cancellation and receipts. Receiver [contract tests](../local/conformance/vault-app-archive-handoff.test.ts)
cover refusal, provenance mismatch, expiry/disposal and sequence validation.
The [Owner workspace browser test](../local/conformance/vault-owner-workspace-browser.test.ts)
adds cross-origin receipt, real workerd/D1/R2 storage, lost-response exact retry,
receipt timing and reopening. Bundle the actual Cloudflare OS sender instead of
the default protocol fixture by setting its checkout root:

```sh
MIKAKI_CLOUDFLARE_OS_SOURCE=/absolute/path/to/cloudflare-os \
  node --expose-gc --test local/conformance/vault-owner-workspace-browser.test.ts
```

Local fixtures do not qualify hosted origins, real Passkeys or popup/session
behavior; see [hosted qualification](#hosted-qualification) for that separate
evidence. This slice does not close #115 or the live messaging gates.

After merging the Passkey login/Vault handoff from main on 2026-10-15, the
combined Vault script measures **342,007 raw bytes**. Its local level-9 gzip
estimate is **97,871 bytes** on macOS / Node 26.11.1 and **98,339 bytes** in
Ubuntu / Node 26.10.0 CI. Its **344,064 raw / 99,328 gzip** values are growth
warning thresholds. Per-resource raw/gzip growth does not block CI; the size
gate checks each complete Worker bundle against Cloudflare's **64 MiB
uncompressed** limit. See the [budget measurements](worker-budgets.md) for
the bundle totals and CI evidence. These are build-size estimates, not network
timing.

<a id="workspace-snapshots-local-implementation"></a>

## Workspace snapshots

Cloudflare OS adds **Save workspace to Vault** and **Restore workspace from
Vault** with the same optional frontend URL setting. These are deliberate,
owner-reviewed copies, not automatic sync or a generic Durable Object backup.

Save opens Mikaki after a user click. Its unlocked Owner workspace requests
one payload from the pinned opener. The Cloudflare OS owner-only RPC captures
supervisor business rows, durably journals the planned clone names, then checks
that the supervisor has not changed before cloning each permanent gadget facet.
A trusted inspector reads frozen user SQL/KV without starting
archived gadget code. A concurrent supervisor change fails capture; each facet
is individually frozen, without a cross-facet application transaction claim.
Private capture clones are deleted after capture, and expired abandoned clones
are reaped by a later capture.

Snapshot version 1 contains source origin/workspace/time, title, canonical
chat history and compaction checkpoints, attachment bytes, code-change history,
Git objects, permanent gadget metadata and each gadget's SQL/KV. It preserves
SQL blobs, ordinary tables, row IDs, indexes, views, triggers, generated columns
and AUTOINCREMENT high-water marks. KV values have an explicit portable codec
for dates, bytes, undefined, arrays, objects, maps and sets. Content Library
records already in gadget storage are included; external Artifacts services
and external gatekeeper-owned resources are not fetched.

The maximum serialized plaintext is 2 MiB minus the existing 29-byte encryption
frame. There are at most 16 gadgets, 10,000 supervisor records, 10,000 rows per
SQL table and 10,000 KV entries per gadget. SQL databases above 8 MiB are refused
before scanning. Oversized copies, native capabilities, virtual tables and
unsupported values fail the entire capture; data is not truncated. Active
agents, pending actions, proposed changes, provisional gadgets/bindings and
current or tombstoned private worktrees must be resolved first. Private
worktree export requires its own contract. Spawned/callable agent chat scopes
also require a separate contract and refuse export; dropping their frozen scope
could grant wider default capabilities when a restored chat resumes. Callback
history remains readable, with bindings to omitted argument capabilities removed.

Mikaki encrypts the complete snapshot as one `workspace-snapshots/<random ID>`
Owner record of kind `workspace-snapshot`. Only that collection/kind pair may
use a 2 MiB ciphertext frame and 3 MiB bounded JSON request. All ordinary records
retain the 24 KiB / 36 KiB limits. Existing AES-GCM identity/revision binding,
nonextractable Owner key, authority checks, CAS, immutable R2 objects, exact
mutation receipts and GC apply. No database schema change is needed in Mikaki.
An uncertain save retains the prepared operation and exact ciphertext for retry.

Restore opens a new Mikaki popup, lists up to eight saved copies at a time and
lets the owner select a preview. **Send this snapshot and restore a new
workspace** explicitly discloses that selected plaintext to its original
Cloudflare OS origin. Another app origin cannot receive it. No Vault keys,
credentials or general read capability are disclosed. Lock/unmount clears the
review and decrypted content; browser storage does not persist it.

Cloudflare OS's authenticated broker derives a fresh workspace ID from the
current caller and a random restore operation ID. It stages all gadget data
before publishing supervisor business rows and rebuilding indexes. The original
workspace is preserved. A durable owner/digest receipt makes an identical retry
idempotent and rejects a changed snapshot or owner. Interrupted staging is
reaped before the same restore resumes. The frontend retains an uncertain
restore's snapshot and operation ID only for that mounted view; a lost view may
produce another new workspace on a later deliberate restore.

Sharing links, collaborators, observers, gatekeeper credentials, external
bindings, approval rules, hooks, live agent context/callback arguments,
alarms and active sessions are not restored. Bindings between restored gadgets
are retained. Historical actions remain history and cannot be executed through
missing gatekeepers. External services must be reconnected manually. Snapshot
storage does not make the source server/AI processing end-to-end encrypted.

Qualification covers real workerd facet cloning and SQL/KV restoration,
chat/Git/attachment recovery, retry receipts, interrupted staging, collaborator
refusal, transactional rollback and portable SQL schema behavior. The paired
browser fixture bundles the actual Cloudflare OS transfer module and verifies
large encrypted writes, lost-response exact retries, explicit restore disclosure,
reopening, mobile layout/accessibility and lock clearing.
Imported SQL schema must contain single, non-data-producing DDL statements;
`CREATE TABLE AS SELECT` and appended data-writing statements are refused before
staging writes. Trigger bodies, including CASE expressions, remain supported.

The optional paired RPC mode uses the Cloudflare OS integration harness and a
real authenticated Cap'n Web WebSocket session. Browser buttons call that
session through Playwright callbacks. Save captures the real workspace; after
Vault disclosure, the authenticated broker restores it and a new session
reopens the copy. The test checks workspace registration, chat history,
binary attachment bytes, gadget SQL/KV, writable restored code and an unchanged
source. It also checks exact restore retries and another user's lack of access.
The source page and Passkey input remain fixtures; this does not exercise the
complete hosted Cloudflare OS UI or account linking.

Build the Cloudflare OS harness first:

```sh
pnpm exec vp run -F @gadgets/integration-tests build:test-gatekeeper
```

Then run in Mikaki:

```sh
MIKAKI_CLOUDFLARE_OS_SOURCE=/absolute/path/to/cloudflare-os \
MIKAKI_CLOUDFLARE_OS_RPC=1 \
  node --expose-gc --test local/conformance/vault-owner-workspace-browser.test.ts
```

## Complete local Cloudflare OS UI

The receiver was merged in [#245](https://github.com/masanork/mikaki/pull/245).
The companion implementation is reviewed in the
[portable snapshot API PR](https://github.com/masanork/cloudflare-os/pull/1) and
[Mikaki UI PR](https://github.com/masanork/cloudflare-os/pull/2) in the user's
Cloudflare OS fork. Upstream's contribution policy does not accept a feature of
this size; those PRs do not target `cloudflare/cloudflare-os`.

To exercise the complete production React frontend, first build in that checkout:

```sh
VITE_MIKAKI_VAULT_URL=https://mikaki.test/vault \
  pnpm exec vp run -F @gadgets/workshop-frontend build
pnpm exec vp run -F @gadgets/integration-tests build:test-gatekeeper
```

Then run in Mikaki:

```sh
MIKAKI_CLOUDFLARE_OS_SOURCE=/absolute/path/to/cloudflare-os \
MIKAKI_CLOUDFLARE_OS_RPC=1 MIKAKI_CLOUDFLARE_OS_UI=1 \
  node --expose-gc --test local/conformance/vault-owner-workspace-browser.test.ts
```

This mode serves the unmodified production assets on the local backend origin.
The actual Workshop buttons open Mikaki and use the browser's authenticated
WebSocket connection directly. It covers save confirmation, refusing disclosure
to a different origin, restoring a selected copy, navigation and reload, plus
the new-session business-data checks above. The test grants local-network access
only to the fixture's loopback origin, so Chromium can reach that backend.
The Workshop account/session and Mikaki login/Passkey PRF remain fixtures.

## Hosted qualification

The isolated Cloudflare OS deployment now uses **https://cfos.mikaki.org**.
The earlier staging page URLs redirect to it. Its dedicated Mikaki OIDC client
and migrated pairwise subject retain the owner's existing application data.
This deployment uses direct OIDC, with no Cloudflare Access gate. The app's
Workers AI binding supplies the model provider without a personal API token.

Hosted owner sign-in, existing workspace visibility and an AI response have
been verified. On **2026-10-17**, Chrome/macOS with a real Passkey completed
Vault unlock, reviewed encrypted save and restoration into a new workspace.
Chat, committed code, SQL and KV survived reload; the restored 106-byte
attachment matched the source's SHA-256. A row added only to the restored app
persisted after another reload, while the original retained its initial row.
Closing a save popup before unlock allowed a fresh retry. App logout made an
already-open app require sign-in on its next read; normal SSO reopened the
restored data.

Separate hosted session checks on the same date passed issuer-side revocation
without a logout notification: an operator revoked only the current Cloudflare
OS client session, left its existing 300-second lease unchanged, and observed
the open page return to sign-in automatically at the natural check deadline.
The RP removed its session row. Injected RP idle expiry also rejected a write
through an already-retained gadget capability; normal sign-in still showed
exactly the two original SQL rows. Shortening only a test RP session's cached
absolute deadline capped its lease/idle deadlines and stopped the open
connection automatically. Repeated normal sign-in preserved code, SQL and KV
under new app SIDs. The actual parent SSO, other sessions and global policy
were unchanged; revoked or expired rows were not reactivated. These scoped
fault injections do not qualify hosted signed Back-Channel Logout delivery,
a real 30-day SSO expiry, or mobile physical-device Passkey/popup behavior.

To repeat this journey, use a dedicated synthetic workspace containing chat,
an attachment, committed code, one SQL row and a distinct KV marker. Finish
agents and proposed changes,
choose **Workspace in Vault → Save workspace to Vault**, then unlock and
review the source in Mikaki before saving. Verify the app's completion receipt.

Restore that selected copy to the same `https://cfos.mikaki.org` origin through
**Restore workspace from Vault** and review the plaintext disclosure. It must
open a different workspace. Reload, compare chat, attachment contents, code,
SQL and KV, then add a row only to the restored app and confirm that the source
is unchanged. Do not seed data in the gadget constructor, which could mask
missing restored state. Check cancellation/retry and hosted app-session
invalidation separately. Keep physical-device results distinct from the
complete local UI test above.

The Cloudflare OS companion documents its
[hosted qualification checklist](https://github.com/masanork/cloudflare-os/blob/main/docs/mikaki-vault.md#hosted-installation-and-qualification)
and [direct Mikaki authentication configuration](https://github.com/masanork/cloudflare-os/blob/main/docs/mikaki-auth.md).
New installations need their own storage and explicit authentication setup;
Access preview configuration is not the configuration of this OIDC deployment.
