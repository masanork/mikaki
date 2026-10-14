# Cloudflare OS copies and workspace snapshots in Owner Vault

The first integration is an owner-reviewed browser handoff from an authenticated
Cloudflare OS conversation to Mikaki's existing Owner Vault. It needs no export
file. This is a local implementation, without hosted connection or deployment.

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

The apps currently have independent sessions. Cloudflare OS's authentication
gatekeepers resolve verified emails; Mikaki uses issuer and pairwise subject
identity. This save does not merge identities or replace Cloudflare OS sign-in.
Later SSO needs an explicit `(iss, sub)` account/linking contract, without
manufacturing an email or equating accounts by an asserted address.

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

Hosted origins, real Passkey devices, popup policy and independent-session
behavior still require deployed qualification. This slice does not close #115
or the live messaging gates.

After merging the Passkey login/Vault handoff from main on 2026-10-15, the
combined Vault script measures **342,007 raw bytes**. Its local level-9 gzip
estimate is **97,871 bytes** on macOS / Node 26.11.1 and **98,339 bytes** in
Ubuntu / Node 26.10.0 CI. The gzip ceiling is **99,328 bytes (97 KiB)**, raised
by 1 KiB to cover the CI measurement; its **344,064-byte raw ceiling** stays
unchanged. Login retains main's separately reviewed **104,448 raw / 32,768
gzip** ceilings. See the [budget measurements](worker-budgets.md) for CI
evidence. These are build-size estimates, not network timing.

## Workspace snapshots: local implementation

Cloudflare OS adds **Save workspace to Vault** and **Restore workspace from
Vault** with the same optional frontend URL setting. These are deliberate,
owner-reviewed copies, not automatic sync or a generic Durable Object backup.

Save opens Mikaki after a user click. Its unlocked Owner workspace requests
one payload from the pinned opener. The Cloudflare OS owner-only RPC captures
supervisor business rows and clones each permanent gadget facet before its
first await. A trusted inspector reads frozen user SQL/KV without starting
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
worktree export requires its own contract.

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

This has not been deployed; hosted session/popup/real-device qualification remains.
