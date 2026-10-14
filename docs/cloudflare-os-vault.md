# Cloudflare OS conversation copies in Owner Vault

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
Wallet/Vault records. Linking an accepted code commit or exported generated
document to a saved conversation is a next increment. Arbitrary runtime state
needs its own snapshot/restore contract.

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

The added review UI and archive schema produce a served Vault script of 324,568
raw bytes / 93,385 bytes under local level-9 gzip. Its budget is adjusted from
323,584/92,160 to 327,680/94,208 bytes for this concrete feature; other asset
limits remain unchanged. These are build-size measurements, not network timing.
