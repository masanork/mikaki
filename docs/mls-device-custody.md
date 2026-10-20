# Vault custody and resumable MLS enrollment

**Status, 2026-10-19:** the client now wraps its independent device-state key
through the existing Owner Vault session and resumes first-device enrollment
from encrypted local preparation. Seven scenarios in each of Chromium, Firefox
and WebKit connect the actual Owner Vault controller, WebCrypto, Wasm MLS and
feature-gated Rust SSO/D1 service. These are synthetic PRF/SSO fixtures, not a
physical Passkey/authenticator or production chat qualification.

The implementation is [VaultMlsDevice](../design/probes/mls/vault-device.ts),
with [browser fault/reload qualification](../design/probes/mls/vault-device.browser.test.ts).
It is still in the isolated messaging qualification. The product UI does not
mount it and no production messaging endpoint/schema is enabled. See the
[device trust](mls-device-trust.md), [encrypted journal](mls-device-storage.md) and
[SSO/D1 adapter](mls-device-service.md) contracts.

## Custody through an opened Owner Vault

The manager receives an already opened `OwnerVaultController`. It never receives
or exports the owner root key or a WebAuthn PRF output. It generates an independent
random 32-byte device-state key, imports a nonextractable AES-256-GCM handle, and
passes only this binary custody frame to `OwnerKeySession.seal()`:

| Bytes | Meaning |
| --- | --- |
| 1 | Frame version `0x01`. |
| 32 | SHA-256 of the journal's canonical origin/device/storage/key/fingerprint scope. |
| 32 | Random device-state key, separate from the owner/archive and MLS keys. |

This uses the existing [Owner record-v2 crypto](vault-owner-key-contract.md), with
collection `messaging-device-keys`, record ID equal to the custody-key UUID, kind
`mls-device-custody-v1` and revision 1. Owner origin/account/Vault/key generation
and record identity are authenticated by that existing format. The decrypted
frame must match the expected journal scope before its key can be imported.
Raw key/frame/checkpoint working arrays are cleared in `finally` blocks. This
does not promise physical erasure of JavaScript strings, runtime copies or old
encrypted storage snapshots.

The wrapped frame stays in a local IndexedDB record; it is not uploaded as an
Owner record or synchronized to another device. The owner root remains under
its existing credential wrapper on the server. Fresh-page unlock therefore
reuses the actual Owner Vault open/unlock path, including its current SSO and
credential checks. One Owner unlock can wrap/open the device and service many
messages; messaging adds no per-message PRF call. The existing document-local
login PRF handoff remains single-use and is never persisted or transferred to
the messaging server.

The manager exposes no raw key, engine or checkpoint getter. Public methods are
explicit `create()`, `open()`, `request()`, `outbox()`, `inbox()` and `close()`.
`create()` requires a caller-selected UUID for a new device and rejects an
existing local or server identity. `open()` has no creation fallback. The first
client profile does not activate replacement/recovery generations automatically.
The explicit [replacement enrollment flow](mls-device-replacement.md) now accepts
an exact signed predecessor on empty local custody and resumes its prepared new
key without treating the old binding as successful replacement registration.

## Prepare before publishing registration proof

Before first enrollment, the manager persists a bounded AES-GCM encrypted local
state containing the **pre-MLS** signing-key checkpoint, the exact enrollment
request/operation UUID and session tag. The plaintext metadata contains only the
format, owner/key context, device scope, public signing key, encrypted custody
frame and encrypted preparation. The enrollment state is authenticated under
its own purpose, complete scope, public key and local revision, with a fresh
random IV. The decrypted enrollment JSON is capped at 4 MiB, with the underlying
checkpoint capped at 2 MiB. It contains no KeyPackages, conversation or message
ratchet; those are available only after activation through the witnessed journal.

One exclusive Web Lock covers local preparation, registration reconciliation
and journal activation for an owner/device slot. All local writes use strict
IndexedDB transactions and complete before the next publication step. Crypto
and network work stay outside the transaction task. The sequence is:

1. Validate the opened owner lease, create/read the server-assigned messaging
   account namespace and reject an already registered device ID.
2. Generate the signing key, scope and independent state key. Seal the custody
   frame under the owner lease and commit the encrypted initial preparation.
   No enrollment challenge/proof is published before this commit.
3. Post the saved enrollment request with its saved operation ID. Validate the
   returned identity, nonce and scope against the prepared key. Save the exact
   signed proof request before sending it to the completion endpoint.
4. Verify the issuer binding with the pinned Wasm trust policy and save the
   bound checkpoint before bootstrapping the encrypted journal.
5. Reconcile or initialize that journal against its registered independent
   witness. Save an encrypted `active` marker, discarding the enrollment
   checkpoint/proof from the current custody record, before exposing the manager.

At restart, the key is reopened from the authenticated local frame through a
fresh owner lease. A fresh signed own binding first reconciles a completion that
already succeeded. Otherwise the original operation/proof is retried. Crashes
after custody prepare, proof prepare, binding prepare, journal bootstrap and
activation retain the same signing key, storage IDs and scope; no raw checkpoint
or device-state key is carried through the Node harness between pages.

If the challenge expires or the owner signs in with a different SSO context,
only the pre-MLS ticket may be renewed. The manager preserves the same signing
key, generation, storage/custody IDs and scope. It does not consume a challenge
bound to another SSO context. A fresh binding lookup and the server's exact
revision, retained-key exclusion and single-generation admission fences prevent
a second independent activation. Renewals are bounded per call and remain
subject to the service's enrollment quotas.

A prepared bound checkpoint is not a chat backup. If the journal is absent while
its witness has advanced, activation stops with state-loss/rollback detection.
It must not bootstrap that initial checkpoint again. An old custody snapshot
cannot reset a newer ratchet. Active records contain no enrollment checkpoint;
a missing active journal likewise never becomes a fresh group.

## Lease and publication boundaries

The Owner controller now supports retained child-handle invalidation. Suspend,
dispose, manual/idle/absolute/session lock and authority loss close the manager,
drop its state-key reference, abort queued/in-flight work and close its journal.
The manager also closes on hidden visibility and pagehide. Resuming a valid owner
lease requires reopening a new manager; an old closed handle stays unusable.
Owner-session verification in progress is awaited inside the device lock rather
than misclassified as permanent lease loss.

Every public journal operation checks current Owner Vault authority before and
after the operation, in addition to the journal's witness and signed device/key
checks. Commands are snapshotted before awaiting authority/locks. A changed root
revision, removed credential/wrapper, changed session or disposal during an
await prevents late success/wire/plaintext from being returned. A remotely
accepted/prepared operation may still need exact reconciliation after the next
unlock. Closing never claims to undo a server-side commit.

Refreshing an existing own lease uses the new `refresh_self` boundary, which
checks the exact local identity and signing key before observing the binding.
A peer token cannot stand in for a current own lease. Initial `bind_self` still
cannot overwrite a pin. Own revocation is retained as an observation and blocks
use after reload, rather than being discarded as a generic failed command.

Consumers must clear already displayed messages and temporary plaintext when
the owner lease closes. Existing copies cannot be recalled. This code does not
provide the final text-chat UI or claim exactly-once UI side effects.

## Evidence and remaining limits

The integrated browser scenarios cover:

- Actual Owner-key API bootstrap/open with synthetic PRF, Vault-wrapped state-key
  custody, first enrollment, MLS exchange and fresh-page decrypt/retry.
- Aborted first/local-proof writes with no premature proof publication.
- Multiple unlocked tabs with exact operation retry and one shared ratchet.
- Disposal while a witness PUT is accepted but its response is held, rejecting
  the late result and recovering the same prepared KeyPackage after unlock.
- Page termination at all five durable enrollment boundaries.
- Expired challenges, changed SSO context and lost successful completion replies,
  retaining the same device scope/key.
- Suspend/dispose/root-authority loss, corrupt custody, different owner and
  missing journal under an advanced witness, with no automatic key reset.

The native probe adds an own-refresh isolation/revocation test; its 25 cases pass.
Existing Owner-key crypto/lease tests also pass, including independent crypto
vectors and the three-browser WebCrypto lease test. The qualification entrypoint
mounts the actual Owner Vault session/key handlers and uses a local R2 binding
for their existing admission contract; it does not add a public product route.

The browser bridge and synthetic PRF are not TLS, hardware-backed key storage,
intended-device user verification or native WebView qualification. Browser
storage can be evicted, a custody key copied with its encrypted state can be
cloned, and compromised same-origin code can use unlocked capabilities. The
independent witness stops divergent/old state from silently advancing; it does
not recover missing private state or protect against rollback/compromise of the
witness together with the client. Repeated full-state encryption, owner authority
checks and witness round trips still need target-device performance measurement.

Live device state remains separate from a long-term conversation archive. Local
custody sync/export, schema/key migration, Owner-root rotation, explicit lost-key
replacement UI, cleanup/retention and durable audit remain unqualified. Fully
lost local custody cannot be reconstructed from SSO or the owner key alone.
Before activation, qualify actual Passkey/device behavior, enrollment/fingerprint/
key-review/recovery UI and production provisioning/schema/routes.
[Explicit recovery](mls-device-recovery.md) now qualifies cancellation and
fresh-group rejoin after actual epoch forks under the existing Owner lease. The [mailbox adapter](mls-device-delivery.md) now qualifies authenticated
same-instance ciphertext delivery and catch-up. The
[initial invitation adapter](mls-device-invitations.md) also qualifies the first
KeyPackage/Welcome exchange and witnessed joining before ordinary delivery.
