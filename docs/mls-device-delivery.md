# Authenticated ciphertext mailbox and catch-up

**Status, 2026-10-19:** qualification code connects the existing Vault-owned
MLS device to an SSO/D1 mailbox. It delivers application messages and update
Commits within one instance, for an already established, independently reviewed
1:1 group. It is feature-gated with `messaging-qualification`, uses only the
local qualification schema/entrypoint and is absent from the product router.
The [independent-instance pilot](federated-messaging.md#first-pilot) remains open.

## Permission and identity

A public `DeliveryChannel` descriptor fixes a UUID, the actual 16-byte MLS group
ID and two endpoints sorted by scope hash. Each endpoint contains the registered
journal scope and reviewed signing-key fingerprint. Both owners must explicitly
approve exactly the same descriptor. The server cannot change its group, endpoints
or fingerprints under that ID. One pair/group cannot acquire a second channel ID.
Each owner can permanently block a channel; a repeated consent cannot unblock it.

The client checks the descriptor against its actual joined two-member MLS roster,
group ID and existing trusted keys. First fingerprint review remains an independent explicit step. The
[initial invitation adapter](mls-device-invitations.md) now transports
KeyPackage/Commit/Welcome and qualifies witnessed joining before activating
ordinary delivery. That transport cannot replace first trust. The consumer retains the
public channel descriptor; it contains no private key or checkpoint.

All endpoints inherit the registry's HTTPS, exact Origin, no-CORS, SSO cookie,
active account/epoch/session/credential and fresh-primary read restrictions.
Delivery mutations recheck these predicates in the SQL write. The channel must
still have both consents, no block, and both current active device generations.
A replacement or revoked generation makes the old channel unavailable; it never
silently redirects queued ciphertext to a replacement key.

A channel-scoped lease endpoint refreshes only its pinned pair's signed bindings.
It rechecks authority and the exact registry snapshots after asynchronous signing.
`syncDelivery` durably refreshes the existing own/peer pins before releasing wire
or processing received messages. It cannot turn a directory response into first
trust or accept a changed key. This allows an unlocked device to catch up after
its cached 300-second leases have expired, while still requiring the online
Owner Vault and independent witness. Peer lease refresh outside an already
approved channel is not a public directory in this slice.

SSO authenticates mailbox access, not possession of a particular MLS private key.
The server's sender scope and message kind are routing metadata. Only the actual
MLS credential/leaf key authenticates content and the sender shown by a consumer.
The browser verifies both the wire digest and actual MLS message; even internally
consistent forged transport metadata cannot authorize modified ciphertext.

## Durable send and receive

`VaultMlsDevice.approveDelivery(channel)` approves a descriptor after checking the
actual local group. `syncDelivery(channel, limit = 16)` performs bounded foreground
catch-up, returning `{sent,received}` counts for this call. It publishes at most
`limit` outgoing messages and consumes at most `limit` incoming messages; the
allowed limit is 1–32. Repeat as needed. These counts do not represent read status
or a globally quiescent conversation. The methods use the same Owner lease,
exclusive device lock, abort handling and authority checks as ordinary commands.

1. Before HTTP publication, the encrypted, witnessed journal fixes the outgoing
   ciphertext's channel, sender/recipient scopes and expiry. A retry keeps the
   same message UUID, ciphertext, digest, routing and deadline across reloads.
2. The server checks the canonical base64url wire, SHA-256 digest, allowed kind,
   current bilateral permission, expiry and capacity in a conditional insert.
   Ciphertext and its immutable receipt are one D1 record. The response is released
   only after the write; a lost successful D1 response is reconciled from a new
   primary read. The server's [batch transaction contract](https://developers.cloudflare.com/d1/worker-api/d1-database/#batch)
   underlies the qualification's fault-injected commit/reply-loss tests.
3. The receipt echoes the message ID, channel, both scopes, kind, wire digest,
   expiry, canonical envelope hash and server sequence. The client checks every
   field over its authenticated same-origin connection before acknowledging its
   local outbox. Reuse of a sender/message ID with another intent conflicts.
   The receipt is not a portable federation signature.
4. Receipt acceptance and merging a pending local update Commit are one encrypted,
   witnessed journal operation. Neither a lost HTTP reply nor a local write failure
   can clear the queue while stranding that Commit's merge. Ordinary manual
   `acknowledge` remains a lower-level qualification operation, not proof of remote
   acceptance.
5. The recipient fetches only its earliest unconsumed sequence. It validates
   routing/size/digest, authenticates MLS and durably saves the ratchet, event and
   duplicate receipt together. Only then does it POST consumption. Invalid MLS,
   an aborted IndexedDB transaction, failed witness, locked Vault or full journal
   leaves the server item unconsumed.
6. Consumption is recipient-only, exact and ordered. It removes the server's wire
   bytes while retaining the immutable receipt/tombstone. A lost response can
   produce a retry but cannot produce a second committed application event.
   External rendering/side effects still require the stable event ID; this does
   not promise global exactly-once delivery.

`stored` means the mailbox durably accepted ciphertext. `consumed` means the
qualified client reported successful local persistence after MLS processing.
Neither means that a person read the message. The server cannot independently
attest that a dishonest authenticated client performed decryption.

## HTTP and bounds

| Route | Contract |
| --- | --- |
| `POST /messaging/channels/:id` | Exact channel descriptor, at most 1 KiB; records only the authenticated owner's consent. |
| `POST /messaging/channels/:id/block` | Exact empty object; sticky block by either owner. |
| `GET /messaging/channels/:id/bindings/:scope` | Fresh `{own,peer}` issuer bindings, only for that endpoint's owner and pinned bilateral pair. |
| `POST /messaging/channels/:id/messages` | Exact envelope, at most 90 KiB JSON; canonical wire at most 64 KiB, application/commit only; returns `stored` plus exact receipt. |
| `GET /messaging/channels/:id/inbox/:scope` | One earliest unconsumed message or explicit null; never advances a cursor on fetch. |
| `POST /messaging/channels/:id/messages/:message/consume` | Exact recipient scope, digest and envelope hash, at most 512 bytes; idempotent consumption of the earliest pending item. |

There are at most 32 consented retained channels per owner, 64 unconsumed messages
per channel and 512 lifetime message receipts per channel. These admission limits
are SQL predicates, not read-then-increment application counters. Consumed receipt
rows are retained and cannot be deleted/reused to reclaim an identity. Existing
journal/operation/inbox limits may be reached earlier. Capacity/compaction,
per-account invitation abuse/rate control and monitoring still need production
work; these are conservative qualification limits, not an unlimited service.

New mail must expire in the next 24 hours. The journal fixes its deadline once;
a retry never extends it. An exact retry of already accepted mail returns its
original stored receipt even after expiry, without claiming successful device
receipt. An expired earliest item returns
`mailbox_expired_recovery_required` and blocks later items. The service never
silently skips a missing/expired Commit, resets a ratchet or changes group.
Expired ciphertext is not automatically purged by this slice; retention and
explicit recovery must be designed together before activation.

## Evidence and remaining work

[Eight workerd scenarios](../design/probes/mls/delivery.server.test.ts) exercise
bilateral authorization, origin/owner/generation isolation, device revocation,
exact retries, changed-intent rejection, ordered consumption, block, expiry,
capacity, competing inserts, successful D1 reply loss, all SSO predicates at
insertion, authority loss during reads, post-sign lease checks and retained
channel quotas across generation replacement.

[Three delivery journeys per browser](../design/probes/mls/vault-device.browser.test.ts)
use actual Owner Vault/controller APIs, independent Wasm devices, encrypted
IndexedDB state and real SSO/D1 handlers. They cover closed recipient pages,
send/consume reply loss, exact envelope reuse after reload, forged acceptance,
modified MLS with consistent transport metadata, a real receive transaction abort,
retry without burning the valid message, and update/application ordering across
reload. Existing seven custody journeys per browser remain in the same suite.
The native trust suite also checks group, joined roster, fingerprint and lease
binding. The virtual HTTPS bridge is a local runtime test, not physical Passkeys,
real TLS or remote D1 replication/failover qualification.

The [initial invitation flow](mls-device-invitations.md) now covers
KeyPackage/Commit/Welcome delivery. [Explicit termination/rejoin](mls-device-recovery.md)
handles actual epoch forks by moving to a fresh mutually approved group.
It preserves received history and quarantines old pending ciphertext.

Still open: public directory and key-change confirmation UI, in-place epoch
merging, usable text/recovery UI, competing-proposal coordination, intended-device/
physical Passkey qualification, background notifications, retention/recovery/abuse
operations, production schema/routing/provisioning and separate-instance
HTTPS federation. The current MLS policy retains no past-epoch secrets and does
not solve arbitrary cross-direction reordering. Failure stops catch-up with the
pending mailbox item intact; there is no automatic ratchet reset or device
re-enrollment. No server holds MLS state or plaintext.

Reproduce with the existing policy, Worker qualifier and MLS Wasm builds:

```sh
npm run build:policy
wasm-pack build design/probes/mls --target web --release --out-dir pkg-web -- --locked
node scripts/build-messaging-qualification.ts
MIKAKI_MLS_BROWSERS=chromium,firefox,webkit node --test --test-concurrency=1 design/probes/mls/delivery.server.test.ts design/probes/mls/vault-device.browser.test.ts
```
