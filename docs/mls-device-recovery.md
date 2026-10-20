# Explicit conversation termination and rejoin

**Status, 2026-10-19:** the local qualification now supports cancelling a managed
invitation, terminating its conversation and rejoining a fresh group with the
same independently reviewed device keys. It also exercises actual simultaneous
MLS update forks and recovery through that explicit rejoin. This is behind
`messaging-qualification`, uses the qualification schema/entrypoint only, and is
absent from production routing. Physical Passkeys and independent-instance
federation remain unqualified.

## Recovery policy

The existing MLS policy keeps no past-epoch secrets and stops incoming processing
while a local Commit is pending. Simultaneous updates or cross-direction old-epoch
traffic can therefore stop catch-up. A failed MLS receive is not proof of an
honest peer or a particular failure cause; modified traffic can also be rejected.
The client does not silently choose a winning Commit, skip pending messages,
restore an old checkpoint or reset a ratchet. Failed transport-bound MLS receives
surface a bounded error such as `mls_receive_rejected` and remain unconsumed.

Recovery is an explicit decision to terminate the old conversation and mutually
approve a fresh group. This does not repair the old group's missing messages or
provide in-place MLS ReInit/merge. It applies to the managed invitation flow,
including an unjoined device or partially completed invitation, and preserves
both device signing identities and independently reviewed peer pins. Device-key
compromise, changed keys, revocation, missing custody or a missing/rolled-back
journal require their separate recovery/review paths; rejoin cannot override them.

## Termination before private-state replacement

`VaultMlsDevice.closeConversation(offer, reason)` takes the exact original offer
and one of `cancel_invitation`, `epoch_conflict` or `leave`.

1. A witnessed local `begin_close` records a stable operation UUID, exact offer,
   reason and the IDs of retained received events. It freezes crypto mutation and
   all wire-release methods before any termination HTTP request. Plaintext inbox
   history remains readable under the valid Owner Vault lease.
2. The server checks the exact group, endpoints, inviter and authenticated owner's
   current scope. One D1 batch inserts that scope's immutable close receipt,
   permanently blocks the channel and checks a final constraint guard. A later
   failure rolls the batch back; a lost successful response is reconciled against
   the durable receipt and block, using a fresh authorized primary read. The
   qualification uses D1's documented [batch transaction contract](https://developers.cloudflare.com/d1/worker-api/d1-database/#batch).
3. The client compares every response field before recording `complete_close`.
   The old private MLS state and pending ciphertext remain intact and frozen.
   Failure or a lost response leaves the local phase `closing`; retry resends the
   same persisted operation and reason rather than creating another intent.
4. A participant can terminate while its peer is revoked or unavailable; the
   terminating owner's own session/device authority must still be current.
   Either participant's block stops old sends, leases, receives and consumption.
   Each participant obtains its own close receipt before approving a successor.

If the initial explicit admission was saved locally but never reached the
service, the client reconciles that same original consent before requesting its
close again. It stays frozen and releases no admission wire. Failed reconciliation
keeps the local phase `closing`; it never claims a remote block without a receipt.

A close response confirms termination, not that pending messages were read or
never accepted. An HTTP acceptance may have happened before its response was
lost. Retained ciphertext/IDs are not automatically moved or re-encrypted. A
repeated consent or rejoin cannot reopen the original channel.

## A new, explicitly approved successor

`approveRejoin(previous, next)` durably stages the exact public successor offer
before sending its consent. `syncRejoin(previous, next)` resumes only that staged
intent. The new UUID and 16-byte group ID must differ from the old ones; endpoints
and reviewed fingerprints must be identical. The inviter role may change only as
part of the new offer agreed by both owners.

The server links the successor to `predecessor_id` and rechecks the caller's own
close receipt, old permanent block, current device generations, full endpoint
pins, group uniqueness and retained channel quota in the consent SQL. A normal
invitation endpoint cannot supply a missing successor consent without these
checks. Concurrent approval can make at most one unblocked successor bilateral;
a conflicting offer is rejected rather than automatically adopted. Callers must
agree on the same successor offer before approving it. The [foreground UI](mls-chat-ui.md) now displays/reviews exact codes and rejects
a different staged proposal. Discovery/negotiation and safe resolution of
independently staged competing same-key rejoin proposals remain open.

Before both consents are present, the old engine remains frozen and unchanged.
After verifying bilateral server acceptance, the client refreshes both signed
leases and rechecks its existing pins. One encrypted, witnessed `activate_rejoin`
operation then:

- Moves the old outbox into an inaccessible-to-delivery quarantine, retaining
  its ciphertext/IDs/digests. It does not automatically retry these messages in
  the new conversation and does not promise recovery of their original plaintext.
- Retains received events, their stable IDs and channel association. The recovery
  record identifies the old conversation's events; new events name the new channel.
- Discards old group, ratchet, pending-Commit and KeyPackage/HPKE state from the
  current provider, while retaining the exact device signing key and trust store.
- Records the retired group ID in the private checkpoint and reserves the exact
  successor group ID. Restoring the checkpoint cannot forget those tombstones or
  create/join a retired group. A second activation of the same recovery is a no-op.
- Prepares the new managed invitation and, for the joiner, one fresh private
  KeyPackage. The [normal invitation flow](mls-device-invitations.md) then delivers
  KeyPackage/Commit/Welcome and activates ordinary delivery only after witnessed
  joining. No new device registration or signing-key trust approval is implied.

An aborted local activation leaves the old frozen checkpoint/outbox in place;
no candidate KeyPackage is released. Reload reconciles a witnessed prepared
candidate or safely retries the unpublished transition. New-group ciphertext
cannot reopen old-group traffic. Failed old-wire attempts do not burn the valid
new ratchet. This is logical state replacement, not physical erasure: retained
old encrypted checkpoints/backups may still contain old secrets, as described by
the [journal's retention limits](mls-device-storage.md).

`recoveryStatus(previous)` returns the stable operation, reason, phase
(`closing`, `closed` or `rejoined`), staged successor, retained event IDs and
metadata for abandoned outbox entries. It exposes no private checkpoint, state
key or quarantined wire. It does not claim an abandoned ciphertext was never
accepted remotely. The journal keeps at most eight rejoins plus a final terminal
close, without pruning group/receipt tombstones to reclaim capacity. Its existing
8 MiB state, inbox, outbox and 512-operation limits still apply and can stop work
sooner. Retention, archival, capacity repair and backup/device-loss recovery remain
production gates.

## HTTP and evidence

| Route | Contract |
| --- | --- |
| `POST /messaging/channels/:id/close` | Exact `{offer,scope,operation_id,reason}`, at most 1,536 bytes; own current scope, immutable operation and permanent block. |
| `POST /messaging/channels/:id/rejoin` | Exact `{previous,next}`, at most 2,400 bytes; own predecessor close receipt, fresh group, exact current pins, immutable predecessor and independent owner consent. |

These routes inherit exact HTTPS origin, no CORS, SSO cookie/account/epoch/
session/credential checks, bounded responses, Owner lease locking/abort behavior
and authenticated witness CAS. Current authority is repeated in SQL writes and
fresh primary reconciliation reads. New consent never allocates/reset a witness
scope, changes a device generation or bypasses key-change review.

[Five workerd scenarios](../design/probes/mls/recovery.server.test.ts) cover exact
owner/offer/operation binding, immutable closure, peer revocation, transactional
rollback and successful reply loss, predecessor/own-close admission, fresh-group
and namespace restrictions, all SSO predicates at close insertion, Origin checks,
and one bilateral successor under competing requests.

[Two recovery journeys in each browser](../design/probes/mls/vault-device.browser.test.ts)
cancel an invitation with an unpublished KeyPackage, lose close/rejoin responses,
reload and join a fresh group without re-registering. They also cause actual
simultaneous update forks, verify failed messages remain unconsumed, preserve
received history, quarantine unsent ciphertext, change the explicitly agreed
inviter role, abort actual rejoin persistence, reload and resume decryption.
Old-wire rejection is followed by a successful new message. Three native cases
check unchanged identity, invalidated old KeyPackage secrets, retired/reserved
groups across restore, revocation fences and bounded retirement without reset.

This qualification does not provide automatic conflict resolution, recovery of
unread/unsent old-group plaintext, multi-device history, arbitrary reordering,
compromised-key recovery, a finished chat/recovery UI, remote D1 recovery or public
federation. The [independent-instance pilot](federated-messaging.md#first-pilot)
remains open. No production migration, deployment or physical Passkey test was
performed.

```sh
npm run build:policy
wasm-pack build design/probes/mls --target web --release --out-dir pkg-web -- --locked
node scripts/build-messaging-qualification.ts
MIKAKI_MLS_BROWSERS=chromium,firefox,webkit node --test --test-concurrency=1 design/probes/mls/recovery.server.test.ts design/probes/mls/vault-device.browser.test.ts
```

The [foreground chat/recovery UI](mls-chat-ui.md) connects these APIs to explicit
code review, termination confirmation, retry, history and quarantine status.

[Changed-device-key admission](mls-device-replacement.md) uses a separate explicit
approval and shares the eight-retired-group limit with same-key rejoin. A
successful replacement keeps the old close tombstone without freezing the new
conversation or invalidating a later close/rejoin after restoration.
