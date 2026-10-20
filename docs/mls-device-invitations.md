# Durable initial MLS invitation delivery

**Status, 2026-10-19:** the qualification client now delivers the initial
KeyPackage and Welcome through authenticated same-instance HTTP/D1, rather than
through the test harness. The flow retains explicit fingerprint review, pinned
issuer bindings and the [Vault-owned witnessed journal](mls-device-custody.md).
It is behind `messaging-qualification`, absent from the product router and uses
only the local qualification schema. No production rollout or real-device
Passkey qualification is claimed.

## Fixed intent and trust

An `InvitationOffer` contains the existing public `DeliveryChannel` descriptor
and an `inviter_scope` naming exactly one of its two registered endpoints. The
UUID, group ID, both scope hashes/fingerprints and inviter role are immutable.
Both owners approve this exact offer. A changed role, group, key generation or
endpoint conflicts; it cannot restart or redirect the original operation.

First trust is still an explicit, independent fingerprint review plus a valid
issuer-signed binding. The transport never invents or confirms a peer from its
own metadata. The qualification exchanges these public trust inputs separately;
the invitation then transports all MLS KeyPackage/Commit/Welcome bytes itself.
A [foreground qualification UI](mls-chat-ui.md) now displays fingerprints and
requires explicit invitation-code approval. [Peer-key review](mls-peer-review.md)
now establishes those pins through signed code inspection and independently typed
fingerprints. [Changed-device-key admission](mls-device-replacement.md) now adds
explicit next-generation enrollment and bilateral fresh-group approval. Public
discovery remains open.

`BoundMlsClient.check_bootstrap` checks existing own/peer pins and distinguishes
an unjoined device, its forming group and its joined group. An existing group
must have exactly the offer's group ID and valid roster. Preparing an invitation
requires an unjoined engine and empty outbox; there is no implicit group reset.
An explicit local intent is saved before server consent or KeyPackage release.
Repeating that same consent can resume after a cached lease expires without
creating another KeyPackage. This metadata-only retry cannot release wire:
actual packet publication/admission first refreshes both pinned signed leases
and rechecks the exact local group, keys and current server permission.

The journal keeps one invitation for its one-group device. Its encrypted state
records the offer, phase and stable KeyPackage/Commit/Welcome IDs together with
private MLS state, outbox and receipt ledgers. The optional state field permits
reading earlier qualification records; an older reader cannot silently ignore
the new field and continue mutating that record. This is not a production schema
migration or a device-loss recovery protocol.

## Three packets and activation

1. The joining device creates one KeyPackage in the witnessed journal. Only after
   both owners consent does it publish a fixed `key_package` envelope to the
   inviter. The server accepts one KeyPackage per channel and retains its receipt.
   A second message ID cannot replace it, including after it has been consumed.
2. The inviter authenticates and validates that KeyPackage, creates the exact
   offered group, and prepares its Add Commit and dependent Welcome in one
   witnessed transaction. The received KeyPackage ID/digest is recorded in that
   same transaction. Only then does the inviter acknowledge its consumption.
   Re-delivery resumes the saved invitation rather than creating another group.
3. The inviter publishes `invite_commit` to a durable server receipt. This packet
   is not delivered to the new member as an ordinary MLS Commit: that device has
   not joined the group yet. The journal accepts the exact server receipt, merges
   the pending Commit and releases its Welcome dependency atomically. This also
   handles a lost Commit acceptance response without double advancement.
4. The inviter publishes the same prepared `welcome` envelope. The joining device
   verifies the expected group, trusted MLS credential/leaf key and original
   private KeyPackage. Joining, the provider's changed private state and the
   received Welcome ID/digest are saved atomically in the witnessed journal.
   A rejected Welcome or failed persistence cannot consume the saved KeyPackage.
5. Only after that local persistence does the joining client acknowledge Welcome
   consumption. One D1 batch records consumption, activates ordinary delivery and
   clears the retained Commit wire together. An injected activation failure rolls
   back the Welcome receipt and activation together. Successful lost D1 replies
   are reconciled by fresh authorized primary reads.
6. Both clients retain the stable event/packet receipts across reloads. A lost
   Welcome send response can be reconciled even after the peer has joined and
   activated the channel. An exact historical receipt is never treated as a
   current journal head or a human read acknowledgment.

Ordinary application/update mail is denied until Welcome consumption activates
the channel. A message may already exist in the inviter's encrypted outbox, but
it is not accepted by the normal mailbox before activation. KeyPackage and
Welcome bytes are cleared on their respective durable consumption reports; the
Commit bytes are cleared at activation. Immutable hashes/IDs/receipts remain.
As with the [normal mailbox](mls-device-delivery.md), SSO authorizes access, and
the server cannot prove that a dishonest authenticated owner actually performed
MLS processing. The qualified client enforces persistence before consumption.

## API, retry and bounds

`VaultMlsDevice.approveInvitation(offer)` prepares the exact local intent and
records only the authenticated owner's consent. `syncInvitation(offer)` performs
at most eight foreground protocol steps, returning `{phase,sent,processed}`.
Phases are `waiting_peer`, `waiting_key_package`, `waiting_welcome`,
`waiting_activation`, `active` or `pending`. The caller can retry the same offer;
no caller-held private checkpoint, raw state key or temporary MLS engine is used.

| Route | Behavior |
| --- | --- |
| `POST /messaging/channels/:id/invitation` | Exact offer, at most 1,200 bytes. Fixed inviter, both registered devices, independently recorded owner consents. |
| `GET /messaging/channels/:id/invitation/:scope` | Current authorized status and at most one role-appropriate KeyPackage/Welcome; never releases `invite_commit` to the joining engine. |
| `POST /messaging/channels/:id/invitation/packets` | Exact envelope, at most 90 KiB JSON / 64 KiB canonical wire. Check role, predecessor receipt, permission, current generations, expiry and message ID. |
| `POST /messaging/channels/:id/invitation/packets/:message/consume` | Exact recipient scope, digest and envelope hash, at most 512 bytes; consumed KeyPackage or joined Welcome only. |

All routes inherit exact HTTPS origin, no-CORS, SSO cookie/account/epoch/session/
credential restrictions, bounded responses and fresh primary reads. SQL writes
recheck live authority; snapshots recheck both endpoints after fetching a packet.
Block/revocation/replacement stop the old invitation and old scopes, rather than
following a new key. The channel's existing 32 retained-consent limit applies;
there are at most three retained bootstrap packets per channel. Message IDs also
cannot be recycled between the bootstrap and ordinary mail namespaces.

Each published envelope has a fixed expiry within the next 24 hours. Exact retries
keep the original ciphertext, routing, digest and deadline. A first receipt is
released only after durable storage. New steps require valid predecessor receipts;
an expired pending packet stops admission with
`invitation_expired_recovery_required`. The MLS KeyPackage's own validity is also
checked by MLS. Neither expiry, a blocked peer nor missing private state causes
silent KeyPackage regeneration, group reset or device re-enrollment. Explicit
[termination and fresh-group rejoin](mls-device-recovery.md) are now qualified;
[foreground repair controls](mls-chat-ui.md) now exercise that path, while
automatic competing-proposal coordination remains future work.

## Local qualification

[Five workerd scenarios](../design/probes/mls/invitation.server.test.ts) cover
fixed-role bilateral approval, wrong-owner/scope rejection, predecessor ordering,
normal-mail gating, immutable/competing packets, expiry, cross-namespace IDs,
transaction rollback at activation, lost successful publish/consume D1 replies,
all SSO predicates at insertion, and revocation/authority loss during snapshots.

[Two new journeys in each browser](../design/probes/mls/vault-device.browser.test.ts)
use real independent Wasm engines and Owner Vault/controller APIs. They lose the
KeyPackage send reply, KeyPackage consumption reply, Commit reply, Welcome reply
and final activation reply in sequence, destroy pages and resume, then decrypt
ordinary messages. No KeyPackage or Welcome is manually relayed by the harness.
A second journey queues ordinary text before activation, rejects modified Welcome
with internally consistent transport metadata, aborts the actual join's IndexedDB
transaction and then joins using the original valid Welcome/KeyPackage. A
command-targeted test fault avoids changing the browser's clock or depending on
the number of unrelated lease-refresh transactions.

These are virtual HTTPS/workerd tests with synthetic accounts/PRF input. Physical
Passkeys, network TLS, intended-device performance, remote D1 failover and separate
Cloudflare accounts remain unqualified. [Explicit abort/rejoin and update-fork recovery](mls-device-recovery.md), together
with [foreground invitation/text/recovery controls](mls-chat-ui.md), are qualified
locally. [Peer-key review](mls-peer-review.md) now also connects the initial and
changed-key confirmation controls. Managed changed-key admission,
competing-proposal resolution, abuse/retention
operations and production activation remain open. The independent-instance
[federation pilot](federated-messaging.md#first-pilot) is still open.

```sh
npm run build:policy
wasm-pack build design/probes/mls --target web --release --out-dir pkg-web -- --locked
node scripts/build-messaging-qualification.ts
MIKAKI_MLS_BROWSERS=chromium,firefox,webkit node --test --test-concurrency=1 design/probes/mls/invitation.server.test.ts design/probes/mls/vault-device.browser.test.ts
```
