# Encrypted MLS device journal

**Status, 2026-10-19:** the isolated MLS qualification now includes an encrypted
IndexedDB journal for device secrets, trust decisions, outgoing wire messages,
received events and retry receipts. Chromium, Firefox and WebKit exercise real
OpenMLS/Wasm against browser IndexedDB, Web Locks and WebCrypto. This is not an
activated product chat feature. Production key custody, an authenticated remote
head witness, SSO enrollment, transport and user interfaces remain adoption gates.
The [feature-gated SSO/D1 adapter](mls-device-service.md) now qualifies registration
and HTTP witness operations locally; product routing and provisioning remain closed.
The [Vault custody/enrollment manager](mls-device-custody.md) now supplies the
state key through the actual Owner Vault lease and qualifies resumable enrollment
without carrying checkpoints or state keys through the test harness.

The implementation is [device-store.ts](../design/probes/mls/device-store.ts),
using [BoundMlsClient](../design/probes/mls/src/bound.rs) and its
[device trust policy](mls-device-trust.md). The
[browser qualification](../design/probes/mls/persistence.browser.test.ts) serves
fixed assets only. Its issuers, custody keys and independent witness are synthetic
fixtures in harness memory, with separate browser contexts for peer devices.

## Custody and scope

The caller must supply an unlocked, nonextractable AES-GCM 256-bit key with
explicit encrypt/decrypt usages. The journal neither generates a fallback key nor
stores that key alongside ciphertext. The intended integration must obtain it
from independently qualified device/Vault custody, with explicit unlock, lock,
logout and device-loss behavior. A `CryptoKey` marked nonextractable alone does
not protect a running application from compromised JavaScript or its distributor.

Each encrypted state uses a fresh random 96-bit IV and a 128-bit authentication
tag. Authenticated data binds the format, application origin, issuer, account,
device, key generation, storage UUID, custody-key UUID, signing-key fingerprint,
revision, previous head and transaction UUID. The IndexedDB key is a SHA-256 hash
of that canonical scope. The database contains only versioned encrypted current
and prepared records, their public metadata and digests. MLS keys, pins, binding
tokens, plaintext events and pending wire messages are inside the encryption.
The [foreground chat UI](mls-chat-ui.md) also keeps bounded sender plaintext
history and device-local display order in that same witnessed transaction.
Transport acceptance status does not imply peer decryption or human reading.

`bootstrap` imports one initial checkpoint only into an empty local scope whose
independent head is also empty. Existing or lost device state cannot be reset by
calling it again. Product enrollment must coordinate durable key creation with
registration; the raw fixture constructor and proof flow are not that adapter.
Plaintext `checkpoint()` remains a low-level test/internal serialization boundary,
not a backup API. The journal restores a fresh engine for each operation and
clears exposed byte arrays after use. This does not promise physical erasure of
JavaScript strings, Wasm memory, browser caches or filesystem remnants.

## Commit before release

One exclusive Web Lock covers a device's complete read, restore, crypto mutation
and commit. Other tabs restore the newest committed record after acquiring the
lock; no mutable MLS engine is shared or retained between calls. Browsers without
Web Locks fail closed. All IndexedDB writes use strict-durability transactions
and resolve on transaction completion, with crypto and network work outside the
transaction task.

A mutation follows this protocol:

1. Restore and validate the witnessed state. Apply the command to an isolated
   candidate and include its resulting MLS checkpoint, queue entries, trust
   changes, event/deduplication records and operation receipt in one plaintext
   state. On command failure, discard all partial mutations and record only the
   rejection and monotonic time watermark.
2. Encrypt the complete candidate and atomically prepare it in IndexedDB while
   retaining the old head. No wire message, plaintext event or success receipt
   is returned at this point.
3. Compare-and-set an independent witness from the old revision/hash to the
   candidate's revision/hash.
4. Atomically publish the same prepared record locally. Only then return the
   receipt; `outbox()` and `inbox()` also reconcile the witness before returning
   wire messages or events.

On restart, a prepared record is authenticated and restored before it can advance
an unchanged witness. If the witness already names that candidate, the journal
publishes the exact candidate without rerunning cryptography. This covers a page
ending after prepare, after witness acceptance or after local publish but before
a response. A lost witness reply or aborted publish transaction takes the same
recovery path. A failed prepare transaction cannot advance the witness.

`close()` drops the journal's key reference, aborts queued lock acquisitions and
prevents in-flight results from being released after locking. An already prepared
candidate can still require reconciliation after the next unlock. Closing does
not roll back an externally accepted head or delete pending messages.

## Independent rollback witness

Local authenticated encryption and an incrementing local counter cannot detect
replacement of the **entire** database with an older valid copy. `HeadWitness`
therefore requires authenticated, linearizable `read` and `compareAndSet`
operations outside that database. CAS retries return the accepted candidate while
it remains current, and the actual newer head after a conflict. A historical receipt
must never masquerade as current state. The original fixture keeps a witness in
Node outside the browser; integrated tests now also use the feature-gated Rust/D1
adapter. No production witness endpoint is mounted by this work.

A real adapter must authorize access for the exact registered account/device
scope, protect its own monotonic record from rollback, preserve it across browser
storage loss and make retries idempotent. The witness handles revision/hash pairs,
not MLS secrets or conversation plaintext. Its availability, metadata retention,
device revocation, scope registration and operational recovery require separate
qualification. Key/storage IDs must be retained under the device lifecycle
contract; allocating a new scope must never silently reactivate an old key after
state loss.

A newer or conflicting witnessed head, missing local state under an existing head,
a corrupted record or the wrong custody key fails closed. Recovery must supply
the exact committed state or explicitly enroll a new key generation. There is
no automatic fresh group, counter reset or acceptance of an old checkpoint.
Rollback protection assumes the witness cannot be rolled back with the browser;
it does not protect against a compromised witness and client together.

This profile requires the witness for reads and mutations, including composing
an encrypted send. It supports a recipient being offline, but does **not** yet
provide sender operation while disconnected from the witness. A different offline
profile needs a separately qualified monotonic anchor and recovery policy.

## Retry, delivery and identity policy

Commands use a UUID operation ID and a canonical command digest. Repeating the
same ID/intent returns the committed receipt and original message IDs; a changed
intent under that ID is rejected. The outbox returns the same persisted wire
bytes and digest on every retry, without resealing the message or advancing its
MLS ratchet. The receive ledger binds a transport message ID to the verified wire
digest and one inbox event ID. Duplicates do not publish a second event; reuse of
an ID for different bytes fails. Applications must render/upsert by that event ID;
reading the inbox is not an exactly-once external side-effect guarantee.

An invitation queues Commit and Welcome atomically. Welcome remains withheld
until the exact Commit digest is acknowledged and the pending MLS Commit is
explicitly merged. Key updates and removals use the same acceptance/merge rule.
Acknowledgment is an API boundary for a future authenticated durable transport
receipt. A local method call is not evidence of server acceptance, peer delivery
or a human read receipt. The current fixture relay supplies those calls itself.

Before each outbox release, the engine revalidates binding freshness, revocation,
review status and the exact own/peer signing-key fingerprint context saved when
the wire message was prepared. A later reviewed replacement cannot release a
queued message encrypted for the previous key. Removal requires only an active
sender, allowing removal of a revoked peer. Observed trust decisions and time
watermarks persist across reloads. Already released bytes and copied plaintext
cannot be recalled.

The existing conservative MLS epoch policy remains: application sends and
incoming traffic are blocked while a local Commit is pending; no past-epoch
secrets are retained, and the same-epoch reorder window is OpenMLS's default five
generations. A durable queue does not make arbitrarily delayed/reordered traffic
decryptable. Delivery must coordinate these limits, and simultaneous Commits or
messages delayed across an epoch still need an explicit conflict/rejoin policy.
No automatic rejoin or silent message deletion is implemented.

## Bounds and remaining qualification

The encrypted JSON state is capped at 8 MiB, including a bounded underlying
checkpoint. The journal allows 64 queued wire messages, 128 inbox events and 512
entries in each operation, receive and acknowledgment ledger. Capacity exhaustion
rejects the whole command; it never evicts ratchet state, silently drops messages
or prunes deduplication records. The invitation test fills all but one queue slot
to prove a failed Welcome admission does not leave a partial Commit. These are
qualification bounds, not a long-term archive design. Product pagination,
compaction, retention, quota recovery and schema/key migration remain unimplemented.
Whole-state serialization and repeated candidate restoration are intentionally
conservative and expensive; throughput, witness latency and target-device
performance must be measured before adopting this as the product storage engine.

Real-browser cases cover exact retry/reload, inbox deduplication, Commit ordering,
page termination at each durable boundary, receive recovery, transaction aborts,
lost witness replies, locking during an operation, simultaneous same-device tabs,
whole-record rollback/deletion/corruption, wrong custody keys, queue exhaustion,
key replacement, revocation and expiry/time rollback. Page termination and
transaction abort injection are not physical power-loss or operating-system
filesystem durability tests.

Before activation, qualify the real custody/unlock and witness adapters, device
registration and loss, the [qualified mailbox](mls-device-delivery.md) on intended
devices, the [initial invitation flow](mls-device-invitations.md), explicit
[abort/rejoin after epoch conflicts](mls-device-recovery.md), inbox/outbox
retention and the actual invitation, key-review and text-chat interfaces. The independent-instance/real-device
[messaging pilot](federated-messaging.md#first-pilot) remains open.
