# Foreground one-to-one chat and recovery UI

**Status, 2026-10-20:** a shared product/qualification browser screen connects the
actual [Vault-owned device](mls-device-custody.md), [initial invitation](mls-device-invitations.md),
[authenticated mailbox](mls-device-delivery.md) and [explicit recovery](mls-device-recovery.md).
The [limited beta host](mls-beta.md) now opens this screen from the normal Owner
Vault, with explicit first registration and initial invitation-code creation.
The host is disabled by default and is not deployed. The screen itself receives
an already opened Owner Vault and enrolled device. The screen now connects
[explicit initial peer-key and replacement review](mls-peer-review.md) to the
witnessed native trust store. It does not discover accounts, unlock a Vault or
silently replace a key.

## Screen and public interface

[`MlsChatView`](../crates/worker/ui/messaging/chat-view.ts) owns one opened `VaultMlsDevice`
handle and an initially empty root element. The host may supply a public invitation
offer to review; supplying it does not approve it. `open()` reads the witnessed
state and, for an already active conversation, performs one bounded foreground
catch-up before enabling sends. Later progress uses the explicit **同期** button;
there is no background polling, notification or delivery/read acknowledgment UI.
The [stylesheet](../design/probes/mls/chat.css) supports narrow screens, full
fingerprint wrapping, keyboard focus and reduced dependence on color.

An invitation code is a bounded, prefixed base64url encoding of the exact public
offer, not a credential or an authenticated identity assertion. Codes include the
conversation/group IDs, both device scopes/fingerprints and the inviter role.
The screen displays the full fingerprints and conversation ID. Approval requires
an unchecked-by-default independent-confirmation checkbox, and the underlying
engine still requires its existing signed binding/pin checks. Code import alone
never registers consent or releases a KeyPackage.

The screen shows waiting-for-participant/activation states and disables text sends
until local admission is active. Active catch-up failures disable sends until a
successful sync. Reopening an active conversation checks the mailbox again, so a
reload does not turn a locally observed update fork into a usable conversation.
Error text describes a verification failure without claiming it proves an epoch
fork or identifying an honest/compromised participant.

## Durable text and honest delivery states

`VaultMlsDevice.sendText(operationId, channel, text)` uses a new witnessed
`send_chat` command. It checks the exact active managed channel, current local
MLS roster/pins and existing lease validity. Encryption, outgoing ciphertext,
stable message ID, sender's plaintext history and the operation receipt are one
encrypted journal transaction. Sending does not bypass the mailbox's fresh
authority/binding checks before wire publication. The earlier low-level `send`
probe command remains available but does not invent sender history retroactively.

`chatSnapshot()` returns only the caller's scope/fingerprint, current public
invitation/phase, recovery metadata, received events and sender history/status.
It reconciles the authenticated witness under the normal device locks and Owner
lease checks. It does not export checkpoints, wire bytes, quarantined wire or private keys.
The [peer-review slice](mls-peer-review.md) adds verified public pin/review data
to that snapshot and gates sending on the actual native trust/group checks.

| Display | Evidence |
| --- | --- |
| 送信待ち | Text/ciphertext is committed locally, without a committed local acceptance receipt. A remote acceptance may already have happened before a response was lost. |
| サーバー受理済み（既読ではありません） | The exact durable transport receipt was verified and committed locally. No human read or peer decryption claim. |
| 受信済み | Authenticated MLS processing and the inbox event are committed in this device's witnessed journal. |
| 停止した会話で保留・自動転送なし | The old conversation has a local termination record and this message has no local acceptance receipt. The wire stays frozen/quarantined; prior remote acceptance is still possible. |

Sender and recipient history survives reload and fresh-group rejoin in the
existing encrypted journal. Each new text event has a device-local monotonic
display position, saved in its MLS transaction. This is the order observed on
this device, not a global clock, remote timestamp or agreed cross-device order.
Earlier qualification inbox events without positions are shown first. Earlier
records can be read through optional schema fields; older readers reject these
new fields rather than silently discarding them.

The composer accepts at most 4,096 UTF-8 bytes. All untrusted text is inserted
with DOM text nodes; no Markdown/HTML interpretation, remote images or automatic
link fetching is added. Drafts live only in the view and are not persisted.
Durable sender plaintext intentionally remains available under the Vault custody
key; it has the same retention and historical-checkpoint caveats as received text.
This is not a separately archived Owner Vault record or a backup/export flow.

While a send result is ambiguous, the view retains the same operation UUID,
exact channel and text, disables editing and offers **同じ送信を再試行**. A returned
durable rejection can be edited as a new intent. Once text is committed, network
delivery retry uses the original encrypted outbox, not another send operation.
After a reload, witness reconciliation recovers any prepared send before the
snapshot is displayed. A draft that never reached encrypted preparation is lost.

## Termination, proposal review and lock

Stopping requires a separate confirmation showing permanent termination and the
need for both participants' fresh approval. The client freezes before its HTTP
close; a lost response displays **停止の確認を再試行**. Received/sent history remains
visible under the valid lease; the UI clears the composer and never carries an
old draft or unaccepted message automatically into the successor.

If the original approval was saved locally but its first HTTP request never
reached the service, close first reconciles only that same original explicit
consent and then obtains the exact termination receipt. The engine remains
frozen throughout and no KeyPackage/Welcome is published by this reconciliation.
If current authority does not permit that reconciliation, the view stays frozen
in confirmation-pending state rather than asserting a nonexistent remote block.

After confirmed closure, either participant can generate a fresh public code or
import the peer's proposal. Approval still requires fingerprint/code review.
The screen rejects another endpoint, reused group and a code differing from the
durably staged proposal before sending consent. It displays the exact staged code
after a lost response/reload and resumes only that explicit intent. Both owners
must agree on one code before approval. Importing a code that conflicts with the
local staged proposal, or receiving a service-reported conflict, displays an
error without selecting, replacing or merging the proposal. Independently staged
different proposals cannot be discovered by this screen; they can remain waiting
for peer approval. Proposal discovery/negotiation and safe supersession of an
already staged conflicting consent remain separate protocol/product work.

`VaultMlsDevice.onClose` propagates Owner lease invalidation to the screen.
Vault lock, logout/authority invalidation, hidden-page invalidation or explicit
view disposal synchronously removes history, drafts and proposal references and
closes the child handle. Lock remains available during a pending network call.
Every async completion checks closed state before updating UI. A closed view must
be constructed again with a new opened device handle; it cannot unlock itself.
DOM removal and cleared references do not promise physical memory erasure.

## Local qualification and remaining gates

[`chat.browser.test.ts`](../design/probes/mls/chat.browser.test.ts) uses the same
real OpenMLS/Wasm, Owner controller, encrypted IndexedDB journal, HTTP witness and
Rust/workerd/D1 handlers as the adapter qualification. Four journeys run in each
of Chromium, Firefox and WebKit:

- Explicit initial approval, lost consent/witness/mailbox replies, exact send
  retry, UTF-8 bounds, literal hostile text, bidirectional history and reload.
- Actual simultaneous MLS updates, failed catch-up/reload, lost close response,
  confirmed termination, mismatched proposal rejection, bilateral fresh-group
  rejoin, retained history and old pending text isolation.
- Actual IndexedDB send-transaction abort, retry and Vault invalidation during
  a held witness response, including completed callbacks that cannot repaint.
- Pre-admission cancellation after an approval request is dropped before reaching
  the service, plus rejection of a code addressed to another key without recording
  an unwanted consent.

The tests also run axe on the active screen and check mobile horizontal overflow;
Chromium captures local wide/narrow screenshots for visual inspection. These do
not establish assistive-technology, physical-device or intended-phone usability.
The shared browser fixture is in
[`vault-browser-support.ts`](../design/probes/mls/vault-browser-support.ts).

Before the peer-review slice, recorded locally on 2026-10-19: the complete ten-file Node regression passed
130 tests with zero failures. The final chat-only three-browser run, including
the dropped-first-approval cancellation fix, passed 15 Node cases (the twelve
journeys plus three parent cases). Strict TypeScript, Prettier and documentation
link checks also passed. The workflow includes these checks; remote CI execution
and production activation are not claimed.

The new encrypted history retains at most 128 sender texts, in addition to the
128 received-event limit. The existing 8 MiB state, 64-entry outbox, 512-operation
and eight-rejoin limits still apply; there is no history pruning or silent reset.
Post-admission failure recovery, operational capacity/retention/device-loss
recovery, actual Passkey/phone qualification, production routes/schema/custody
provisioning and independent-instance federation remain open.

The [changed-device-key flow](mls-device-replacement.md) connects accepted new peer
pins to separate bilateral channel consent, old-conversation closure and a fresh
group, including interrupted enrollment/activation and exact retry.

[Explicit proposal cancellation](mls-replacement-cancellation.md) adds immutable
pending-proposal veto, exact cancellation retry, peer-veto observation and fresh
consent to resolve conflicting codes.
