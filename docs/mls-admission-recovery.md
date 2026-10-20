# Recovery after bilateral MLS admission

**Status, 2026-10-19:** local qualification now covers a peer closing a changed-key
invitation before this endpoint activates it, expired admission packets, an
interrupted pending Commit and a joined Welcome whose consumption never reached
the service. Users explicitly stop the failed invitation and approve a new public
code. Product routing, production schema/deployment and real-device qualification
remain open.

If the peer registers another key while this endpoint still retains its original
native group, a closed metadata-only recovery root can now use the
[latest-key stop bridge](mls-replacement-stop.md#bridging-an-existing-ordinary-recovery).
It preserves this flow's exact close receipt and cancellation history, then
requires a separate stop intent and fresh bilateral key/code approval. An
unconfirmed close must complete first. Pending same-key successors require their
own explicit veto or close; a fully confirmed deferred chain can now retain all
its receipts and use that bridge while the original native group remains intact.
Advanced native groups remain a separate recovery gate.

## Consent and native state

Pre-bilateral [proposal cancellation](mls-replacement-cancellation.md) still returns
`cancelled` or `admitted`; it cannot report an admitted proposal as cancelled.
After bilateral approval, stopping uses the existing immutable per-endpoint close
receipt. Both owners must separately obtain their own close receipt and approve
the same fresh successor. No failed invitation or old conversation is reopened.

A replacement may fail while one endpoint still holds the original group and
the other already holds a forming or joined replacement. In that case:

1. Exact replacement status confirms this owner's saved approval and bilateral
   admission or closure. An explicit unchecked UI confirmation authorizes stopping.
2. A witnessed `recovering` transition records a stable close UUID and the failed
   invitation as metadata. It emits no KeyPackage and leaves the native provider
   intact. Interrupted HTTP and local completion retry that same close intent.
3. The confirmed close changes the replacement record to `abandoned`. Old wire
   stays frozen; a fresh public invitation code requires separate owner approvals.
4. Once the successor is ready and both current signed device bindings verify,
   one journal transaction calls native replacement from original to failed,
   then native restart from failed to fresh. Only the fresh group can produce new
   admission wire. Both retirement fences, the checkpoint and any fresh KeyPackage
   commit together. Any native or IndexedDB failure preserves the previous state.

An endpoint that already activated the failed replacement uses ordinary native
restart instead. Initial-invitation expiry uses the same existing close/rejoin
flow. A pending Commit/Welcome is isolated with the failed conversation. Sent and
received history remains encrypted in the original device's Vault; pending text
is not re-encrypted, copied to another device or automatically sent to a successor.

The screen can approve a fresh successor while the still-retained original roster
is unusable for the newly confirmed peer key. This exception is limited to the
exact abandoned replacement recovery and a currently verified peer pin. Sending
continues to require an active two-member group. Fresh binding verification and
native roster/predecessor checks still apply before either provider transition.

Deferred replacement plus restart consumes two of the existing shared eight
native retirement slots. The journal checks both slots before successor consent;
existing bounds on recovery records, operations, history and state bytes remain.
Closing remains possible even when no more successor capacity is available.

## Authenticated admission metadata

`POST /messaging/channels/:id/invitation/status` accepts exactly `{offer,scope}`
with a 1,536-byte limit. It returns the exact channel and inviter plus boolean
`ready`, `complete`, `blocked` and `expired`; it never returns packet bytes. One
fresh-primary query binds the exact descriptor and own consent to the current
Owner SSO and own device. A revoked or superseded peer does not hide a closure
from a still-authorized caller. Admission and normal delivery continue to require
both current endpoints.

Before completion, expiry of any fixed admission packet, including a consumed
KeyPackage, requires recovery. This prevents a consumed predecessor disappearing
from the inbox from hiding an unusable admission. Packet expiry after successful
Welcome consumption does not invalidate a completed conversation. A locally fixed
outgoing envelope that expires before publication also requires recovery.

Synchronization persists `recovery_required` when it confirms closure or expiry,
freezing ordinary journal mutations and all outbox reads across reload. It does
not stop a healthy invitation simply because a network response was lost. Normal
exact packet/consume retries still resume such cases. A race with closure during
publication is reconciled through a fresh metadata check.

## Qualification and limits

[Service cases](../design/probes/mls/admission-recovery.server.test.ts) exercise the
actual Rust/workerd/D1 route: own versus peer consent, bilateral readiness,
blocked state, metadata-only response, peer revocation, consumed-packet/Welcome
expiry, completed admission, exact descriptors, unrelated owners, scope, Origin,
body bounds and current SSO.

[Four journeys per browser](../design/probes/mls/admission-recovery.browser.test.ts)
use the actual Wasm module, Owner Vault/controller, encrypted IndexedDB/Web Locks,
SSO witness and mailbox:

- Stop from the already activated peer before this endpoint replaces its key;
  explicitly recover in the UI, abort local begin/finish/activation transactions,
  lose successful close/rejoin responses, reload and retry exact receipts. Inspect
  and approve a fresh code on both devices, retain isolated history and decrypt
  new text while rejecting original and failed group reuse.
- Join Welcome locally but drop its consumption request, expire admission packets,
  reload the failure marker and recover with reversed inviter roles.
- Interrupt replacement Commit publication, expire the consumed KeyPackage,
  quarantine both pending Commit and Welcome, then deliver text in a fresh group.
- Lock the new device during a witnessed deferred recovery. Verify no late close
  request, reopen under a fresh lease and finish without an old local group.

A native regression restores an unjoined reservation between replacement and
restart, retains both retirement fences and the signing identity, rejects a stale
KeyPackage's Welcome after provider reset, and proves fresh encrypted text and
exclusion of the old device. Existing normal invitation, cancellation, delivery,
revocation and crash regressions remain in the full suite. Axe covers the
pending recovery confirmation. A separate Chromium capture was visually inspected
at 390 pixels, with no horizontal overflow.

```sh
node scripts/build-messaging-qualification.ts
MIKAKI_MLS_BROWSERS=chromium,firefox,webkit node --test --test-concurrency=1 design/probes/mls/admission-recovery.server.test.ts design/probes/mls/admission-recovery.browser.test.ts
```

[Same-key rejoin recovery](mls-rejoin-recovery.md) now qualifies a successor
closed before local restart and repeated stops within the retirement limit.
[Pending-rejoin cancellation](mls-rejoin-cancellation.md) and [further key updates
before bilateral consent](mls-generation-negotiation.md) now have explicit paths.
Further generation changes after bilateral admission,
missing local custody and compromised account/issuer recovery remain
separate gates. No automatic retry invents a new group, silently approves a peer
code or reconstructs private state. Remote CI and physical-device ceremonies are
not implied by local browser qualification.

Recorded locally on 2026-10-19: all 199 Node cases in the complete 17-file
Chromium/Firefox/WebKit regression passed in one run, with zero failures,
cancellations or skips. This includes 12 new browser journeys, their three
parent cases and three new service cases. All 38 standalone Rust cases passed
(29 binding and nine lifecycle). Native/Wasm and qualification-Worker Clippy
passed with warnings denied; strict TypeScript, Prettier, Rust formatting,
documentation links and source whitespace checks passed. The separate 390-pixel
Chromium visual capture also passed its overflow check and was inspected locally.
Remote CI, physical-device qualification and production activation remain unperformed.
