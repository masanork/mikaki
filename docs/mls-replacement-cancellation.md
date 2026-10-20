# Explicit replacement proposal cancellation and conflict recovery

**Status, 2026-10-19:** the local qualification now supports an explicit veto of
a pending changed-key proposal, including one whose approval never reached the
service. Owners can then review and approve one shared fresh proposal. Old
conversation blocking, independent key pins, immutable receipts and ciphertext
quarantine remain enforced. Product routing and production schema/deployment
remain disabled.

## The cancellation boundary

A proposal can be cancelled before both endpoint consents are committed. The
service permanently blocks that exact child and the original parent. Cancellation
never resumes the old conversation, reverses device registration, restores an old
key pin or releases old queued ciphertext. Even an unpublished proposal gets a
server tombstone, so a delayed approval request cannot resurrect it.

Once both owners have approved, cancellation returns the explicit `admitted`
outcome. It does not claim success, block that admitted child or reset the local
provider. The screen can continue joining or explicitly stop that invitation through the
[post-admission recovery flow](mls-admission-recovery.md). Cancellation and final consent run under database
transaction guards: whichever commits first determines whether the child is
cancelled or admitted. There is no state that both reports cancellation and admits
a bilateral child. The admission result can include a forming group, not just a
completed Welcome.

This slice provides pre-bilateral proposal cancellation. [Recovery after bilateral admission](mls-admission-recovery.md) now covers a peer
closing the child before local activation. [Further key updates before bilateral
consent](mls-generation-negotiation.md) now use signed historical membership and
fresh approval. Further key updates after bilateral admission, missing local
custody and compromised-account/issuer recovery still
need further qualification. Those conditions fail closed; this screen cannot
silently adopt another proposal, reconstruct private state or restart the parent.

## Exact service receipts and current authority

| Route | Contract |
| --- | --- |
| `POST /messaging/channels/:id/replace/status` | Exact `{previous,next,scope,operation_id}`; returns the same descriptors, scope/approval UUID and `unpublished`, `waiting`, `cancelled`, `admitted` or `closed`. |
| `POST /messaging/channels/:id/replace/cancel` | Exact `{previous,next,scope,approval_id,operation_id}`; returns the same intent plus immutable `cancelled` or `admitted` outcome. |

Both bodies are limited to 3,000 bytes. The caller's scope and SSO authority must
be current, including account status, epoch, credential, session revocation and
expiry. Historical registry metadata identifies exactly the original device slots
and changed-key proposal. A peer's superseded/revoked scope does not prevent a
still-current owner from stopping that stale proposal. An inactive caller scope
cannot use this exception. New admission continues to require both current active
scopes; cancellation does not weaken that view.

If the caller already has an approval receipt for this child, its exact scope,
approval UUID and serialized intent hash must match. An unrelated owner, different
parent/group/role/fingerprint, different approval UUID or different cancellation
intent cannot reuse a receipt. Existing generic invitation consent cannot bypass
a blocked child.

One D1 batch freezes the parent, creates the exact child if absent, records a
per-owner cancellation outcome, blocks only a non-bilateral child and asserts the
exact result with the existing CHECK guard. A failed statement rolls back the
whole sequence. A fresh primary read reconciles a committed but lost database
reply. Retries use the saved cancellation UUID and return the same outcome. The
service keeps at most 32 cancellation receipts per owner, without pruning blocked
children or approval records to reclaim space. Existing admission quotas still
count earlier approved generations/proposals.

The service exposes no public proposal directory or other owner's operation UUID.
Status is an authenticated check of a caller-supplied exact proposal, not a way to
invent or confirm a peer key.

## Witnessed client transitions and independent reapproval

`cancelReplacement(previous,next)` first saves `cancelling` and a stable
cancellation UUID in the encrypted witnessed journal. No cancellation HTTP request
is sent before that local preparation commits. The pending transition freezes
send/update/invitation work. Reload, a lost successful HTTP response and a failed
local finish retry that exact intent; no replacement key is generated.

A confirmed cancellation, or a peer veto observed through the authenticated exact
status response, records `cancelled`, quarantines the old outbox and clears its
active send/commit references. Received/sent history remains encrypted in the
unchanged device's Vault. Public ID/kind/digest metadata continues to describe the
quarantine after reload and after a later proposal activates. No old wire is
re-encrypted or automatically sent on that later conversation. The old native
provider is left frozen until a fresh bilateral transition legitimately replaces
it; cancellation does not perform an MLS membership change.

A committed `admitted` outcome instead returns the local transition to `consented`
and retains the cancellation receipt. The UI offers synchronization or an explicitly confirmed post-admission stop
followed by a fresh invitation. Native activation still requires exact independently
accepted pins, fresh leases and the original roster/predecessor checks.

The UI starts cancellation with an unchecked confirmation explaining that the
old conversation stays stopped. During an ambiguous result it shows a retry of
the same cancellation. Once cancelled, users may generate or import another code,
compare it with the peer and explicitly approve again. They cannot replace a
still-pending approved proposal simply by importing another code. A different
channel ID and group are required; cancelled candidate IDs/groups cannot be
reused. Each peer's own saved approval remains independent.

The journal retains up to eight replacement intents, including cancelled ones.
Completed replacement/rejoin activations still share the native eight-retired-
group limit. Cancelled intents do not consume a native activation, but their
journal/server tombstones are retained. Existing state, history and operation
limits can stop work earlier. Capacity repair, retention/archival and tombstone
compaction remain open.

Owner lock, visibility changes and lease invalidation synchronously clear codes
and plaintext. A held witnessed cancellation preparation cannot send a late HTTP
request or repaint after locking. Reopening reconciles the same prepared intent
under a fresh owner lease.

## Qualification

[Six service cases](../design/probes/mls/replacement-cancellation.server.test.ts)
use the actual Rust service/workerd/D1 for unpublished tombstones and exact retry,
competing proposals, stale approval rejection, revoked-peer cancellation, final
consent races, rollback, lost committed database replies, all five live SSO
predicates, unrelated owner/Origin checks and body bounds.

[Three journeys per browser](../design/probes/mls/replacement-cancellation.browser.test.ts)
use real Wasm, Owner Vault/controller, encrypted IndexedDB/Web Locks and the
SSO-authenticated witness/mailbox:

- Approve different proposals, reject silent substitution, explicitly cancel one,
  reload and approve the peer's proposal with reversed inviter roles. Decrypt real
  text while retaining old history/quarantine and rejecting the cancelled code.
- Drop an unpublished approval, abort actual begin/finish transactions, lose a
  committed cancellation response and reload with the same UUID. Observe the veto
  from the other device. Lock during another witnessed cancellation and verify
  no late request/display, then reopen and reconcile it.
- Attempt cancellation after bilateral consent, verify `admitted` rather than
  success, finish joining and explicitly terminate the conversation.

Axe and a 390-pixel overflow check cover the pending proposal screen; Chromium
captures a local screenshot for visual inspection. Physical-device/assistive-
technology qualification and remote CI are not implied.

```sh
npm run build:policy
node scripts/build-messaging-qualification.ts
MIKAKI_MLS_BROWSERS=chromium,firefox,webkit node --test --test-concurrency=1 design/probes/mls/replacement-cancellation.server.test.ts design/probes/mls/replacement-cancellation.browser.test.ts
```

The [qualification CI](../.github/workflows/mls-probe.yml) includes these files
alongside the existing lifecycle, trust, persistence, registry, custody, mailbox,
invitation, recovery, peer review and replacement cases.

Recorded locally on 2026-10-19: the complete 15-file Chromium/Firefox/WebKit
regression passed all 181 Node cases in one run, with no failures, cancellations
or skips. This includes the six new service cases and all nine new browser
journeys plus their three parent cases. The existing 37 standalone Rust cases
also passed. Native/Wasm and qualification-Worker Clippy warnings were denied;
strict TypeScript, Prettier, Rust formatting, documentation links and whitespace
checks passed. The pending-proposal screenshot was visually inspected at the
390-pixel viewport. Remote CI, physical-device qualification and production
activation remain unperformed by this local qualification.
