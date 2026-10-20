# Recovery when a same-key rejoin stops before local activation

**Status, 2026-10-19:** local qualification now covers an agreed rejoin closed or
expired before this endpoint restarts its native group. It also covers repeated
stops within the existing retirement limit and a failed same-key successor of a
still-deferred [changed-key recovery](mls-admission-recovery.md). Product routing,
production schema/deployment and physical-device qualification remain open.

## Explicit stop and new consent

Previously, the local recovery record could retain one immutable `next` proposal
while the native provider still held the original group. If the peer activated
that proposal and then closed it, retrying `/rejoin` failed permanently. Selecting
another code would conflict with the saved proposal, and pretending the failed
proposal was locally active would misrepresent private state.

Synchronization now confirms the exact successor's status and records
`successor_failed: true`. The screen offers an unchecked confirmation to stop
that rejoin. It does not generate a replacement code or native KeyPackage on
failure detection. A network error alone never sets this marker.

`recoverRejoin(previous,failed)` first commits `begin_rejoin_recovery` in the
witnessed encrypted journal. This retains the parent's exact `next`, creates a
child close record with a stable operation UUID, and links it through
`deferred_from`. The managed failed invitation is metadata only; the native group
and old outbox are unchanged. Only then does it send the exact close request.
Lost replies, local completion failure and reload retry the original close UUID.
A Vault lock invalidates the handle before any late request or display is released.

Each endpoint needs its own close receipt for the failed successor. Both then
inspect and approve the same fresh public code. The parent proposal is never
silently replaced, reopened or treated as a successful conversation. A stopped
successor cannot be resumed by a stale request.

A status read of an absent candidate reports `unpublished`; it does not publish
consent or claim a close. An explicit recovery cannot close an absent candidate.
If the peer explicitly approves and then stops a candidate whose local approval
request never reached the service, the known exact closed child is recoverable.
Neither endpoint needs to activate it or publish a KeyPackage to stop it.

## One transaction for all deferred retirements

Pending recovery links point only to the immediately preceding recovery record,
whose exact saved successor must equal this child's offer. The bounded ledger
rejects inconsistent links, partial retirement, branching and cycles. Existing
records without these optional fields remain readable.

Once the fresh successor is bilaterally ready, current signed own/peer bindings
must verify. In one journal command, the client:

1. Applies any still-deferred changed-key transition at the root.
2. Restarts each original/failed group in order, reserving exactly the next
   agreed group and retaining every native retirement fence.
3. Marks the corresponding recovery records `rejoined`, isolates the original
   outbox on the root record and creates only the final invitation's KeyPackage
   when this endpoint is the joiner.

All native transitions, the checkpoint, recovery metadata and final outbox commit
together before wire can be released. Any native error or IndexedDB failure
restores the previous complete state. No intermediate failed group becomes a
source of admission wire. Previously accepted messages remain accepted in history;
unaccepted old text remains isolated and is never automatically re-encrypted or
forwarded. Other devices do not receive the original device's private history.

Deferred and completed transitions share the existing eight retired-group slots.
A pending chain costs one slot per restart plus one for an unapplied changed-key
root. Capacity is checked before successor consent reaches HTTP. A seventh
pre-activation failure can still complete with eight total retirements; a further
restart is refused without dropping fences or claiming approval. The nine-record
recovery limit still leaves room to stop the last active conversation. Other
operation/state/history limits can stop work earlier; capacity repair remains open.

The fresh-code UI permits an independently confirmed current peer key when the
root is an exact abandoned replacement, even though the retained old roster
cannot send to that key. This exception follows the verified recovery chain.
Sending still requires an active two-member group and normal trust checks.

## Authenticated successor status

`POST /messaging/channels/:id/rejoin/status` accepts exactly
`{previous,next,scope}` with a 2,500-byte limit. It returns the exact successor and
inviter, predecessor ID, caller scope, `state`, `complete` and `expired`.

`state` is `unpublished`, `waiting`, `admitted` or `closed`; the
[pending-proposal veto flow](mls-rejoin-cancellation.md) additionally returns
`cancelled` for a retained cancellation tombstone. An existing child must
match both descriptors, inviter and actual predecessor link. An unrelated ID
collision is a conflict, never an unpublished proposal. Expiry includes consumed
admission packets until completion; old packet age cannot invalidate a completed
group. Responses contain no packet bytes, private state or other owner's close UUID.

Fresh-primary reads require the caller's current device and Owner SSO. After
looking up the child, the service rechecks the exact blocked predecessor and this
endpoint's own close receipt with live account/epoch/credential/session/expiry
predicates. A revoked peer cannot hide a closure from a still-current caller.
This read does not authorize new admission. Existing SQL guards continue to
require both current endpoints and exact separate successor consents.

A close racing between status and consent is reconciled by a fresh exact status
read. Once the witnessed native transition has applied, synchronization uses the
current invitation authority instead of repeating consent and a no-op activation. Locally fixed failure markers prevent old proposal activation across reload
or another foreground synchronization. No generic initial-invitation API is used
to recreate a missing linked successor.

## Qualification and remaining boundaries

[Four service cases](../design/probes/mls/rejoin-recovery.server.test.ts) use actual
Rust/workerd/D1: separate parent-close authority, unpublished/waiting/admitted/closed
states, unapproved endpoint closure, immutable predecessor/role, unrelated owner,
scope, Origin, strict body bounds, ID collision, expiry/completion, peer revocation
and all five live SSO predicates changing during the child lookup.

[Five journeys per browser](../design/probes/mls/rejoin-recovery.browser.test.ts)
use real Wasm, Owner Vault/controller, encrypted IndexedDB/Web Locks, witness,
SSO and mailbox:

- Race peer closure after status but before consent; explicitly stop through the
  UI, lose close/rejoin responses, abort begin/finish/activation, reload and retry
  exact receipts. Independently approve a fresh code and decrypt real text while
  preserving original quarantine and rejecting retired groups.
- Stop seven successive candidates before local activation, restore the chain,
  complete within eight retirements, retain all history/fences and refuse the
  next restart before any approval HTTP request.
- Lose successful approval/status responses without inventing failure, then
  expire a KeyPackage before local restart and recover across reload.
- Drop the unpublished approval request, refuse to close an absent candidate,
  then recover after the peer explicitly approves and stops it, with no failed
  admission KeyPackage publication.
- Extend an unapplied changed-key recovery with another failed rejoin, lock at its
  witness, verify no late close, unlock and independently approve a fresh code.
  Normalize the changed-key and same-key transitions together before real text.

A native regression restores between repeated unjoined reservations, preserves
both signing identities and retirement fences, rejects stale KeyPackage material
and old-group traffic, then decrypts text only in the final fresh group. Axe and a
390-pixel overflow check cover the failed-rejoin confirmation. The Chromium
capture was also visually inspected at that width.

```sh
node scripts/build-messaging-qualification.ts
MIKAKI_MLS_BROWSERS=chromium,firefox,webkit node --test --test-concurrency=1 design/probes/mls/rejoin-recovery.server.test.ts design/probes/mls/rejoin-recovery.browser.test.ts
```

A busy local host may set `MIKAKI_MLS_TEST_TIMEOUT_MULTIPLIER=4` to extend the
outer test deadlines. The default remains 1 in CI. Protocol/lease expiry,
assertions and the device clock are unchanged; this does not qualify intended-
device performance.

[Healthy pending-rejoin cancellation/reselection](mls-rejoin-cancellation.md) now
keeps the original parent while explicitly choosing another code. [Repeated key
updates before bilateral consent](mls-generation-negotiation.md) now qualify fresh
changed-key admission. Further key changes after bilateral admission, missing
local custody, operation/state capacity repair
and compromised-account/issuer recovery remain separate gates. This qualification
does not activate product routing, migrate production schema, run remote CI or
qualify physical devices.

Recorded locally on 2026-10-19: the complete 19-file Chromium/Firefox/WebKit
regression passed all 221 Node cases in one run, with zero failures,
cancellations or skips. This includes 15 new browser journeys, their three parent
cases and four new service cases. This run used
`MIKAKI_MLS_TEST_TIMEOUT_MULTIPLIER=4` for the busy local host; all functional,
lease-expiry and protocol assertions remained unchanged. The run took about
20 minutes and does not qualify intended-device performance or the default CI
runtime budget.

All 39 standalone Rust cases passed (30 binding and nine lifecycle). Native/Wasm
and qualification-Worker Clippy passed with warnings denied. Strict TypeScript,
Prettier, Rust formatting, documentation links and whitespace checks passed.
The 390-pixel Chromium confirmation screen was visually inspected; its overflow
check and Axe assertions passed. Remote CI, physical-device ceremonies and
production activation remain unperformed.
