# Stopping admitted replacements after another key update

**Status, 2026-10-20:** the local qualification service now supports an explicit,
stop-only operation for a bilaterally admitted changed-key successor after an
endpoint registers another key. It retains an immutable receipt for the calling
current generation and permanently blocks that exact successor. Fresh agreement
with the latest key remains a separate bilateral operation.

The encrypted client journal and UI now connect this service to fresh current-key
approval and actual Wasm text delivery when the unchanged endpoint retains
the completed original native group or has already activated the exact failed
changed-key target, including an unjoined reservation, a forming group with a
pending commit, or a joined pair. The original-group path includes a journal already redirected
to a closed ordinary admission-recovery root and its confirmed deferred same-key
successors. Every pending proposal must first be explicitly cancelled or closed. The
latest registered device uses a fresh profile and retains no old private history.
Repeated admitted-but-unactivated
successors remain explicitly stopped until the final fresh agreement.

Recovery from a later native same-key successor, a retained local ordinary-close
chain for an activated replacement, simultaneous changes at both endpoints, device loss, capacity repair, product hosting, production
provisioning/routing and physical-device validation remain open.

## Failure and authority boundary

For a completed original conversation O between A1 and B1, both owners approve
successor X between A1 and B2. Before joining finishes, B3 registers in the same
account/device slot. The ordinary close route correctly refuses B3's scope,
because it is outside X; B2's superseded scope also has no current authority.
Proposal veto cannot report a bilaterally admitted child as cancelled.

`POST /messaging/channels/:id/replace/stop` supplies the missing stop-only bridge.
It accepts the exact shape `{previous,next,scope,operation_id}`, at most 3,000
bytes. Here `previous` is O, `next` is the admitted X, `scope` is the caller's
current registered scope, and `operation_id` identifies this explicit stop intent.
The response is exactly:

```json
{
  "predecessor_id": "original-channel-uuid",
  "channel": { "id": "failed-channel-uuid", "group": "group-id", "a": {}, "b": {} },
  "inviter_scope": "failed-inviter-scope",
  "scope": "current-caller-scope",
  "operation_id": "saved-stop-uuid",
  "state": "closed"
}
```

Channel endpoints in the response are the complete exact requested endpoints,
including their scopes and fingerprints; the abbreviated example omits values.
No token, packet, plaintext or private state is returned.

The matching read-only `POST /messaging/channels/:id/replace/stop/status` accepts
the same bounded shape. It returns `state: "admitted"` or `"closed"` with the same
exact descriptors, current caller scope and request operation UUID. It checks
current authority on a fresh primary read and writes no receipt, consent, channel
or fence. A successful read is not a stop acknowledgment. The client uses it to
reject an absent, unilateral, substituted or unavailable target before persisting
a new local intent; the stop write still repeats all authority predicates.

Once a local stop intent is witnessed, the stopped target cannot advance its
saved replacement consent or native activation. This guard applies even while
the service still reports admitted and both endpoint keys remain current. Old
proposal synchronization returns recovery-required before channel HTTP; direct
journal consent/activation commands reject the stopped target. Only a distinct
fresh target can proceed after the stop is confirmed.

Every write and the final primary reconciliation require:

- The exact completed and already blocked original conversation, including its
  group, endpoint scopes/fingerprints and inviter.
- The exact existing child, including its group, endpoints, inviter and original
  predecessor link. Both endpoint consents must already be set. An absent or
  unilateral proposal cannot be created, cancelled or approved by this operation.
- Historical registry evidence that X changes exactly one original device slot
  to a higher generation with a different key.
- Live Owner SSO and the caller's current registered device head in an endpoint's
  same account/device slot. A later generation must follow a revoked historical
  endpoint and have a different key/fingerprint. Another device UUID under the
  same owner does not qualify.

An unchanged current endpoint can also stop X. The peer may already be revoked;
stopping delivery does not require that peer to cooperate or become live again.
The caller's active account, matching security epoch, active credential,
unrevoked/unexpired session and current device head remain mandatory. This uses
the existing Owner-authenticated service boundary; it does not assert physical
possession of a device's private key.

## Atomic stop and retained intent

The qualification-only `messaging_replacement_stop` table retains the child,
owner, current caller scope, operation UUID and canonical intent digest. Each
child/scope has one immutable receipt, and operation UUIDs are unique within this
table. A changed descriptor, UUID or role cannot rewrite the saved intent.
Each later registered generation must save its own explicit stop intent; an old
generation's receipt does not grant the newer generation authority.

One D1 transaction inserts the receipt, blocks the exact admitted child and checks
the complete authority/receipt predicate again using the existing CHECK guard.
Any denied or failed statement rolls back the entire transaction. Authority loss
after receipt insertion cannot leave a partially confirmed stop. The original
parent stays blocked, and admission/cancellation receipts and ciphertext remain
untouched.

A fresh-primary read reconciles the exact blocked child and receipt even when
the committed batch reply was lost. It rechecks current caller scope and SSO;
loss of authority after commit produces no successful acknowledgment. The
existing unconfirmed-error convention returns 409 after a failed batch, or 503
when a successful batch cannot be confirmed by that read. Clients must retain
their frozen intent until an exact successful response is reconciled.

Receipts are bounded at 32 per Owner across all device generations. Existing
exact retries still succeed at the limit; a new stop rolls back without blocking
its target. The other owner records a separate intent and has a separate limit.
Receipts and group/channel fences are never deleted to make room.

## Fresh approval remains separate

The existing uniqueness rule refuses an alternative O-to-Y proposal while X is
an unblocked bilateral successor. After explicit stop, A1 and the current B3 may
independently approve a fresh channel/group Y using their exact latest scopes and
fingerprints. One new approval still grants no live pair lease. Both new approvals
remain mandatory, along with the existing historical-membership proof and native
group activation before real text can flow.

X's old approvals do not carry forward to Y. Retrying X's stop cannot affect Y,
and substituting Y under X's stop UUID cannot close Y. X and O remain blocked.
Stopped invitation packets cannot be fetched, consumed or republished, including
when both endpoint keys are still current. Their stored ciphertext is retained;
the operation does not copy it into the fresh conversation.

## Witnessed journal, native retirement and UI

After read-only preflight, `begin_stop_replacement` saves the original and failed
offers and a stable stop UUID in the encrypted journal and authenticated head
witness. It quarantines the old outbox and freezes sends, receives, ordinary
admission and wire release. It keeps the current native provider intact. Only after
this commit does the manager send the stop write. An exact successful response
allows `complete_stop_replacement` to mark the local stop `stopped`. An
unactivated proposal becomes abandoned; an activated proposal retains its native
retirement history. A wrong target, role, scope or operation UUID cannot confirm it.

`replacement_stops` is optional in older journals, bounded at eight entries and
strictly validated on restore. Stops retain their own quarantine and exact IDs;
they are never pruned. Additional stops before native activation must share the
same original anchor. Old stop retries after retirement return their retained
local result without touching the new provider. A new generation in a fresh
profile must obtain its own service receipt; another generation's local intent
is never copied into it.

Client, service and Wasm builds must match. Older journals without the optional
stop field still load in this build. Reading a new stop-bearing journal with an
older strict module, mixed-version tabs and downgrade rollout remain unqualified.

The UI exposes a fresh unchecked stop confirmation for a stale pending or
already activated proposal.
The newly registered device can separately inspect and stop the previously
approved public replacement code. The original/failed IDs and old fingerprints
are displayed independently of the current device's fingerprint. After stopping,
both endpoints independently review the latest peer key and approve a new code.
An admitted stop grants none of this new consent. A unilateral or malformed code
fails preflight without leaving a frozen local stop intent.

The new replacement's `restart_from` names the last witnessed stop. On the changed
endpoint, the signed original-membership proof is scoped natively to the original
group and first retained failed group. It does not change enrollment ancestry or
make the old key live. After fresh bilateral consent and current bindings, a
single journal transaction replaces the original group with that first opaque
reservation, restarts through every retained stopped target and reserves only the
final fresh group. All original/failed group fences, checkpoint, journal phases
and final KeyPackage commit together. Intermediate groups produce no native
admission wire on that endpoint.

The unchanged device retains every stop it observed. A later fresh device starts
with its own selected original/failed targets; it does not inherit the previous
device's private checkpoint or old message history. Server-side stopped targets
remain blocked for all profiles. The shared eight-retirement limit counts each
stopped group as well as ordinary replacement/rejoin retirements. Preparation
rejects an over-limit proposal before publishing new HTTP consent. Same-key rejoin
after recovery uses that same budget.

`check_replacement_origin` is a read-only native guard: an existing native group
must still be the exact original two-member group; a fresh device must have no
reserved group. A different native group, a forming group or an unjoined
reservation is explicitly rejected by that guard. Current self binding remains
required. Final replacement separately validates actual original roster keys and
current independent pins. The activated-target path uses the distinct native
guard below and does not weaken this original-group check.

Lost responses, substituted receipts and aborted local writes retain the frozen
saved UUID. Reload and synchronization retry exactly that request. A Vault lock
at the committed intent witness clears the UI synchronously and sends no late stop
write; unlock reconciles the same saved intent. Failed activation leaves the
current provider and pending stop fences intact for atomic retry.

## Recovering an already activated replacement

For O-to-X already activated locally, O remains natively retired. The managed
invitation must still be exactly X (including a recorded admission failure with
no ordinary close intent). The caller must be the unchanged original endpoint,
and the journal must retain the exact active
O-to-X replacement. A separate read-only `check_activated_replacement_origin`
requires that native O fence, the exact X reservation, current self binding and
an independently reviewed different current peer key. An existing native group
must be active, exactly X, and contain either only the unchanged own leaf or
that leaf plus the exact old peer leaf from X in the same device slot and an
older generation. Unrelated, retired or inactive targets and mismatched own or
peer leaves cannot pass. The read neither clears provider state nor writes wire.

The first stop records optional `native_origin: true`. Restore requires the
exact active replacement, unchanged original endpoint and managed X; this flag cannot coexist with an ordinary
close link or appear after another pending stop. A retired flagged stop must
link to a committed active recovery replacement. Older journals without this
field remain readable; older modules, downgrade and mixed-version use remain
unqualified. Ordinary-close/deferred chains from an already activated target are
still outside this path and cannot be skipped.

After X completes, the endpoint that changed its own key in O-to-X can instead
handle the other endpoint's next key update through the ordinary X-to-Y flow.
It must not use the original O anchor: both endpoints would then have changed
relative to O. UI selection, stop-intent creation and restore enforce the
unchanged-original-endpoint restriction for `native_origin`. A denied old-anchor
stop writes no service receipt or frozen intent and leaves the current-group
replacement path available. This preserves alternating sequential key updates;
simultaneous changes before the first replacement completes remain unqualified.

Fresh bilateral O-to-Y approval calls `restart_activated_replacement` in the
same witnessed transaction as the new invitation and final KeyPackage. Native
code repeats the origin check, retains O's existing fence and retires X exactly
once. The forming group's old pending Commit/Welcome and queued text stay in
the stop's quarantine. If another admitted Y is stopped before activation, the
managed/native origin remains X; final recovery retires X and every additional
observed target without constructing an intermediate group. A failed IndexedDB
write restores the actual X provider and exact pending stop records for retry.

The shared budget counts unique retired/reserved group IDs across active
replacement history, completed rejoins and retained stops. The original O fence
is counted once even though two active replacement receipts share that anchor.
Five later ordinary rejoins after O/X/Y retirement fill the eight native slots;
the next approval fails before HTTP consent. No receipt or native fence is
pruned. Pending text from both O and X is shown as isolated and never replayed
into the final conversation.

## Bridging an existing ordinary recovery

The older admission-recovery flow can already have recorded X as its managed
invitation while preserving the native O group. Once B3 registers, an ordinary
same-key X-to-R rejoin cannot admit the new key. The client now connects this
specific metadata-only state to the stop operation above.

The original ordinary close must first reach `closed` using its saved operation
UUID and reason. A lost reply or aborted completion is retried through the
existing stop-confirmation control, even after the peer key is superseded. A new
stop cannot replace or infer that acknowledgment. The new stop intent has its own
UUID and an optional `recovery_id` naming the exact retained ordinary close UUID.

The link requires the same abandoned O-to-X replacement and exact X offer.
A single closed root with no successor retains the earlier `recovery_id` format.
For a deferred chain, optional `recovery_chain` contains every ordinary close UUID
in order, including that root. Every target must be `closed` with reason
`cancel_invitation`; each parent must retain its exact failed successor and the
immediately following child must link back to it. The final child must have no
pending successor. Missing, substituted, duplicate, reordered or unconfirmed
closes cannot link to a stop. Restore validates the entire retained chain.

A pending same-key proposal first uses the existing explicit veto. An unpublished
or unilateral proposal becomes an immutable cancellation tombstone, even after
the peer key is revoked. A bilateral proposal returns `admitted`, which requires
a separate unchecked confirmation to close that exact target. Its saved close
UUID must be acknowledged before the root stop can begin. An admitted veto may
remain in an intermediate parent's history only when it names the exact closed
child; no pending veto is allowed. Cancelled proposal IDs remain unusable.

Exact native origin checking still requires the original completed O group.
An active native successor, forming group or unjoined reservation cannot use
this bridge. The unchanged current endpoint must retain its own original native
group and ordinary close records. A newer generation cannot inherit those close
receipts or use a superseded scope's authority.

Beginning the stop quarantines the retained O outbox. The managed invitation
continues to identify the last recovery-required target until fresh bilateral
approval commits native retirement and final Y preparation atomically. For a
chain X-to-R1-to-R2, O, X, R1 and R2 all retire in that one transaction. Neither managed nor
native O is reopened. Stop retries, aborted activation and reload preserve this
state. Restore validates the exact root link and, for a retired linked stop, its
committed replacement/retirement chain.

If another key registers after Y is admitted but before local activation, another
explicit O-to-Y stop can share the already witnessed root link. The managed
metadata still names the last ordinary recovery target, each stopped target retains its own receipt and the final
activation retires every observed target atomically. This does not permit
skipping an ordinary same-key successor recorded under the recovery root.

Once its linked stop is retired, that ordinary recovery no longer freezes later
work. Its close receipt, phase, inbox IDs and cancellation
tombstones remain unchanged. The root's diagnostic abandoned-message list retains
the old outbox in its stop quarantine. Deferred children report no local abandoned
wire, since this endpoint never activated them; they never refer to the fresh
outbox. This also holds after later ordinary rejoins. Every actual original,
stopped and deferred group consumes one shared retirement slot. The retained close
metadata adds no duplicate native retirement; exceeding eight slots rejects fresh
consent before HTTP. Retired chain members cannot be reopened or mutated by a new
rejoin/cancellation command. Reusing an operation UUID under another offer cannot
make that unrelated recovery inherit a retired stop. The newly registered
profile obtains a separate stop receipt and receives no old private state.

## Local evidence

Twelve real workerd/D1 cases cover latest-generation stopping; unchanged-endpoint
stopping; fresh bilateral agreement; independent further-generation receipts;
revoked peers and stale caller denial; wrong owner/device/descriptor/body/Origin;
absent and unilateral proposals; failed writes and lost committed replies;
all five SSO predicates before the batch and after commit; authority mutations
inside the transaction; final-approval races; retained opaque invitation packets;
the 32-receipt quota using actual repeated registration through generation 34;
and read-only preflight with exact descriptors and current authority.

These are service tests: the fixture completes the original server-side admission
metadata directly and uses opaque wire bytes for transport-denial assertions.
They do not claim an actual post-admission Wasm recovery or real text journey.

Two additional native cases separately prove read-only origin checks, rejection
of forming/reserved/other groups and revoked self, and latest-key replacement
through multiple stopped IDs with real final text, old-wire denial and restored
retirement fences.

Five browser journeys use the actual Wasm module, Owner Vault controller,
encrypted IndexedDB and authenticated HTTP witness:

- Independent explicit stops, fresh key/code approval, real text, retained old
  pending-text isolation and reload on both endpoints; an old stop retry cannot
  reset the active conversation.
- Lost committed stop responses, real begin/complete write aborts, a substituted
  receipt and failed activation retain the same intent without early new wire.
- Another key update after a second admitted successor retains every locally
  observed stopped target and emits only final native admission wire.
- Vault lock at the committed stop-intent witness clears the screen, sends no
  stop write and reconciles the same saved UUID after unlock.
- Proposal veto releases only the unused historical marker; reversed inviter
  roles still work. Six subsequent same-key rejoins exhaust the remaining shared
  retirement slots and the next consent is denied before HTTP. A substituted
  stop code and an advanced target whose peer key is still current add no stop
  write.

The stopped screen passes Axe and a 390-pixel overflow check; its Chromium capture
is visually reviewed. Synthetic PRF/issuers remain qualification fixtures, not
physical-device Passkey or production evidence.

Four further browser journeys cover the existing ordinary recovery bridge and
the shared pending-stop guard:

- Exact retained close receipt, cancellation tombstones and quarantine survive
  a lost stop reply, actual begin/complete IndexedDB aborts, aborted activation,
  another admitted key update, reload, final current-key text and a later
  ordinary rejoin. Retired IDs and cancelled proposals remain unusable.
- An original close with a lost reply and aborted completion must first finish
  under its saved UUID. The new linked stop uses a distinct UUID, followed by
  separate bilateral approval and real text delivery.
- Even when both old endpoints remain current and the stop write never reached
  the service, a witnessed stop intent blocks old saved-consent synchronization
  before channel HTTP and rejects direct consent/activation commands locally.
  Confirming the stop retries its original UUID without native admission wire.
- A pending same-key successor cannot be skipped by stopping its changed-key
  root. After explicit confirmation of its deferred close, the exact retained
  chain can now link to a distinct root stop; wire stays frozen until fresh consent.

Three further journeys per browser cover unpublished and unilateral proposal veto
after peer rotation, and a repeated bilateral chain with its own exact closes. They exercise
lost close/veto/stop replies, actual IndexedDB aborts, lock at the committed intent
witness, another generation after admission, final real text and reload. Actual
native calls reject all five retired original/intermediate group IDs. Three more
same-key rejoins exhaust the remaining eight-slot budget and the next approval is
denied before HTTP. The UI lists all confirmed targets, passes Axe and 390-pixel
overflow checks, and never copies old private history into the new profile.

Four additional native cases exercise exact activated origins for an unjoined
reservation, a forming group, a pending invitation commit and a joined pair.
They verify read-only rejection of wrong anchors, targets and fingerprints,
failed/replayed retirement without checkpoint mutation, restored native fences,
old ciphertext denial, actual fresh text and the eight-retirement limit.

Four further browser journeys per engine cover the activated target in unjoined,
forming/pending-commit and joined states. They use actual Wasm, Owner Vault,
encrypted IndexedDB, authenticated witness and workerd/D1. The forming case first
records an actual peer close and admission failure, then exercises an aborted stop-intent write,
Vault lock at the committed witness, no late stop write and a substituted reply.
Lost stop responses and aborted completion retain the same UUID. Every case
aborts final native activation, reloads or records another admitted stop, and
then separately approves the final current-key conversation. Native origin modes,
exact original quarantine metadata, pending admission-wire quarantine, old-text
isolation, old-consent denial before channel HTTP, native retired-ID rejection and
real fresh text are asserted. The joined case registers another generation before
final activation and exhausts the shared budget through five ordinary rejoins;
the next consent is refused before HTTP. The stopped UI has Axe and 390-pixel
overflow checks plus a Chromium capture for visual review. The fourth journey
switches the other endpoint's key after the first replacement completes, rejects
an old-anchor stop before its service write, and uses the current completed group
as the next original. Fresh bilateral text, queued-text isolation and restored
native fences remain asserted.

Twenty-three focused structural cases cover exact close order, missing/duplicate
links, unconfirmed/activated children, wrong descriptors/endpoints, unresolved
vetoes, unrelated UUID reuse, later unrelated recovery and the older single-root
journal format.

The browser HTTP relay now materializes each actual workerd response before
discarding a lost reply or pausing delivery at the head witness. Lock tests still
pause after the server commits and before the browser receives the response.
This removes a fixture stream-reading race after browser cancellation and drains
discarded replies; it does not substitute a receipt or bypass service authority.

```sh
node scripts/build-messaging-qualification.ts
node --test --test-concurrency=1 design/probes/mls/server.test.ts design/probes/mls/*.server.test.ts
cargo clippy --locked -p mikaki-worker --target wasm32-unknown-unknown --features messaging-qualification --lib -- -D warnings
```

Earlier admitted-successor slice, before the ordinary-root bridge, recorded
locally on 2026-10-20: the complete 25-file Chromium/Firefox/WebKit run
passed all 292 Node cases with zero failures, cancellations or skips (about
32 minutes). This includes the twelve service cases and fifteen browser journeys
plus their three parent cases for this slice. The local run used
`MIKAKI_MLS_TEST_TIMEOUT_MULTIPLIER=4`; protocol expiry, device clocks and
assertions were unchanged. Intended-device performance and the default remote
CI runtime budget remain unqualified.

That earlier slice also passed all 45 standalone Rust cases (36 binding and nine lifecycle). The
qualification Worker and actual optimized browser module built successfully.
Native/Wasm and qualification-Worker Clippy passed with warnings denied. Strict
TypeScript, Prettier, Rust formatting, documentation links and whitespace checks
passed. The CI definition now lists all 29 Node test files and gives the job 60 minutes
for setup/build plus the expanded regression; per-test deadlines remain unchanged.
The 390-pixel Chromium capture was visually inspected and Axe/overflow checks
passed. Remote CI, physical-device ceremonies and production activation remain
unperformed.

Before deferred-chain support, the ordinary-root bridge's targeted Chromium/Firefox/WebKit run on
2026-10-20 passed all 96 Node cases: 78 browser journeys and 18 parent cases across
six affected browser files. There were zero failures, cancellations or skips;
runtime was about 20.5 minutes. This includes all twelve new journeys and their
three parent cases. The stopped screen passed Axe and the 390-pixel overflow
check in each browser; its Chromium capture was visually reviewed. Strict
TypeScript, Prettier, documentation links, workflow YAML and task-file whitespace
checks passed. At that stage all 26 Node test files were listed exactly once in CI.

Exploratory runs exposed an existing five-second UI-idle assertion failure and,
separately, a paused-response stream race in the HTTP fixture. The isolated retry
and final regression passed after the relay correction, with no changes to UI
assertion deadlines, protocol expiry or device clocks. The local outer test
deadline multiplier remained four. This is targeted regression; the then-current full
26-file suite, remote CI, intended-device performance and production activation
were not qualified by this run.

```sh
MIKAKI_MLS_BROWSERS=chromium,firefox,webkit \
MIKAKI_MLS_TEST_TIMEOUT_MULTIPLIER=4 \
node --test --test-reporter=tap --test-concurrency=1 \
  design/probes/mls/admission-recovery.browser.test.ts \
  design/probes/mls/rejoin-recovery.browser.test.ts \
  design/probes/mls/rejoin-cancellation.browser.test.ts \
  design/probes/mls/generation-negotiation.browser.test.ts \
  design/probes/mls/replacement-stop.browser.test.ts \
  design/probes/mls/replacement-stop-recovery.browser.test.ts
```

For deferred-chain recovery, the final targeted run on 2026-10-20 passed all 86
Node cases: 51 browser journeys and 12 parent cases across four browser files in
Chromium/Firefox/WebKit, plus 23 structural cases. There were zero failures,
cancellations or skips; runtime was about 19.7 minutes. This includes all nine new
browser journeys. They use the actual Wasm, Owner Vault, encrypted IndexedDB,
authenticated head witness and workerd/D1 service. Every recorded intermediate
close survives the final atomic retirement, reload and later ordinary rejoin.

The stopped chain screen passed Axe and the 390-pixel overflow check in all three
browsers; its Chromium capture was visually reviewed. Strict TypeScript,
Prettier, documentation links, workflow YAML and task-file whitespace passed.
At that stage, all 28 Node test files were listed exactly once in CI. The job permits 60
minutes for setup/build and the expanded regression; per-test defaults are
unchanged. The local outer deadline multiplier was four; protocol expiry,
device clocks and UI assertions were unchanged. The complete 28-file suite,
remote CI, production activation and physical-device qualification remain open.

```sh
MIKAKI_MLS_BROWSERS=chromium,firefox,webkit \
MIKAKI_MLS_TEST_TIMEOUT_MULTIPLIER=4 \
node --test --test-reporter=tap --test-concurrency=1 \
  design/probes/mls/replacement-stop-chain.test.ts \
  design/probes/mls/replacement-stop-chain.browser.test.ts \
  design/probes/mls/replacement-stop-recovery.browser.test.ts \
  design/probes/mls/replacement-stop.browser.test.ts \
  design/probes/mls/rejoin-recovery.browser.test.ts
```

For activated-target recovery, the broad local run on 2026-10-20 passed all 98
Node cases with zero failures, cancellations or skips in about 20.1 minutes:
60 browser journeys and 15 parent cases across five browser files in
Chromium/Firefox/WebKit, plus 23 structural cases. This includes the existing
ordinary/deferred recovery and stop regressions.

The final unchanged-original-endpoint restriction was then qualified by a focused
15-case run in all three browsers (four journeys and one parent per browser),
with zero failures, cancellations or skips in about 4.9 minutes. It repeats the
three native-origin journeys with the final role checks and adds alternating
sequential endpoint key updates, including denial of the wrong old-anchor stop
before its service write. Together these runs cover 101 distinct Node cases:
86 unchanged regression cases and the final 15-case activated-target slice.
The latter includes actual stopped-state restore and failed activation under the
new `native_origin` role constraint.

All 49 standalone Rust cases passed (40 bindings and nine lifecycle), including
four new activated-origin cases. The actual optimized Wasm was rebuilt:
1,748,258 raw bytes / 679,284 gzip estimate. Native/Wasm Clippy with warnings
denied, Rust formatting, strict TypeScript, probe Prettier, documentation links,
workflow YAML, all 29 CI test-file entries and task-file whitespace passed. The
current service source was unchanged and the browser runs used its existing
workerd qualification build. The final stopped-screen capture was visually
reviewed; the three-engine journeys assert Axe and 390-pixel overflow checks.

Both final runs used `MIKAKI_MLS_TEST_TIMEOUT_MULTIPLIER=4`; protocol expiry,
device clocks and UI assertions were unchanged. The full 29-file suite, remote
CI, product hosting, production activation and physical-device qualification
remain open. Recovery from a later failed native same-key successor or a retained
local ordinary-close chain of an activated replacement remains a separate gate.

```sh
MIKAKI_MLS_BROWSERS=chromium,firefox,webkit \
MIKAKI_MLS_TEST_TIMEOUT_MULTIPLIER=4 \
node --test --test-reporter=tap --test-concurrency=1 \
  design/probes/mls/replacement-stop-chain.test.ts \
  design/probes/mls/replacement-stop-chain.browser.test.ts \
  design/probes/mls/replacement-stop-recovery.browser.test.ts \
  design/probes/mls/replacement-stop.browser.test.ts \
  design/probes/mls/rejoin-recovery.browser.test.ts \
  design/probes/mls/replacement-stop-advanced.browser.test.ts

# Final focused follow-up after restricting the activated-origin role.
MIKAKI_MLS_BROWSERS=chromium,firefox,webkit \
MIKAKI_MLS_TEST_TIMEOUT_MULTIPLIER=4 \
node --test --test-reporter=tap --test-concurrency=1 \
  design/probes/mls/replacement-stop-advanced.browser.test.ts
```
