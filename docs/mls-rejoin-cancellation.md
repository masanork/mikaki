# Same-key rejoin proposal cancellation and reselection

**Status, 2026-10-19:** local qualification supports an explicit veto of a pending
same-key rejoin, including a proposal whose approval request never arrived. Both
owners can then independently approve one shared proposal under the original
closed predecessor. This extends [failed-rejoin recovery](mls-rejoin-recovery.md);
product hosting, production schema/deployment and physical devices remain open.

## Veto before bilateral consent

Suppose a stopped conversation is O. One endpoint approves candidate X, while its
peer approves Y. Previously the encrypted journal fixed each endpoint's `next`
and neither could select the other's proposal. Stopping X and advancing recovery
to X would leave the endpoints anchored to different predecessors.

The new explicit cancellation keeps O as the predecessor. An unchecked screen
confirmation authorizes the veto of X. Only a verified, durably recorded
`cancelled` receipt clears the local `next`. The user can then import Y, inspect
its exact code and fingerprints, and separately confirm fresh consent. No prior
checkbox approval carries over to the newly selected code.

The service permanently blocks X. If X was never published, cancellation creates
a blocked child with zero consents. A delayed approval cannot resurrect it. Its
ID and group cannot be used again in a local rejoin or changed-key proposal.
Cancellation neither opens O nor resets the native provider, creates a KeyPackage,
changes a key pin or transmits retained ciphertext. Original pending text stays
isolated; it is never automatically re-encrypted into the selected conversation.

If bilateral consent already committed, the immutable outcome is `admitted`.
Cancellation does not block the child or claim it was cancelled. The screen offers
synchronization to continue joining, or a separate unchecked confirmation to
[stop that admitted rejoin](mls-rejoin-recovery.md) and approve a fresh conversation.
An admitted outcome stays admitted even after a later explicit close.

## Atomic service contract

`POST /messaging/channels/:id/rejoin/cancel` accepts exactly
`{previous,next,scope,operation_id}`, at most 2,600 bytes. Both offers have the same
exact endpoints/fingerprints and different channel IDs and group IDs. The reply
contains `predecessor_id`, exact `channel` and `inviter_scope`, caller `scope`,
the same operation UUID and `outcome: cancelled | admitted`.

This protocol already identifies approval by the immutable successor descriptor.
Cancellation therefore does not introduce a second approval UUID or change the
existing `/rejoin` request. The veto receipt binds the caller, exact descriptor,
predecessor, role, operation UUID and canonical intent hash. Another UUID or a
modified intent cannot replace a retained receipt.

Each write and reconciliation requires the exact blocked predecessor, this
endpoint's own original close receipt, its current registered device/fingerprint
and live Owner SSO. Account activation, security epoch, credential activation,
session revocation and expiry are checked inside the SQL transaction. The peer
may have been revoked; it cannot prevent a still-current caller from vetoing an
old pending proposal. This exception adds no consent and grants no admission.
New approval still requires both current devices.

One guarded D1 batch creates an absent candidate, records its immutable outcome
and blocks it only if both consents have not committed. Cancellation and final
approval serialize: either cancellation wins and subsequent approval fails, or
bilateral approval wins and cancellation returns `admitted`. A failure rolls back
the entire batch. A fresh-primary exact receipt read reconciles a committed batch
whose reply was lost. This uses D1's documented
[transactional batch and primary session behavior](https://developers.cloudflare.com/d1/worker-api/d1-database/).

The existing metadata-only `/rejoin/status` also returns `cancelled` when an exact
child has a veto tombstone. A peer veto stops reapproval and produces the
`proposal_cancelled` foreground result. The user can explicitly confirm the local
veto and select another code. The failure-recovery API refuses to advance a vetoed
candidate into a new predecessor. Unrelated channel collisions never look unpublished.
Status and cancellation expose no packet bytes, private state or peer operation UUID.

## Witnessed local decisions

`begin_cancel_rejoin` records the exact candidate, stable cancellation UUID and
`pending` outcome in the encrypted journal and monotonic witness before HTTP.
Until completion, approval, native activation and linked failure recovery are
refused. Reload and either the retry control or synchronization reuse that saved
request rather than generating another cancellation identity.

`finish_cancel_rejoin` verifies the exact receipt and atomically records its final
outcome. It clears `next` only for `cancelled`, retaining all veto metadata. An
IndexedDB abort leaves the original pending state and retry identity intact.
Locking the Vault invalidates the operation before later HTTP or display can be
released, even when the witness already committed the local intent.

Optional cancellation metadata preserves compatibility with existing journals.
Strict restore validation checks exact offers, unique IDs/operations, terminal
outcomes, the relationship to the currently selected proposal and consistency
with other recoveries/replacements. Vetoes are retained, never pruned to make room.
The local journal permits at most 32 cancellation attempts across its recovery
records; the service permits 32 retained receipts per Owner across devices.
Other operation/state quotas can stop work earlier. Capacity repair is a separate
gate. Vetoing an unjoined proposal consumes no native retirement slot.

The same selection rules work on a linked failed-rejoin recovery, including an
unapplied changed-key root. Original deferred links and native reservations stay
intact. Only fresh bilateral consent triggers the existing atomic retirement and
final invitation process.

## Local evidence

Seven real workerd/D1 cases cover unpublished tombstones and exact retries,
competing proposals, bilateral and concurrent final-approval outcomes, transactional
rollback/lost database replies, exact authority/body/origin checks, all five live
SSO predicates and retained quota overflow without an orphan child.

Four journeys per browser use the actual Wasm client, Owner Vault controller,
encrypted IndexedDB journal and authenticated HTTP witness:

- Conflicting X/Y proposals, unchecked veto and fresh Y consent, reversed inviter
  roles, real text delivery, isolated original text and retained veto after reload.
- An unpublished approval, actual IndexedDB aborts before intent and completion,
  a lost successful response, stable retry bodies and no cancelled invitation wire.
- Final approval winning, interrupted local receipt persistence, explicit admitted
  stop, veto/reselection within the linked recovery and fresh MLS text.
- Peer veto without reapproval, lock during the committed local witness, no late
  cancellation HTTP or visible history, and retry after unlock with the saved UUID.

The existing failed-rejoin journey also vetoes an alternative within a deferred
changed-key recovery before approving the final code. The unchecked veto screen
passes Axe and the 390-pixel overflow check; the Chromium capture was visually
inspected.

```sh
node scripts/build-messaging-qualification.ts
MIKAKI_MLS_BROWSERS=chromium,firefox,webkit node --test --test-concurrency=1 design/probes/mls/rejoin-cancellation.server.test.ts design/probes/mls/rejoin-cancellation.browser.test.ts
```

This qualification does not activate production routing or schema, run remote CI
or qualify real Passkeys/devices. [Further key updates before bilateral consent](mls-generation-negotiation.md)
now use historical membership and fresh approval. Further generation changes after bilateral admission,
device loss, capacity repair and compromised-account/issuer recovery remain open.

Recorded locally on 2026-10-19: the complete 21-file Chromium/Firefox/WebKit run
passed all 243 Node cases, with zero failures, cancellations or skips (about
19 minutes). The new slice contributes 12 browser journeys, three parent cases
and seven service cases. The seven service cases also passed after adding the
Owner quota index. This run used `MIKAKI_MLS_TEST_TIMEOUT_MULTIPLIER=4`; protocol
and lease expiry, assertions and device clocks remain unchanged. It does not
qualify intended-device performance or the default CI runtime budget.

All 39 existing standalone Rust cases passed. Native/Wasm and qualification-Worker
Clippy passed with warnings denied; strict TypeScript, Prettier, Rust formatting,
documentation links and whitespace checks passed. The local CI workflow includes
all 21 Node test files. Remote CI and production activation remain unperformed.
