# Changed-device-key enrollment and bilateral admission

**Status, 2026-10-19:** the local qualification connects explicit replacement
registration, independent key review, bilateral channel approval and a fresh MLS
group to the actual Owner Vault, witnessed encrypted journal and authenticated
Rust/workerd/D1 service. One endpoint changes at a time. This remains a separate
build feature, local schema and entrypoint; no product route or production
migration/deployment is enabled.

## Registration preserves the old device boundary

`VaultMlsDevice.createReplacement(previousVerifiedDevice)` is an explicit action
on an empty local custody slot. Ordinary `create()` still rejects an existing
registry identity, and `open()` never creates a missing device. The replacement
must use the authenticated owner's same issuer/account/device UUID, exactly the
next generation, a different fresh signing key and new storage/key IDs. Existing
local custody cannot be overwritten by this API.

Before saving or publishing the new proof, Rust verifies the registry's signed
previous binding with configured trust anchors and compares its exact identity,
revision and independently supplied previous fingerprint. The encrypted initial
checkpoint retains only public predecessor metadata, together with the new
private state. The registration request uses the exact previous registry revision
and the existing challenge-bound possession proof, operation UUID and SSO checks.
The service retires the old registry scope; its journal/mail authority cannot
continue using that generation.

On resumption, Rust distinguishes a fresh lease for the exact old head from a
lease for this exact new public key. An existing old binding is not evidence that
the replacement has registered successfully. The same encrypted prepared key,
intent and scope survive page loss, renewed enrollment tickets and successful
reply loss. A different new head or inconsistent predecessor fails closed.
There is no private-state/history transfer, fallback identity creation or direct
state-key export. Browser tests reuse only a synthetic authenticator PRF for the
same credential; actual device/Passkey migration remains unqualified.

## Peer review and channel consent are separate

The unchanged endpoint first reviews and independently types the new fingerprint
through the [peer-key review flow](mls-peer-review.md). This does not authorize an
old MLS leaf or release old queued text. The new device independently confirms
the unchanged peer. Both then review one bounded public `mikaki-replace-v1:` code
containing exact previous and proposed invitation descriptors.

The screen shows the old conversation ID/retired fingerprint and the new
conversation ID/current fingerprints. An unchecked confirmation is required to
close the old conversation and approve the new one. A code supplies transport
metadata, not a trust root or independent fingerprint confirmation. The unchanged
endpoint can generate a fresh proposal only after the new peer pin is accepted.
A new device can inspect a received proposal only after confirming its peer.

`POST /messaging/channels/:newId/replace` accepts exact
`{previous,next,scope,operation_id}` with a 3,000-byte body limit. The service checks
historical device ownership and both current active registry scopes. Exactly one
endpoint must keep its scope/fingerprint; the other must be the same account and
device UUID with higher generation and a different key. A different device slot,
both changed endpoints, reused group, mismatched parent, revoked scope, unrelated
owner or changed SSO authority cannot authorize the transition. The parent must
have completed initial admission.

One D1 batch permanently blocks the parent, creates the exact successor, writes
an immutable per-owner/scope/operation/intent approval and sets only that owner's
consent. A final CHECK guard rolls back all writes if the exact authority/receipt
conditions fail. A fresh primary read reconciles successful database reply loss.
Generic invitation consent cannot supply missing replacement consent. The shared
successor rule admits at most one unblocked bilateral child, including competing
requests. An idempotent retry retains its approval UUID; a changed intent or
replacement operation is rejected. Existing account quotas still apply.

The first approval stops the old conversation. New membership starts only after
both owners approve the same exact successor and current signed leases refresh.
A failed request leaves the local prepared transition frozen for exact retry.
There is no automatic proposal substitution or return to the old conversation.
The [explicit proposal cancellation flow](mls-replacement-cancellation.md) now
permits a pre-bilateral veto, preserves tombstones and requires fresh consent
before choosing another proposal.

## Atomic local activation and retained history

Preparation saves the exact proposal and stable approval UUID in the witnessed
encrypted journal before HTTP. Pending transitions freeze ordinary send/update/
invitation work while permitting current key observations and the exact retry.
Lock/lease invalidation clears the screen and aborts subsequent authority/wire
work; late results cannot repaint plaintext or codes.

After bilateral server consent, native activation validates the old actual
two-member roster and the independently accepted higher-generation peer pin on
the unchanged endpoint. The new endpoint requires its retained signed own-key
predecessor or [verified historical membership](mls-generation-negotiation.md)
when the original leaf is older than the enrollment predecessor. This leaves
immediate enrollment ancestry unchanged. Each endpoint starts a fresh provider
while preserving its current signing key, retires the exact old group and
reserves only the approved new group. The normal witnessed
[KeyPackage/Commit/Welcome workflow](mls-device-invitations.md) performs admission.
An aborted local transaction cannot release its candidate KeyPackage.

The unchanged endpoint retains sent/received history. The replacement device
starts without old history. Old pending ciphertext is quarantined with public
ID/kind/digest metadata and is never re-encrypted or automatically forwarded.
Quarantine does not prove that an earlier send was never accepted remotely.
Old group/KeyPackage secrets cannot admit the new device, and the old device
cannot decrypt new-group messages. Checkpoint restoration retains group
retirement and exact reservation fences. This is logical provider replacement,
not physical erasure of retained encrypted backups or old plaintext history.

Replacement/rejoin activations share the native limit of eight retired groups;
the replacement intent ledger is also bounded at eight, including cancelled
proposals. Existing operation/state/
history/outbox quotas can stop work sooner. Tombstones are never pruned to make
a transition fit.

## Qualification and remaining gates

[Three native cases](../design/probes/mls/tests/bindings.rs) check exact signed
predecessor validation/resumption, restored reservation and real new-group text
with old-device/old-wire denial, missing predecessor, wrong roster and revocation.
[Six actual service cases](../design/probes/mls/replacement.server.test.ts) cover
bilateral exact consent, generic-consent denial, immutable operation, rollback,
lost committed database reply, mismatched parent/group/owner/device, both changed
endpoints, all five live SSO predicates, Origin, revocation and concurrent children.

[Three journeys per browser](../design/probes/mls/replacement.browser.test.ts) use
real Wasm, Owner Vault/controller, encrypted IndexedDB/Web Locks, authenticated
HTTP witness and the Rust service:

- Enroll a real next generation in separate empty custody, review both peer keys,
  require unchecked bilateral consent, preserve history on the unchanged device,
  quarantine old queued text, decrypt new text, reject the old device, then reload,
  close and rejoin again without losing the earlier closure/replacement fences.
- Resume interrupted enrollment after ticket expiry and lost successful proof
  response, lose the successful approval response, abort an
  actual activation transaction, reload with the same operation, lose a Welcome
  consumption response, then finish without double admission or proposal adoption.
- Lock during witnessed preparation and verify no late display or HTTP approval/
  wire publication; reopen and reconcile the same frozen prepared proposal.

[Admission recovery](mls-admission-recovery.md) now qualifies a peer closing an
admitted child before local activation, expiry and interrupted joining.
[Same-key rejoin recovery](mls-rejoin-recovery.md) now covers closure before local
restart, including a still-deferred replacement root. [Repeated-generation negotiation](mls-generation-negotiation.md)
now covers further key updates before bilateral consent. Further updates after
bilateral admission, in-place rotation, simultaneous
changes at both endpoints, adding another device slot, lost-credential/Vault
recovery, history migration, capacity repair, intended-device performance and
accessibility, issuer-key custody, product hosting and production rollout remain
open. Account-authenticated replacement is not protection against compromise of
the account or issuer. Independent-instance federation also remains open.

```sh
npm run build:policy
node scripts/build-messaging-qualification.ts
wasm-pack build design/probes/mls --target web --release --out-dir pkg-web -- --locked
cargo test --locked --manifest-path design/probes/mls/Cargo.toml
MIKAKI_MLS_BROWSERS=chromium,firefox,webkit node --test --test-concurrency=1 design/probes/mls/replacement.server.test.ts design/probes/mls/replacement.browser.test.ts
```

The [qualification CI](../.github/workflows/mls-probe.yml) includes both new files
alongside the complete lifecycle/trust/storage/service/custody/delivery/invitation/
recovery/chat/review regression. Remote CI and production activation are not
implied by the local harness.

Recorded locally on 2026-10-19: all 37 standalone Rust cases passed (28 binding
and nine lifecycle), with native/Wasm and qualification-Worker Clippy warnings
denied. Strict TypeScript, Prettier, Rust formatting, documentation links and
whitespace checks passed. Cargo audit found no vulnerabilities and retains the
existing transitive `proc-macro-error2` unmaintained warning.

The 13-file Chromium/Firefox/WebKit regression covers 163 Node cases. The Mac
entered clamshell sleep during the initial run; failures/cancellations were
confined to the storage and replacement browser files. The other eleven files
passed. Both affected files were then rerun across all three browsers with idle
sleep inhibited: all 39 cases passed with no failures or cancellations. These
are per-file results across the initial run and clean retry, including all nine
replacement journeys and their three parent cases. Intended-device and remote
CI qualification remain open.
