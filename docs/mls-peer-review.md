# Explicit peer-device and key-change review

**Status, 2026-10-19:** the local foreground chat now supports initial peer-key
confirmation and explicit replacement review through the actual Vault-owned,
witnessed MLS journal. A signed code can be inspected without establishing trust.
Typed independent fingerprint confirmation is required before first use. Changed
keys, registry conflicts and revocation block sends and survive reload. This is
qualification-only; no product route, production schema or deployment is enabled.

## Contact codes and verification

`VaultMlsDevice.ownContact()` obtains the authenticated owner's signed binding,
refreshes only that exact own key in Rust and returns `{scope,binding}`. The screen
encodes this public data with a bounded `mikaki-device-v1:` prefix. A code is a
transport for a candidate, not proof of the human behind an account and not an
independent fingerprint confirmation. Its signed lease lasts at most five minutes;
refreshing it never replaces the signing key or allocates a new journal scope.

The client never interprets unverified JWT claims as identity display data.
`BoundMlsClient.inspect_peer` uses the independently configured issuer keys and
the existing strict binding profile to verify signature, issuer, audience, device
identity, key, revision, status and expiry. It rejects the owner's own account and,
after confirmation, another account/device slot. It returns only public verified
identity/fingerprint/revision/status/times. It does not confirm a pin, release a
KeyPackage, create a group or follow an embedded URL. No new directory lookup or
issuer-key discovery is added.

The contact's routing `scope` is outside the signed binding. It is public,
untrusted transport metadata, not an additional identity claim. Channel admission
still checks both exact scopes, current generations and signed-key fingerprints
against the service registry before wire publication. Altering a routing scope
cannot bypass those checks or change the separately confirmed fingerprint.

## Separate display and independent confirmation

`stagePeer(contact)` validates the candidate in Rust, records any observation
about an existing pin and saves one current review in the encrypted witnessed
journal. A review contains a new UUID, exact candidate code, verified public
metadata and observation. Observing an existing signed change/revocation/conflict
is a successful retained operation, not an exception that discards the denial.
Staging an unconfirmed active key records a candidate without creating a pin.

The screen displays the issuer, account ID, device ID, generation, registry
revision and full fingerprint. The independent-fingerprint input starts empty;
it is neither populated from the code nor replaced by a checkbox. Users must
compare through a separate contact path such as meeting or calling. A typed
value that differs from the candidate is rejected by the Rust verifier. Invitation
consent remains a separate explicit action after key confirmation.

`approvePeerReview(operationId, reviewId, previous, independentFingerprint)`
compares the exact persisted review UUID. First trust uses the `unconfirmed`
previous marker; replacement approval requires the retained previous fingerprint,
the independently entered new fingerprint and the existing higher-generation,
higher-revision/different-key rules. A different review staged by another tab
invalidates an uncommitted approval. Approval, updated trust pins and the operation
receipt commit in one encrypted witnessed transaction. Failed preparation cannot
publish a partial pin. An ambiguous result retains its exact operation/intent
for retry; a committed snapshot can reconcile that result after reload.

`chatSnapshot()` adds public `trust` and `peer_review` metadata from the native
engine. The snapshot exposes neither private checkpoints nor ciphertext/private
key material; the contact binding contains its public verification key.
The screen gates sends and invitation approval on the actual retained native pin
state and current group checks, not its own record of button clicks. Candidate
codes, confirmation inputs and pending operations are removed from the display
on the existing Owner lease/visibility/lock invalidation path; late completions
cannot restore them.

## Changed keys, conflict, expiry and revocation

The screen distinguishes an unconfirmed candidate, current pin, changed key,
registry conflict, expired lease and signed revocation. An expiry requires a
fresh signed lease; a current same-key lease can refresh an existing pin without
another independent confirmation. A changed key is displayed with the retained
old fingerprint and new verified fingerprint, and requires explicit typed review.
Same-revision contradictory registry contents do not expose a confirmation
override. Invalid signatures/expired candidates do not overwrite retained trust.

The native trust store also retains up to eight verified revocation tombstones
observed before first confirmation, without treating them as pins. A later active
declaration of that generation or reused key cannot silently become first trust,
including after checkpoint restoration. A genuinely new higher generation and
different key still requires independent confirmation. The bounded ledger fails
closed rather than pruning denials; capacity/recovery policy remains a product
gate. Existing confirmed-peer revocation and stale-observation fences remain.

Key approval and MLS membership are separate. Accepting a new pin does not make
the old leaf key valid, re-encrypt queued text, rewrite an old channel descriptor
or mark the old group usable. The screen keeps sends disabled and explains that
the new key still needs explicit group admission. The current same-key
[fresh-group rejoin](mls-device-recovery.md) intentionally requires identical
endpoint fingerprints and cannot be used to bypass that admission. The [changed-device-key admission](mls-device-replacement.md) now connects explicit
next-generation registration and bilateral approval to a fresh group through the
managed mailbox/UI workflow. Device-loss/Vault recovery and history migration
remain open.

Revocation is enforced when a verified notification is observed or a current
server check denies delivery. The screen does not implement public discovery,
push notifications or automatic signed peer-status retrieval. A cached lease is
not a promise of instant global revocation. Tests import the actual signed
revocation response through the same code-review boundary.

## Qualification

Four native cases cover verification without pinning, identity/slot restrictions,
changed-key display/acceptance with old group denial, conflict/revocation/expiry
states and retained unconfirmed revocation across restore. The existing lifecycle,
pinning, pending-wire, rejoin and adversarial suites remain required.

[`peer-review.browser.test.ts`](../design/probes/mls/peer-review.browser.test.ts)
adds four journeys per browser using real Wasm, Owner Vault/controller, encrypted
IndexedDB/Web Locks, authenticated HTTP witness and Rust/workerd/D1:

- Exchange own contact codes, reject a wrong independent fingerprint, reload a
  pending review, then confirm both keys, approve the invitation and decrypt text
  without the earlier fixture shortcut that pins peers directly.
- Replace a real registry generation, retain old pending ciphertext, reload the
  mandatory review, reject the old fingerprint, lose a successful approval reply,
  verify the old group remains blocked, then retain a signed revocation.
- Reject invalid signatures and expired codes without overwriting trust, then
  retain a same-revision signed registry conflict without an approval override.
- Stage a review in another unlocked tab, reject the stale screen's approval,
  abort an actual IndexedDB approval transaction, then lock during its witnessed
  retry and verify that no late fingerprint/code display is released.

The tests run axe and a narrow-screen overflow check on the initial review and
capture a Chromium screenshot for local visual inspection. Physical Passkeys,
assistive-technology/device qualification, production provisioning/routing,
further generation changes after bilateral admission, capacity repair and independent-instance
federation remain open. [Admission recovery](mls-admission-recovery.md) now covers
closed/expired changed-key admission and interrupted joining.
[Same-key rejoin recovery](mls-rejoin-recovery.md) covers pre-activation successor
closure, repeated stops and deferred changed-key roots. The [chat UI contract](mls-chat-ui.md) describes the surrounding
text/delivery/recovery behavior.
The [pending-rejoin veto](mls-rejoin-cancellation.md) and [repeated-generation
negotiation](mls-generation-negotiation.md) cover explicit selection before bilateral consent.

Recorded locally on 2026-10-19: all 34 standalone Rust cases passed (25 binding
and nine lifecycle), with native and Wasm Clippy warnings denied. The final
combined chat/review run passed all 30 Node cases across Chromium, Firefox and
WebKit (24 journeys and six parent cases). Strict TypeScript, Prettier, local
documentation links and whitespace checks passed. The CI workflow includes the
new review file; remote CI and production activation are not claimed.
