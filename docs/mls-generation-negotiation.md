# Repeated device generations during pending negotiation

**Status, 2026-10-20:** local qualification supports repeated updates of one
endpoint's registered key before bilateral successor consent. The unchanged
endpoint explicitly vetoes stale proposals, independently confirms the latest
fingerprint and approves a fresh shared code. The latest device can prove its
relationship to the original conversation's historical leaf even when its
immediate enrollment predecessor is a different generation.

This covers pending changed-key proposals and a pending same-key rejoin from an
already completed original conversation. A further key change after bilateral
admission, a failed/uncompleted predecessor, simultaneous changes at both
endpoints, device loss and capacity repair remain separate gates. Product hosting,
production routing/schema and physical-device qualification remain open.

The [witnessed admitted-successor stop flow](mls-replacement-stop.md) now connects
the current same-slot head to explicit stop, quarantine, atomic deferred retirement
and fresh latest-key text while the unchanged endpoint retains its original native
group. The separate stop flow also covers the exact activated failed replacement
(unjoined, forming or joined). Later native same-key recovery successors and
already-started ordinary recovery from an activated replacement remain open; the evidence
below still covers the pre-bilateral negotiation journey.

## Original membership and enrollment ancestry

For an original conversation between A1 and B1, suppose B2 registers and A1
approves candidate X. Before B2 approves, B3 registers; another update may produce
B4 before agreement. The registry correctly rejects B2/B3's obsolete scopes. A1
can veto X using its own current authority and the retained historical registry,
then review B4 and separately approve a fresh candidate Y.

Previously, B4's native checkpoint retained only its immediate enrollment
predecessor B3. The server already recognized the same account/device slot at a
higher generation, but native replacement required the original B1 fingerprint
to equal that immediate predecessor. It could not complete Y.

The latest device now obtains a fresh issuer-signed **revoked** binding for B1,
verifies its signature with the configured trust anchors, and compares its exact
fingerprint to the selected original conversation. Its issuer/account/device slot
must equal the current device's slot and its generation must be lower. The old
key is historical identity metadata; it never becomes a current lease or pin.

The checkpoint stores this public `group_previous` marker with the exact old and
new group IDs, separately from `own_previous`. Enrollment still requires exactly
the next generation and its exact signed immediate predecessor/revision. Preparing
a historical marker does not change enrollment recovery or current key trust.
Generic group creation/joining is blocked while the marker awaits activation.

After fresh bilateral consent, native replacement consumes only the marker for
the selected original and new groups. It preserves the current signing key,
retires the original group and reserves the fresh group for normal
[KeyPackage/Commit/Welcome admission](mls-device-invitations.md). The unchanged
endpoint checks the actual original two-member roster against its independently
accepted current peer key. Intermediate cancelled candidates produce no native
groups or invitation wire.

An aborted local transaction restores the previous native checkpoint and all
metadata. Restore validates the historical slot/generation, fingerprint/revision,
group lengths, retirement fences and absence of another active group/reservation.
Older checkpoints without the optional marker still restore. Current device/peer
revocation, untrusted or expired tokens, another device slot and a substituted
fingerprint cannot authorize replacement.
The client, service and Wasm qualification builds must match. Mixed-version tabs
and downgrade/production rollback qualification remain open; an unavailable
historical-proof route leaves the saved proposal frozen without new consent.

## Read-only historical membership proof

`POST /messaging/channels/:id/replace/predecessor` accepts the existing exact
approval shape `{previous,next,scope,operation_id}`, at most 3,000 bytes. It returns
the exact predecessor ID, successor channel/inviter, caller scope and saved
approval UUID, plus `binding` for this caller's original historical leaf.

The service requires:

- The exact previously completed conversation and same historical device slots.
- Exactly one changed endpoint, with higher generation and different key; the
  caller must own that changed current scope, not the unchanged peer's scope.
- Both current endpoint scopes and live Owner SSO, including active account,
  matching security epoch, active credential, unrevoked and unexpired session.
- The historical fingerprint/scope from the selected original conversation and
  the same account/device UUID as the changed current device.

Fresh-primary reads bracket asynchronous issuer signing. If own or peer authority
changes, the service discards the signed result. All five live SSO predicates are
rechecked after signing. The historical binding is explicitly `revoked`, expires
after 300 seconds and contains public identity/key metadata only. This endpoint
adds no channel, closure, consent, approval receipt, packet or private-state copy.

The native verifier checks the token while fresh, then retains its historical
fact in the encrypted checkpoint. That retained fact grants no ongoing transport
authority: fresh current bindings and exact server consent remain necessary for
activation and wire publication. Account/issuer compromise remains outside this
account-authenticated replacement guarantee.

## Durable approval and explicit UI

The existing witnessed `prepare_replacement` saves the exact proposal and stable
approval UUID first. On the changed endpoint, `attest_replacement_predecessor`
then verifies the historical binding natively and atomically records the marker
and `predecessor_confirmed: true` in the encrypted journal and witness. Only then
can that endpoint publish its successor consent. Later synchronization reuses the
saved approval and marker; it does not repeatedly sign or rewrite ancestry.

A lost proof response or actual IndexedDB abort leaves the proposal frozen with
no endpoint approval or KeyPackage released. A Vault lock invalidates the handle
and clears the UI; a committed witness can reconcile the same marker after
unlock. Failed activation retains the marker and exact approval UUID for retry.
Confirmed local or peer veto releases only the exact unused historical marker in
the same journal transaction as cancellation. An admitted result retains it for
explicit recovery. Enrollment ancestry, current pins, signing identity and
retirement fences remain intact, and an active group/reservation cannot be cleared.

When a peer's accepted key differs from a pending proposal, the screen identifies
that stale proposal. The user explicitly vetoes it, checks the latest fingerprint
and approves a new code with a fresh unchecked confirmation. An old same-key
rejoin must be cancelled before a changed-key code can be created. Once cancelled,
the screen directs the user to the checked new key instead of generating another
code with the obsolete same-key pair.

Original pending text stays isolated on the unchanged device; it is never
automatically re-encrypted or forwarded. The newly enrolled device starts without
old history. Superseded scopes cannot send or synchronize using old authority.
Existing generation, approval, journal/state and retirement limits still apply;
vetoes and fences are not pruned to make room. Only the final activation consumes
a native retirement slot, rather than each unjoined intermediate generation.

## Local evidence

Four native cases cover third-generation historical membership with real new
MLS text and old-wire denial, exact target groups across restore, unchanged
immediate enrollment ancestry, malformed/untrusted/active/expired/other-slot
bindings, legacy checkpoints, current revocation and exact unused-marker veto.

Four real workerd/D1 cases cover a signed historical leaf after two registrations,
absence of unintended writes, exact descriptors/body/Origin/owner/scope, both
current endpoints, incomplete parents and post-signing SSO loss.

Four browser journeys use actual Wasm, Owner Vault/controller, encrypted IndexedDB
and the authenticated HTTP witness:

- Two further key updates during pending proposals, explicit vetoes and fresh
  independent pin/code approval, fourth-generation real text, retained original
  quarantine, no stale invitation wire, obsolete-scope rejection and reload.
- A pending same-key rejoin interrupted by two registered generations, explicit
  veto under the original parent, fresh changed-key agreement and actual text.
- A changed endpoint vetoing its own approved proposal, observing a peer veto,
  releasing only unused native markers, restoring and selecting a fresh peer
  code with real text. An old veto retry cannot reset the new active conversation.
- Lost historical proof, an actual attestation write abort, lock at its committed
  witness, failed activation and reload with the same approval UUID and exact
  proof request. No early endpoint consent, KeyPackage or late plaintext display.

The stale-proposal screen passes Axe and a 390-pixel overflow check; the Chromium
capture was visually inspected. Synthetic PRF and issuers are used; real-device
Passkey migration and production activation are not implied.

```sh
node scripts/build-messaging-qualification.ts
wasm-pack build design/probes/mls --target web --release --out-dir pkg-web -- --locked
cargo test --locked --manifest-path design/probes/mls/Cargo.toml
MIKAKI_MLS_BROWSERS=chromium,firefox,webkit node --test --test-concurrency=1 design/probes/mls/generation-negotiation.server.test.ts design/probes/mls/generation-negotiation.browser.test.ts
```

Recorded locally on 2026-10-20: after fixing unused-marker release and adding the
changed-endpoint/peer-veto regression, the complete 23-file Chromium/Firefox/WebKit
run passed all 262 Node cases with zero failures, cancellations or skips (about
22 minutes). This slice contributes 12 browser journeys, three parent cases and
four service cases. The run used `MIKAKI_MLS_TEST_TIMEOUT_MULTIPLIER=4`; protocol
expiry, device clocks and assertions remain unchanged. Intended-device performance
and the default remote CI runtime budget remain unqualified.

All 43 standalone Rust cases passed (34 binding and nine lifecycle). Native/Wasm
and qualification-Worker Clippy passed with warnings denied. Strict TypeScript,
Prettier, Rust formatting, documentation links and whitespace checks passed. The
CI file includes all 23 Node test files. The 390-pixel Chromium capture was visually
inspected and its Axe/overflow checks passed. Remote CI, physical-device ceremonies
and production activation remain unperformed.
