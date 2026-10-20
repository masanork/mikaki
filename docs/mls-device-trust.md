# MLS device identity and key continuity

**Status, 2026-10-19:** the isolated MLS implementation now verifies signed
account/device bindings, device-key possession, initial fingerprint confirmation,
key changes and revocation. Native and browser tests use synthetic accounts and
real signatures. No production enrollment endpoint, SSO/registry adapter, DID
resolver or chat UI is enabled by this work. A separate
[encrypted browser journal](mls-device-storage.md) now qualifies durable state
and retry behavior, with synthetic custody and an independent witness fixture.
The [feature-gated SSO/D1 service adapter](mls-device-service.md) additionally
qualifies session-bound enrollment, signed binding issuance, generation/revocation
and HTTP witness CAS against real workerd SQL, with synthetic owner sessions.
The [Vault custody manager](mls-device-custody.md) adds durable pre-enrollment,
fresh-page unlock and own-lease refresh without overwriting initial pins.
The [foreground peer-review UI](mls-peer-review.md) now verifies public contact
codes, requires independently typed fingerprints, retains changes/revocations
and keeps old MLS groups blocked after replacement-pin approval.

The implementation is [trust.rs](../design/probes/mls/src/trust.rs) and
[BoundMlsClient](../design/probes/mls/src/bound.rs), alongside the
[S1 lifecycle qualification](../design/probes/mls/README.md). It implements the
client authentication boundary described by [MLS Architecture section
4](https://www.rfc-editor.org/rfc/rfc9750.html#section-4), using a bounded
application-specific JWS profile rather than modifying MLS cryptography.

## Identity and initial trust

A device identity is the canonical JSON encoding of these fields, in order:

| Field | Meaning |
| --- | --- |
| `issuer` | Exact configured HTTPS origin of the instance's authentication service. |
| `account_id` | Lowercase UUIDv4 for the messaging account namespace, not a display name or an RP's pairwise OIDC `sub`. |
| `device_id` | Lowercase UUIDv4 for a registered messaging device. |
| `generation` | Positive safe integer identifying this device's signing-key generation. |

The canonical identity becomes the MLS BasicCredential. The actual Ed25519
signature key in the MLS leaf must match the verified binding; checking the
credential text alone is insufficient. Human-facing names are not authentication
inputs and are not included in a device fingerprint.

Trust anchors are an independently configured, bounded list of instance origins
and 32-byte Ed25519 public keys. They cannot come from a certificate's `jwk`,
`jku`, `x5u`, `x5c` or another discovery URL; those headers are rejected. No
network request is made. Restoring a synthetic checkpoint also requires the
caller to supply the same trust anchors independently. Instance key rotation and
DID resolution require a later explicit continuity contract.

First peer trust requires both a valid issuer signature and an independently
confirmed device fingerprint. The directory's response must not supply both
the candidate and the user's purported confirmation. The fingerprint is
base64url(SHA-256(JSON encoding of
`["mikaki-device-fingerprint-v1", identity, "Ed25519", public_key_base64url]`)).
The client has no implicit first-use acceptance or silent pin overwrite.

## Enrollment proof and signed binding

The device creates a JWS possession proof with type
`mikaki-device-registration+jwt`. It binds the exact identity, its public key,
issuer audience, a canonical 32-byte server challenge and an issue/expiry window
of at most 60 seconds. `verify_registration` requires the expected identity and
challenge as separate trusted arguments. A self-asserted account in the proof
does not authorize enrollment.

The future issuer adapter must derive those arguments from a validated owner
session and a server-created enrollment transaction. It must atomically consume
the one-use challenge, recheck session/credential/account authority, and commit
the device generation/registry revision before returning a binding. This pure
proof verifier does not implement that transaction or challenge replay ledger.
No Passkey private key is used as an MLS signing/decryption key.

A binding is a compact JWS with exactly this protected header profile:

- `typ`: `mikaki-device-binding+jwt`;
- `alg`: `EdDSA`, restricted to Ed25519 by the pinned key size and verifier;
- `kid`: base64url SHA-256 of the configured issuer public key.

Its signed payload contains `iss`, exact `aud: "mikaki-mls-device-v1"`, the
structured `device`, canonical base64url `public_key`, positive safe-integer
`revision`, `status` (`active` or `revoked`), `iat` and `exp`. The issuer must
match the device namespace. Revisions are per device; key generations and
registry revisions are separate. Bindings are valid for at most 300 seconds,
with no implicit clock-skew grace. Duplicate or unknown fields, unsupported
algorithms/types, padding, malformed signatures and oversized inputs fail closed.
The profile follows [JWT validation guidance](https://www.rfc-editor.org/rfc/rfc8725.html#section-3)
and separates registration proofs from device attestations by type and audience.

Short-lived bindings bound the freshness of an unobserved revocation. They do
not rotate the device key every five minutes: the issuer may refresh a lease for
the same registered key/generation without the device being online. A client
must obtain a current signed lease before using an expired binding. The future
directory adapter must enforce this profile and provide refreshed status.

## Continuity, revocation and review

The trust store retains the accepted key separately from the latest verified
registry observation, including a monotonic clock watermark.

| Observation | Client behavior |
| --- | --- |
| Same active key/generation and current lease | Refresh the lease; retain the existing pin. |
| Changed key/generation | Return `key_changed`; block use pending explicit review. |
| Conflicting contents under the same registry revision | Return `registry_conflict`; retain a mandatory review state. |
| Signed revocation | Return `revoked`; immediately block that member locally. |
| Older revision/generation, earlier issue time or local clock rollback | Reject; never replace the retained observation. |

The first three returned statuses and `revoked` are accepted observations to
retain, not generic request failures to discard. Repeating a confirmation does
not reset an existing pin. A later old-key response cannot dismiss a review
task, even when its revision is higher. These decisions survive restoration of
the current checkpoint. The encrypted journal additionally detects rollback
against its independent witness; restoring an old raw checkpoint directly
remains unsafe.

Accepting a replacement requires the exact previous and independently checked
new fingerprints, a higher generation/revision, a different signing key and
current active status. A revoked generation cannot be reactivated through this
review. Reviewing a replacement does not authenticate the old MLS member: the
existing group remains blocked until the old member is explicitly removed and
the replacement is invited with its own fresh KeyPackage. Tests exercise this
remove/reinvite path and confirm that the retired key cannot read the new epoch.
Transferring retained history to a new device is a separate archive decision.

Revocation is not instant global cryptographic removal. A client that has not
observed it may act until its cached binding expires. Observing clients refuse
messages from the revoked sender and stop sending to that member. An active
device can still remove the revoked peer, then merge the removal to advance the
MLS epoch. Revocation cannot recall keys/plaintext already copied by a device.

## MLS enforcement and evidence

`BoundMlsClient` verifies its own binding before use and the peer binding at
KeyPackage admission and Welcome acceptance. Incoming messages are checked
against the authenticated MLS sender's actual leaf key. After a Commit, every
resulting member is checked again. Correctly authenticated commits that add an
unapproved third device or replace a signing key without review are rejected.
Join/receive and other group mutations run on an isolated candidate so a failed
policy check cannot publish a changed epoch or consume the original secrets.

The raw `MlsProbeClient` remains available only for S1 tests and constructing
adversarial traffic. It bypasses the application identity policy and must never
be exposed as the product messaging interface.

[Native cases](../design/probes/mls/tests/bindings.rs) verify proof context,
signature/header/claim validation, impostor KeyPackages, substituted Welcome,
authenticated Add/Update attacks, signed key changes, exact review, explicit
re-invitation, expiry, clock rollback, revocation and issuer-anchor isolation.
[Browser cases](../design/probes/mls/bindings.browser.test.ts) use separate Wasm
devices and independent Node Ed25519 issuance/verification in Chromium, Firefox
and WebKit. They exercise real JWS wire interoperability, key substitution,
revocation and key-change decisions across page reloads. Issuer private keys
remain in fixture memory and the loopback server serves only fixed assets.

The next work is production integration/provisioning of the qualified SSO/registry
adapter and intended-device custody/unlock. The
[initial invitation flow](mls-device-invitations.md) now qualifies the first
KeyPackage/Welcome delivery with independently confirmed fingerprints. The
[same-instance mailbox](mls-device-delivery.md) now connects established pairs
to authenticated delivery and catch-up. Raw checkpoints contain plaintext private
state; the browser journal encrypts them with the complete operation state before
storage. They are not backups or a production trust store. The independent
instance/real-device [messaging pilot](federated-messaging.md#first-pilot) and
the threat from compromised browser distribution remain open gates.
