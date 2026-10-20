# MLS device lifecycle qualification

This implements the first, isolated S1 gate in the [messaging implementation
specification](../../../docs/implementation-spec.md#6-conversation-archive-mls-and-federation-p2s1p3).
It runs real OpenMLS key agreement and private messages with independent device
providers, plus the [client account/device trust boundary](../../../docs/mls-device-trust.md).
It now includes a [witnessed encrypted browser journal](../../../docs/mls-device-storage.md)
for private state, outgoing messages, received events and retries.
The [SSO/D1 service adapter](../../../docs/mls-device-service.md) qualifies
session-bound registration, signed leases and witness CAS behind a separate
Worker build feature and local entrypoint.
The [Vault custody adapter](../../../docs/mls-device-custody.md) now wraps the
independent state key through the actual Owner Vault lease and persists enrollment
before publishing a proof, with crash/reload and lock qualification.
The [authenticated ciphertext mailbox](../../../docs/mls-device-delivery.md) adds
bilateral same-instance delivery and catch-up. The [initial invitation
adapter](../../../docs/mls-device-invitations.md) transports KeyPackage/Commit/Welcome
and activates ordinary delivery only after witnessed joining.
The [explicit recovery flow](../../../docs/mls-device-recovery.md) now freezes
terminated conversations and qualifies fresh-group rejoin after update forks.
The [foreground chat UI](../../../docs/mls-chat-ui.md) now connects invitation review,
text/history, termination and explicit fresh-group rejoin to those adapters.
The [peer-key review UI](../../../docs/mls-peer-review.md) adds signed contact-code
inspection and independently typed initial/replacement fingerprints.
The [changed-device-key flow](../../../docs/mls-device-replacement.md) connects
next-generation enrollment and bilateral fresh-group admission without replaying
old pending ciphertext or copying old private history.
The [explicit proposal cancellation flow](../../../docs/mls-replacement-cancellation.md)
resolves competing pending proposals through veto and fresh approval, preserving
old-conversation blocking and ciphertext quarantine.
The [admission recovery flow](../../../docs/mls-admission-recovery.md) now covers
peer closure before key activation, expired packets and interrupted joining, with
explicit stop and fresh bilateral consent.
The [same-key rejoin recovery](../../../docs/mls-rejoin-recovery.md) covers a peer
stopping a successor before local restart, repeated stops and deferred changed-key
roots within the existing retirement limit.
The [limited product host](../../../docs/mls-beta.md) now reuses this client core
from the normal Vault screen behind explicit beta flags. Default product routing
remains disabled; no production release, physical-device acceptance or AI recipient
is qualified here.

## Source and isolation

The protocol, Basic credentials, traits and RustCrypto provider are pinned to
OpenMLS revision `e0b21a70a55a9014b8de2772b36bf3d638adad51`, including upstream
[#2261](https://github.com/openmls/openmls/pull/2261). The initial crates.io
OpenMLS 0.9.1 / provider 0.6.0 build passed the lifecycle checks, but its lockfile
included the unused optional `libcrux-kem` 0.0.9 backend with
[RUSTSEC-2026-0330](https://rustsec.org/advisories/RUSTSEC-2026-0330) and
[RUSTSEC-2026-0331](https://rustsec.org/advisories/RUSTSEC-2026-0331).
The pinned upstream dependency update removes these findings without advisory
exceptions. This source revision is not a claim of a new published OpenMLS release.

The only selected suite is RFC 9420's
`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`. Draft protocol features and secret
debug logging are disabled. Device randomness comes from the provider's system
CSPRNG, including browser randomness in Wasm. No custom ratchet is implemented.
The standalone Cargo workspace and lockfile keep this dependency tree out of
the authentication Worker and existing browser bundle.

## Implemented behavior

- Generate independent device signing keys and signed, validated KeyPackages.
- Create one conversation and add one peer using serialized Commit/Welcome
  messages and an embedded ratchet tree. Joining checks the expected group ID.
- Exchange bounded UTF-8 private messages in both directions and expose the
  authenticated MLS credential label, rather than an external claimed sender.
- Export/import the provider's private storage and restore groups with
  `MlsGroup::load`, including unpublished KeyPackages and pending commits.
- Update keys, explicitly merge commits and remove the other device. A removed
  device, including its retained pre-removal state, cannot open later messages.
- Reject modification, truncation, trailing bytes, cross-group traffic and
  replay. Bounded same-epoch reordering remains supported after restoration.
- `BoundMlsClient` additionally requires signed issuer/device attestations and
  independently confirmed fingerprints. It checks actual MLS leaf keys at
  admission, Welcome, receive and resulting Commit rosters; supports signed
  revocation, explicit key-change review and removal/re-invitation; and never
  silently replaces a known key. Registration includes a challenge-bound
  device-key possession proof. The feature-gated Rust service now verifies those
  proofs against actual SSO/D1 authority and issues matching bindings; production
  routing, schema rollout, issuer custody and actual Passkey enrollment remain open.

Application sends and incoming traffic fail while a local commit is pending;
the caller must explicitly reconcile that commit. This is a deliberately
limited probe policy, not a solution for simultaneous commits.

An important integration finding: a failed OpenMLS receive can consume message
ratchet state, and a rejected staged join can consume KeyPackage material. The
wrapper runs receive/join against an isolated in-memory candidate and replaces
the live state only after success. The denial tests then deliver the original
valid message/Welcome, proving that rejected input did not burn its secrets.
The copied checkpoint is bounded but intentionally expensive; product storage
needs a real transaction boundary rather than copying the whole device state.

## Private state and durable browser qualification

`checkpoint()` exports **plaintext private keys and MLS state**. It is an internal
serialization/test boundary, never a backup API. The raw lifecycle/identity tests
hold synthetic checkpoints in harness memory and clear exposed byte arrays.
Restoring requires the exact checkpoint version and source revision. The raw
encoding alone is neither authenticated nor rollback-resistant.

`PersistentMlsDevice` encrypts the complete checkpoint, trust store, outbox,
inbox/deduplication and retry receipts together before writing IndexedDB. Each
operation restores a fresh engine under an exclusive Web Lock. A separate
monotonic witness reconciles the prepared and published record before any wire
message or event is released. Retries return the same persisted ciphertext.
The browser qualification terminates pages at each commit boundary, aborts actual
IndexedDB transactions and exercises multiple tabs, lost witness responses,
whole-database rollback, quota limits, revocation and key replacement.

This journal requires an independently supplied nonextractable custody key and
authenticated witness. `VaultMlsDevice` now connects both to the actual Owner Vault
controller and SSO/D1 handler. The opt-in product beta uses the same client;
production release, offline operation without the
witness and backup/device-loss recovery are not implemented. Tests keep fixture
custody keys and the witness outside browser storage. Retaining old encrypted
checkpoints still retains old MLS secrets for anyone who later obtains the
custody key. Memory cleanup does not promise physical erasure by the runtime.

Raw `MlsProbeClient` credential names such as `alice/device-1` remain synthetic
labels; that class deliberately bypasses application identity policy for S1 and
adversarial tests. `BoundMlsClient` binds canonical issuer/account/device/key
generation identities to signed attestations and reviewed fingerprints.
Qualified issuer accounts are synthetic fixtures, not a production Mikaki SSO
integration or DID/person verification. See the [trust profile and remaining
adapter requirements](../../../docs/mls-device-trust.md). This probe must not be
mounted as a public chat API.

## Reproduce

From the repository root, with the pinned Rust toolchain, wasm-pack 0.15.0 and
the repository's npm dependencies installed:

```sh
cargo fmt --manifest-path design/probes/mls/Cargo.toml -- --check
cargo clippy --locked --manifest-path design/probes/mls/Cargo.toml --all-targets -- -D warnings
cargo test --locked --manifest-path design/probes/mls/Cargo.toml
wasm-pack build design/probes/mls --target web --release --out-dir pkg-web -- --locked
cargo clippy --locked --manifest-path design/probes/mls/Cargo.toml --target wasm32-unknown-unknown -- -D warnings
npm run build:policy
node scripts/build-messaging-qualification.ts
npx playwright install chromium firefox webkit
MIKAKI_MLS_BROWSERS=chromium,firefox,webkit node --test --test-concurrency=1 design/probes/mls/browser.test.ts design/probes/mls/bindings.browser.test.ts design/probes/mls/persistence.browser.test.ts design/probes/mls/server.test.ts design/probes/mls/delivery.server.test.ts design/probes/mls/invitation.server.test.ts design/probes/mls/recovery.server.test.ts design/probes/mls/server.browser.test.ts design/probes/mls/vault-device.browser.test.ts design/probes/mls/chat.browser.test.ts design/probes/mls/peer-review.browser.test.ts design/probes/mls/replacement.server.test.ts design/probes/mls/replacement.browser.test.ts design/probes/mls/replacement-cancellation.server.test.ts design/probes/mls/replacement-cancellation.browser.test.ts design/probes/mls/admission-recovery.server.test.ts design/probes/mls/admission-recovery.browser.test.ts design/probes/mls/rejoin-recovery.server.test.ts design/probes/mls/rejoin-recovery.browser.test.ts design/probes/mls/rejoin-cancellation.server.test.ts design/probes/mls/rejoin-cancellation.browser.test.ts design/probes/mls/generation-negotiation.server.test.ts design/probes/mls/generation-negotiation.browser.test.ts
cargo audit --file design/probes/mls/Cargo.lock
```

On a busy local host, `MIKAKI_MLS_TEST_TIMEOUT_MULTIPLIER=4` can extend outer
browser-test deadlines. Values 1 through 4 are accepted; the default is 1 and CI
keeps its original per-test budgets. This does not alter protocol/lease expiry,
assertions or the device clock, and is not a performance qualification.

Without `MIKAKI_MLS_BROWSERS`, the browser test runs Chromium. Each device uses a
separate browser context/Wasm module; the harness relays serialized wire bytes.
It serves only fixed assets on a loopback ephemeral port. Reloading destroys
the old page before restoring a fresh client. The final test reports optimized
Wasm size and gzip size without writing keys, checkpoints or plaintext reports.
[The CI workflow](../../../.github/workflows/mls-probe.yml) repeats native and
three-browser checks plus the dependency audit.

## Local evidence, 2026-10-19

On macOS arm64 with Rust 1.98.1, the current slice has nine native MLS lifecycle
cases plus twenty-eight binding/adversarial cases. The three-browser harness has
twelve lifecycle/identity/denial cases plus twenty-four journal scenarios and
one size report. Native and Wasm
Clippy use warnings denied; TypeScript is also checked. The optimized isolated
module including device trust measures 1,744,049 bytes, or 678,698 bytes
with the harness's gzip settings. These sizes exclude an application UI and
are not cold-start or intended-phone performance measurements.

Cargo audit reports no vulnerabilities. It retains one transitive
`proc-macro-error2` unmaintained warning (RUSTSEC-2026-0173); no advisory ignore
was added. The CI workflow is present locally; remote execution has not been run as part
of this qualification.

The separate feature-gated Rust service adds nine actual workerd scenarios and
three integrated browser journeys using real Wasm proofs and the SSO/D1-backed
HTTP witness. Its Wasm Clippy check also denies warnings, and five native Worker
host/policy tests pass. The service is mounted only by the explicitly enabled
limited beta product host, and stays absent in the default product build.

Vault custody adds seven integrated scenarios per browser (21 total), using
actual Owner-key APIs, synthetic PRF, encrypted preparation, real Wasm proofs,
reload, transaction aborts, tab conflicts and disposal during a witnessed write.
Thirteen existing Owner-key checks, including the three-browser lease case,
also pass locally. The mailbox adds eight workerd cases and three delivery
journeys per browser (nine total), with closed-page catch-up, exact retries,
receipt/content tampering, failed local persistence and ordered key updates.
Initial admission adds five workerd cases and two journeys per browser (six
total), covering packet/reply loss, immutable intent, Welcome rejection and
failed join persistence. Explicit recovery adds five workerd cases, three native
retirement/secret-isolation cases and two journeys per browser (six total),
including cancellation, actual update forks, quarantine and rejoin after a local
write failure. The foreground UI adds four integrated journeys per browser (twelve total),
covering explicit code approval, durable sender/receiver history, exact retries,
actual fork/rejoin controls, literal hostile text, failed persistence and lock
during a witnessed send. Axe and narrow-layout checks also run. No physical
Passkey or production activation is claimed. Peer-key review adds four native
public-display/denial cases and four journeys per browser, including first trust
through actual text delivery, changed/revoked keys, registry conflicts, stale-tab
review, aborted approval and lock during its witnessed retry.

Changed-key admission adds three native cases, six workerd cases and three
journeys per browser, covering real replacement enrollment, independent key
review, bilateral consent, old-history isolation, lost responses, interrupted
enrollment/activation, lock during preparation and concurrent successor denial.

Proposal cancellation adds six workerd cases and three journeys per browser,
covering competing proposals, unpublished tombstones, exact veto retry, cancelled
wire isolation, real reversed-role admission, persistence failures, lock and
cancellation versus final approval.

Admission recovery adds three workerd cases and four journeys per browser for
pre-activation peer closure, packet expiry, interrupted Commit/Welcome, exact
close/rejoin retries, atomic deferred retirement, quarantine and lock.

Same-key rejoin recovery adds four workerd cases and five journeys per browser
for exact successor status, pre-activation closure/expiry, repeated stops, native
retirement capacity, immutable proposals, lost replies, lock and changed-key roots.

Same-key proposal cancellation adds seven workerd cases and four journeys per
browser for competing codes, unpublished tombstones, exact veto retries, final
approval races, failed persistence, peer veto, lock and fresh real MLS delivery.
See [the cancellation qualification](../../../docs/mls-rejoin-cancellation.md).

Repeated-generation negotiation adds four native cases, four workerd cases and
four journeys per browser for stale-proposal veto, signed original membership,
fresh current-key agreement, real text, proof/activation failure, reload and lock.
See [the negotiation qualification](../../../docs/mls-generation-negotiation.md).

Admitted-successor stopping adds two native cases, twelve workerd cases and five
journeys per browser for current-generation stopping, witnessed quarantine, atomic
retirement of original/stopped groups, fresh bilateral agreement and actual text.
It covers repeated admitted successors while the unchanged endpoint retains its
original native group or has already activated the exact failed replacement
(unjoined, forming or joined). Later native same-key successors and already
started ordinary recovery of an activated replacement remain separate gates.
See [the service qualification](../../../docs/mls-replacement-stop.md).

Four more journeys per browser cover the ordinary admission-recovery root bridge
and the shared pending-stop guard. They retain the root's exact close receipt, cancellation
tombstones and isolated outbox through failed persistence, lost replies, reload,
fresh current-key text and a later ordinary rejoin. An unconfirmed original close
must finish with its saved UUID first. Pending same-key successors remain frozen
and cannot be skipped by stopping their root.
While a witnessed stop is unconfirmed, even still-current old endpoint keys
cannot advance the saved old consent or native activation.

Three further journeys per browser qualify explicit veto/close of those pending
successors after peer rotation, followed by a witnessed ordered chain of confirmed
closes. Lock, lost replies, aborted activation, another generation and reload
retain every native retirement fence and original receipt. Actual current-key
text and subsequent ordinary rejoins share the same eight-retirement budget.
Twenty-three structural cases reject missing/substituted/unconfirmed links and
retain compatibility with single-root stop journals.

Four further native cases and four journeys per browser cover an already
activated failed replacement: reserved, forming with a pending commit, and joined.
Exact native origin checks retain the original fence through failed persistence,
lock, lost replies, another generation, reload and fresh bilateral text. Queued
text and pending admission wire stay isolated; subsequent ordinary rejoins share
the unique eight-group retirement budget. Later actual same-key successors and
already-started ordinary close chains remain separate recovery gates. Alternating
sequential key changes keep using the completed current conversation; the endpoint
that changed its key cannot freeze that group through the older original anchor.

## Next adoption gates

1. Integrate/provision the qualified SSO/registry adapter and issuer-key custody.
   Qualify intended-device enrollment/recovery and the connected invitation/peer-key
   review UI before activating production routing and schema.
2. Qualify the connected Vault custody and authenticated monotonic witness on
   intended devices. Qualify retention/quota/device-loss recovery and explicit
   rejoin/capacity recovery; the current journal requires witness availability.
3. Integrate the qualified foreground one-to-one text/recovery UI into the
   product host; qualify later native same-key successors, ordinary recovery from
   activated replacements, device-loss
   recovery and capacity repair.
   Qualify two independently deployed instances, real devices, loss behavior and
   operational limits before product activation.

The [federation pilot](../../../docs/federated-messaging.md#first-pilot) remains
open. These tests do not qualify public federation, long-term archives, forward
secrecy of deliberately retained plaintext, multi-device history restoration or
the security of browser code distribution.
