# Android Messenger and Wallet: device and session rebuild

Status: design and qualification baseline, 2026-11-03. This is not a claim that
the proposed device session, native Chat, recovery or device qualification exists.
Baseline: main `6395e6b2`. No Android device was attached for this assessment.

## Current boundaries

- Android's primary account path uses a first-party WebView with WebAuthn support.
  Chat is also hosted in that WebView, not a separate external browser. The
  native shell opens Wallet and overlays the workspace for Chat/account.
- After an explicit login, native code obtains a short-lived account projection
  by independently checking the WebView's HttpOnly SSO cookie with the server.
  The projection is capped at 20 seconds and contains no bearer token or PRF.
  This is an account projection, not a registered-device credential. On process
  startup `app_session_allowed` is false; an existing WebView cookie alone does
  not automatically restore the native projection.
- Wallet holder and storage keys are Android Keystore keys, separate from the
  login credential. Existing key generation does not require user authentication;
  Keystore presence alone does not establish a biometric-protected operation.
  Wallet and document files are in no-backup storage. Loss of an installation
  or key must not be represented as automatic restoration of holder credentials.
- Messaging has an existing device identity, enrollment, generation and
  replacement model. Its browser custody uses an Owner Vault session; the
  journal is not a backup. It does not yet establish native Android custody,
  background delivery, or recovery of lost conversation history.

See [the existing product slice](wallet-chat-mvp.md),
[messaging device trust](mls-device-trust.md), and
[messaging custody](mls-device-custody.md). Do not treat the compatibility
external-browser OIDC path as the current default Android path.

## Product and security contract

Treat these as independently observable states, never as synonyms:

1. **Account:** IdP authentication establishes an account, subject to its
   session and step-up policy. A passkey may be synced or cross-device; success
   does not prove which installation owns a native key.
2. **Installation:** a fresh installation creates a purpose-specific native
   device key and proves possession in a one-use, account-bound enrollment.
   The server records a revocable device generation. Registration requires an
   explicit user action and current account authorization; a QR or passkey alone
   is not proof of physical proximity or an existing device's approval.
3. **Service session:** an enrolled device obtains renewable, narrowly scoped
   authority bound to its key, with expiry, rotation, replay protection and
   server-side revocation. Account switch, cancellation, loss of key and
   revocation fail closed. An SSO cookie or the current account projection is
   not evidence of such binding. Offline status must not extend server authority.
4. **Local unlock:** controls access to local content and sensitive key use.
   Android user authentication must be bound to the actual cryptographic key
   operation when that assurance is required. Unlock is not online authorization.
5. **Operation consent:** credential presentation displays recipient and claims
   before approval. Additional user authentication depends on the operation and
   issuer/verifier policy, not on the mere fact that an app was opened.

Keep account, session proof, MLS signing/state, holder and storage keys separate.
Document platform and hardware-backed properties from actual evidence; do not
infer hardware backing or user verification from an alias name.

## Initial recovery policy for implementation

Until a separately reviewed backup design is implemented, a lost device can be
revoked and a replacement enrolled through account recovery, but neither old
plaintext messages nor non-exportable holder credentials are promised to return.
Existing peers must review changed messaging identities under the existing
replacement policy. Where an issuer supports it, the user may request a new
credential; do not imply that every issuer supports reissuance. Explain this
before device enrollment and credential receipt. Preserve existing local data on
login failure, logout, transient network errors and cancelled enrollment.

This conservative policy does not choose a permanent history-backup product.
An encrypted backup, transfer from another device, and issuer reissuance each
need separate threat models, user consent and acceptance tests before claims.

## Sequence and gates

1. **Observe the installed app.** Record exact source commit, APK digest,
   package/signing certificate, Android/WebView versions and IdP environment.
   With an authorized test account and two devices where needed, observe first
   login, cancel, background and process kill during authentication, return,
   relaunch, offline use, Chat/Wallet navigation, logout, account switch and
   revoked account/device. Record visible steps and outcomes without credentials,
   cookie values, passkey identifiers, plaintext messages or document data.
   Verify account association and passkey behavior on the actual signed APK.
2. **Define and test state transitions.** Specify startup, enrollment, active,
   locked, offline, expired, revoked, replacement and recovery states. Test
   subject changes, stale async responses, process death, lost responses and
   logout races before connecting a new credential to existing storage. Account
   A's state must never become accessible under account B.
3. **Implement enrolled-device session.** Build a server enrollment and
   revocation contract plus Android Keystore proof and a durable session with
   refresh/rotation. Test replay, concurrent refresh, key loss, revocation,
   account switch and cancellation across real server transactions. Do not make
   a long-lived bearer cookie the durable device credential. Keep the current
   path until migration and rollback are demonstrated.
4. **Connect native Chat and Wallet journeys.** Reuse the existing messaging
   protocol and explicit replacement/peer-review rules. Bring persistence,
   lifecycle, notifications and delivery under the same installation identity;
   demonstrate send/restart/receive and Wallet review with two independent
   accounts and devices. Maintain explicit Wallet holder and issuance policies.
5. **Improve Passkey entry.** Compare external OAuth with Android Credential
   Manager only after the account/session boundaries are fixed. A direct native
   ceremony needs Android app association and server validation for the actual
   Android origin, one-use challenges and an independently designed session
   exchange. It must not turn an embedded OAuth authorization page into a
   substitute for the external-user-agent flow.

Physical device results, host/browser tests, production deployment and security
review are separate gates. A simulated UI or successful build is not an Android
passkey, Keystore, offline recovery or two-device messaging result.

## Existing projection hardening

The existing Android account projection now caps its 20-second native lease
from the start of the verification request, rather than adding network latency
to the lease. A response arriving after the login deadline, after cancellation
or after a generation change cannot activate the native account. This change
does not persist a session, enroll a device, or grant offline access. It only
limits authority in the existing SSO projection path.

After a successful network check, native code also rechecks the WebView cookie
and readiness before accepting the result. A changed, missing or unavailable
cookie closes the native projection. This narrows an account-switch race; the
WebView and server checks are not atomic, so the bounded lease still matters.
The Worker also rechecks DBSC cookie expiry inside its projection queries and
caps the returned expiry by that cookie deadline. The local Worker/D1 test
checks a live DBSC deadline, an expired cookie and ordinary SSO without DBSC;
it does not simulate revocation at every interleaving or prove deployment.

An isolated [local D1 experiment](../design/probes/android-device-registry/README.md)
checks conditional enrollment and revocation under concurrent Workers. Its
proofs, sessions and clock are synthetic; it does not expose a product endpoint
or implement a device-bound session.

The [installation proof core](../crates/oidc/src/installation_enrollment.rs)
now binds a verified ES256 DPoP proof to a server-pending key, nonce, endpoint
and short deadline. A separate host-verifier/local-D1 test joins that output to
the fixture's conditional consumption and replay reservation. Owner consent,
trusted loading of pending state, production Worker/D1 wiring, and token/session
issuance remain unimplemented; the fixture's verified values are test inputs.

## Android loading and cancellation observation

On the API 35 tablet emulator, a debug-only APK temporarily bypassed the
WebAuthn feature check and setup because the installed WebView was version 124.
With simulated slow networking, it showed the native loading indicator, returned
to an interactive Wallet after cancellation, allowed another attempt and stayed
on Wallet for six seconds after the second cancellation. The test used no
account or credential. This is an observation of the WebView host lifecycle,
not a Passkey, PRF, account-switch or physical-device qualification. The
production source retains the WebAuthn feature check and setup. A prior emulator
run reported an ANR while the renderer was waiting under CPU/I/O pressure;
the limited retry above is not enough to rule out that failure on other devices.

## Installation key custody checkpoint

The Android native plugin has a separate P-256 Keystore namespace for future
installation-session proofs. It accepts a caller-generated 128-bit identifier,
rejects replacing an existing alias, bounds compact-JWS signing input, and offers
public-key lookup and deletion to Rust only. Creation is serialized within this
app process; this is not a multi-process coordination protocol. The key does not
require fresh user authentication, because future background session renewal must
not be confused with biometric unlock or presentation approval.

Three instrumented tests on a local API 35 Android emulator exercised a
non-exportable private-key handle, signature verification and tampering,
same-process concurrent creation, malformed input, key deletion and separation
from a Wallet holder alias. Test APK SHA-256:
`c4420bc3b510f0b1c42d105643b30663b49ab8c3b1694a83ea7ffef9ebc8ff40`.
The test APK has its own application identity; it does not establish hardware
backing, attestation, production app custody, physical-device behavior or a
server-recognized device. This code does not itself enroll a device, mint or
refresh tokens, establish replay protection, perform biometric approval, or
recover orphaned keys after a crash. Those remain requirements before it is
connected to a service session.
