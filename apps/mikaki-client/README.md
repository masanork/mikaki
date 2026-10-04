# Mikaki Tauri client

This is an experimental Tauri 2 client. Install the pinned CLI with `npm ci`
from this directory; `npm run tauri -- android init --ci --skip-targets-install`
and `npm run tauri -- ios init --ci --skip-targets-install` initialize the
checked-in native projects. Its bundled local UI starts OIDC login
in the system browser. Desktop uses an ephemeral `127.0.0.1` callback port;
Android and iPhone use an app-claimed HTTPS callback. Rust uses Authorization
Code with S256 PKCE, checks callback `state` and `iss`, exchanges the one-use
code as a public client, validates the signed ID Token and nonce, and holds
the resulting UserInfo token only in process memory. The token is not a Vault
grant. No remote document has Tauri command access.

The [client architecture review](../../docs/tauri-client-auth.md) describes the
separate Vault resource grant and WebAuthn PRF work. A mobile-only Vault
preview opens the system browser for one-attribute consent. Its DPoP P-256
private key is generated and retained by Android Keystore or the iPhone Secure
Enclave; the Rust code receives only its public coordinates and DER signatures.
The access token stays in Rust process memory. It does not decrypt the owner
envelope. Mobile callback
and Android app association and ordinary OIDC return/token validation have
been tested in a signed installed app; iPhone remains unqualified.
Android reads My Number input-support attributes and traditional IC driving licences
over NFC. A disabled-by-default backend path verifies static issuer signatures,
links attributes after browser-owner consent, and issues a short-lived SD-JWT or mdoc through
OID4VCI. Android encrypted receipt persistence and signed preregistered SD-JWT/mdoc OID4VP
presentation and Android QR + BLE peripheral proximity are implemented locally.
UserInfo verified attribute release requires separate owner consent; PDS remains unimplemented. The icon uses mikaki's woven fence mark; a distribution
signing identity has not been selected. Android release signing can use an
ignored local keystore configuration described in the activation checkpoint.

## App interface

The bundled UI provides a login entry, browser-authentication waiting screen,
account home, account details and settings. Settings offer system/light/dark
appearance and local logout; browser SSO remains active. Back navigation cannot
reveal account screens after logout. Cancel invalidates the pending Rust
transaction, including delayed discovery or token responses. Appearance is the
only value stored in WebView localStorage; tokens remain in Rust memory.

Technical status and the opt-in Vault key/consent/ciphertext tools live under
Settings → Diagnostics. The home does not claim to decrypt or manage Vault data.
See [screen previews and validation](../../docs/mobile-ui-preview/README.md).
From the repository root, `npm run test:mobile-ui` checks the real bundled
assets with a synthetic native bridge, and `npm run preview:mobile-ui`
regenerates the screenshots. These browser checks do not establish OS callback
delivery or device-specific layout.

## Identity-card read, account linking and issuance

Settings → Diagnostics reads My Number input-support four attributes or traditional
IC driving licences on Android. Driver's licence PIN1 is sufficient for a local
preview; PIN2 is required for backend signature verification because the signed
hash also covers photo and registered domicile. Both PINs are verified once and
never uploaded. The My Number personal-number EF is never read.

The preview remains unverified until the user chooses to submit signed evidence.
The backend verifies against operator-configured trusted issuer keys, opens an
owner-consent page, and links only normalized attributes/provenance. The app can
then receive an at-most-five-minute `dc+sd-jwt` or `mso_mdoc` through OID4VCI 1.0 using a separate holder
key and validate it. Android keeps the holder in Keystore and encrypts the
receipt in backup-excluded storage; restore revalidates the existing key, signature
and expiration bounded by five minutes, linkage, evidence trust-key and document validity (plus the Document Signer certificate for mdoc). Other platforms retain receipts in process memory. An owner management page
supports inspecting and deleting linkage. It does not claim liveness, current
licence status or government issuance. Signed preregistered OID4VP requests can
select supported attributes for explicit user-approved direct POST presentation.
mdoc issuance also requires `IDENTITY_MDOC_CERT_DER` matching the issuer key.
The verifier registry is empty by default; configure approved keys and exact
HTTPS destinations using `MIKAKI_OID4VP_VERIFIERS` at build time.

The browser can also link attributes without authorizing issuance to the reading app.
A registered independent wallet can then obtain a separately approved credential through
OID4VCI authorization code + S256 PKCE using its own holder key. This requires migration
0038 and 0039, `IDENTITY_WALLET_ENABLED=true` and an exact HTTPS wallet callback registry.
Optional PAR and ES256 DPoP tokens are supported. A pinned Multipaz JVM SDK has received
both formats through PAR, PKCE and DPoP nonce challenge/retry against local workerd;
see the [reproduction steps](../../docs/identity-card-issuance.md#reproduce-the-multipaz-host-sdk-issuance-test).
Wallet app persistence/presentation E2E and HAIP certification remain unqualified.

Android also has an opt-in native wallet flow configured at build time with
`MIKAKI_HAIP_WALLET`: instance attestation, mandatory PAR, browser approval,
PKCE and DPoP token exchange, holder-key attestation, encrypted credential
delivery and validated receipt storage. Settings → Diagnostics exposes both
SD-JWT and mdoc issuance when this configuration is present. Tokens, proofs,
keys and authorization callbacks stay in native code. The build configuration
must also provision separate SD-JWT credential CA and mdoc IACA roots; HAIP
receipts verify their certificate paths at reception, restoration and presentation.
Optional offline CRLs fail closed. Pending approval can be
restored while the native process remains alive; cancellation invalidates late
results. See the [configuration and verification boundary](../../docs/identity-card-issuance.md#opt-in-native-wallet-issuance-commands-and-ui)
before enabling it. Physical Android and external wallet interoperability remain
to be qualified.

The host E2E now carries each actual workerd-issued SD-JWT/mdoc into an encrypted
OID4VP response with the same Rust-held holder key. Independent Node JOSE/CBOR
checks CA/IACA trust, selective disclosure and request binding. It also tests
consent denial, request replay and tampering. This uses synthetic attestation,
account approval and consent; Android device/UI and external Wallet presentation
remain separate. See [reproduction and limits](../../docs/identity-card-issuance.md#issuance-to-presentation-host-e2e-checkpoint).

Before device E2E, run `npm run check:identity-wallet-device -- --online
--wallet-config /path/to/public-wallet-config.json --apk /path/to/signed-wallet.apk`.
This reads public endpoints and checks the selected APK/device; it does not login,
issue, install or change settings. Its passing prerequisites do not qualify E2E.
See [the device qualification order](../../docs/identity-card-issuance.md#android-wallet-device-preflight-and-qualification-order).

`plugins/identity-reader` extracts the Android IsoDep transport from madowi with
Rust-only methods; no WebView generic APDU command exists. `vendor/civ-card` is a
licensed minimal source snapshot with exact provenance in `ORIGIN`. The shared
[identity crate](../../crates/identity/src/lib.rs) owns strict parsing/verification.
iOS and desktop NFC are unsupported. See [flow, guarantee boundary, deployment
configuration and checks](../../docs/identity-card-issuance.md).

Preregistered OID4VP Final verifiers can configure `response_encryption` for ECDH-ES/A256GCM `direct_post.jwt` responses with either SD-JWT or mdoc. Configured encryption is mandatory; requests cannot downgrade to plaintext or replace the pinned recipient key. The mdoc DeviceSignature binds that recipient's JWK thumbprint. See [identity issuance](../../docs/identity-card-issuance.md) for registry configuration and protocol boundaries.

An opt-in verifier registry profile `oid4vp_draft18_mdoc` supports a narrow preregistered PE request and encrypted mdoc response using the legacy wallet-nonce handover. The default `oid4vp_final` profile remains separate. This provides Annex B wire components; Android same-device invocation now supports registered HTTPS GET request_uri endpoints via `MIKAKI_OID4VP_REQUEST_URIS`, cold-start queueing and the existing explicit consent. The explicit `oid4vp_final_x509_hash` profile also supports POST request_uri with shared capability metadata and a one-use signed-echo wallet nonce; see the [POST checkpoint](../../docs/identity-card-issuance.md#request-uri-post-and-wallet-metadata-checkpoint) and [host HTTPS transport verification](../../docs/identity-card-issuance.md#native-https-presentation-transport-checkpoint). The [selected official HAIP Wallet baseline](../../docs/identity-card-issuance.md#official-wallet-happy-flow-encryption-and-disclosure-subset-checkpoint) passes eleven modules in each format (22 runs), including [claims omission with explicit proof consent](../../docs/identity-card-issuance.md#dcql-claims-omission-checkpoint), bounded DCQL sets and encrypted errors, with four remaining host rejection probes awaiting real Wallet error-screen evidence; raw verifier-code fragments are also accepted at exact registered completion endpoints. [Same-credential multiple-query presentation](../../docs/identity-card-issuance.md#same-credential-multiple-query-presentation-checkpoint) has shared Rust and independent issued-Wallet peer coverage in both formats. The [verified inventory selection core](../../docs/identity-card-issuance.md#verified-inventory-selection-core-checkpoint) also supports a mixed SD-JWT/mdoc batch with distinct holder keys in shared Rust tests; [native inventory storage and consent](../../docs/identity-card-issuance.md#native-inventory-persistence-and-consent-checkpoint) now connect that core to up to eight Android receipts, v1/v2-to-v3 migration and one atomic reviewed response. Host Node/JOSE verifies a real native mixed response; physical migration and Keystore qualification remain pending. Registered HTTPS browser completion is available via `MIKAKI_OID4VP_REDIRECT_URIS`; only a bounded response_code or raw verifier-code fragment is passed to the native opener after acknowledgement and cancellation checks. Completion failures preserve a sent-credential result without resubmission. Opt-in `certificate_trust` validates a bounded reader CA chain and DNS SAN in addition to the pinned signing key for online and proximity requests. Optional offline `certificate_trust.revocation` requires signed complete CRLs for the leaf and intermediates and bounds consent by CRL freshness. Online OCSP/CDP retrieval, dynamic X.509 client identifiers, verifier-side session redemption and Annex B conformance remain separate work.

Backend intake/issuance remain disabled until migration 0036, dedicated issuer
keys, trusted card issuer keys and the rate-limit binding are provisioned.
OID4VP Final uses its own handover. ISO 18013-5 QR/NFC transcript constructors
share the DeviceAuthentication core. Android QR + BLE peripheral holder transport
includes transcript-bound session encryption and signed-reader consent. Central-mode
holder transport, physical NFC/BLE interoperability, 18013-7 Annex A/B and 23220
profile qualification remain separate work. Local
synthetic tests and an Android build do not qualify physical-card reading. Test
real-card success, PIN errors without retries, removal, cancellation and resume
before activation. Android wallet persistence, erasure and presentation still
need device and real-verifier qualification.

Android mdoc proximity now has a QR engagement + BLE peripheral GATT holder path, encrypted SessionEstablishment/SessionData and a pinned signed-reader request followed by explicit attribute/retention consent. Build-time `MIKAKI_MDOC_READERS` defaults to `[]`; configure approved reader P-256 public keys separately from the OID4VP registry. Android HCE static and negotiated NFC engagement can hand over to BLE; QR engagement also supports NFC-only encrypted APDU retrieval with deferred consent and response fragmentation; no physical NFC/BLE/TNEP interop, L2CAP or iOS proximity qualification is claimed. See [identity-card-issuance](../../docs/identity-card-issuance.md) for the reader certificate profile, cancellation rules and remaining ISO profiles.

The mdoc proximity diagnostics offer `nfc_negotiated_data` for NFC engagement and encrypted NFC retrieval without QR or Bluetooth, and `nfc_negotiated` TNEP Hr/Hs negotiation followed by BLE peripheral retrieval, with exact handover bytes bound to encryption and signatures. It uses the same explicit `MIKAKI_MDOC_READERS` registry and native consent as QR/static NFC. Physical TNEP/reader interoperability is still unqualified; see [identity card issuance](../../docs/identity-card-issuance.md).

```sh
cargo test -p mikaki-identity --locked
cargo test --manifest-path apps/mikaki-client/src-tauri/Cargo.toml --lib --locked
npm run test:mobile-ui
# After building the Rust worker:
node --test local/conformance/identity-issuance.test.ts
# From apps/mikaki-client with SDK/NDK and JDK configured:
npm run tauri -- android build --debug --target aarch64 --ci --apk
```

The arm64 debug APK can also be assembled after building its Rust JNI library
using `./gradlew :app:assembleArm64Debug -x :app:rustBuildArm64Debug --no-daemon
--max-workers=2` from `src-tauri/gen/android`. This bypasses the observed Tauri CLI
Gradle subprocess startup issue; it requires an up-to-date Rust library first.

## Desktop setup

Apply the normal OP migrations through `0026_native_loopback_redirect.sql` and
register a public desktop client with a separate client ID, sector
`127.0.0.1`, and redirect URI `http://127.0.0.1:0/oidc/callback`. The operator
command and input format are in the architecture review. The client ID is
public but must match the registration. Set `MIKAKI_DESKTOP_CLIENT_ID` in the
build environment, then build from `src-tauri` with `cargo check` or the Tauri
CLI. The issuer is pinned to `https://auth.mikaki.org`.

The desktop login requires an installed OP with the matching client
registration, a system browser, a Passkey, and a local loopback listener. A
successful compile or synthetic Worker test does not qualify the installed
flow. Test login, cancel/timeout, callback interception, wrong port/issuer,
second login, and process restart on each target desktop OS before release.

## Android and iPhone setup

The [activation checkpoint](../../docs/native-client-activation.md) records
the inspected production state, prepared public registration, Android signing
configuration and deployment evidence. The checked-in registration is now
applied to production. Android's ordinary login, fresh Passkey biometric prompt,
app return, and cancellation are verified on a signed Pixel build; the remaining
device cases are open. See the [App Links recovery record](../../docs/native-client-activation.md#android-app-links-recovery-observed-on-2026-10-01)
for a device setting that prevented callback delivery despite domain verification.

Register a separate public mobile client with sector `app.mikaki.org` and
exact redirect URI `https://app.mikaki.org/oidc/native/callback`.
The authorization server remains `https://auth.mikaki.org`; the callback
host is separate so Safari can open its Universal Link from the authorization
site. Set its
public ID as `MIKAKI_MOBILE_CLIENT_ID` **when compiling the Rust app**. The
Tauri app identifier is `app.tossa.mikaki`. Configure the production Worker
with `MIKAKI_IOS_TEAM_ID` (the ten-character Apple Developer Team ID) and
`MIKAKI_ANDROID_SHA256_CERT_FINGERPRINT` (the colon-separated SHA-256
fingerprint of the Android distribution signing certificate). Each
`/.well-known/` association response is 404 until its corresponding valid
value is configured. It must be publicly reachable over HTTPS on
`app.mikaki.org`; redirects or a mismatched signing identity will prevent
the OS from delivering the callback. That hostname was deployed as a second
Custom Domain on 2026-09-30. Its Android association uses the dedicated local
verification certificate; Apple association still awaits a Team ID. The mobile
client registration is active. The callback host serves only the Apple and Android
association documents; all other requests, including a browser fallback to
the callback path, return 404 without cache or referrer disclosure.

The pending PKCE transaction lives only in app memory and expires after three
minutes. If the OS terminates the app during browser login, restart login;
an unpaired cold-start callback is ignored. Test actual App/Universal Link
delivery, Passkey authentication in the external browser, cancellation,
wrong and duplicate callback parameters, and app restart on signed Android
and iPhone builds. Compilation alone does not qualify this flow.

For physical-device qualification, compile with
`MIKAKI_MOBILE_LOGIN_PROMPT=login` to request fresh OP authentication using
the standard [OIDC `prompt=login` parameter](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest).
This also makes cancellation and pending-transaction expiry observable when
the browser already has an SSO session. It does not select an authenticator
or bypass user verification. Leave the variable unset in normal builds to
retain browser SSO. The flag applies to mobile authorization requests only.

The generated iOS entitlement contains `applinks:app.mikaki.org`. A signed
physical-device build also needs an Apple development team and an association
response containing that team's app identifier. This checkout has neither a
signing certificate nor a configured team ID. The iPhoneOS Rust/Swift target
passes `MIKAKI_NATIVE_VAULT_PREVIEW=1 cargo check --target aarch64-apple-ios`.
The full Simulator build through Tauri CLI is blocked on this machine because Xcode 27 has
the iOS 27 SDK but only the iOS 26.5 Simulator runtime is installed.

## Mobile Vault preview

Build with `MIKAKI_NATIVE_VAULT_PREVIEW=1` and a registered mobile client ID
to show the Vault action. The matching OP must explicitly run with
`MIKAKI_NATIVE_VAULT_OAUTH=preview`; normal deployment keeps that path closed.
The preview requests `scope=openid vault.read`, the Vault resource, and exact
`authorization_details` for `owner_note`. It verifies the callback and signed
ID Token, requires a DPoP Token response, and reads ciphertext through
`GET /vault-api/attributes/owner_note`. A DPoP nonce challenge is retried once
with a fresh proof. The UI shows only the revision and format version.

The DPoP key is a persistent, non-exportable installation key. iPhone requires
a physical device with Secure Enclave; the simulator has no fallback signing
key. Android uses Android Keystore without requiring StrongBox, so hardware
backing varies by device. The token remains in process memory and is discarded
on logout or process exit. The flow has not been exercised on a signed Android
or iPhone build. Desktop Vault consent is still unavailable because the current
server grant requires an exact registered HTTPS callback rather than its
ephemeral loopback port. Production enablement also requires reviewed client
display identity in the consent page and installed-app security tests. The iOS
Swift plugin was compiled with the iOS Simulator Rust target. The Android
Kotlin plugin was compiled into an arm64 debug APK with `MIKAKI_NATIVE_VAULT_PREVIEW=1
npm run tauri -- android build --debug --target aarch64 --apk --ci`. Neither
build establishes working OS callback association or Vault access on a signed
physical device.

The Android API 35 arm64 emulator ran the preview APK. The `端末の鍵を確認`
action created or reopened the Android Keystore key and produced a DPoP proof;
Rust verified the signature against the public key returned by the plugin.
The check succeeded again after force-stopping and restarting the app. It does
not contact the OP or prove OAuth consent, App Link delivery, or hardware-backed
key storage on a physical device.

On 2026-09-30, a physical Pixel 10 Pro running Android 17 also passed the
key check, including after force-stopping and restarting the app. This was a
locally debug-signed preview APK, without a configured mobile client ID.
The device reported the callback domain as unverified (code 1024), so this
result establishes OS signing and Rust signature verification only. It does
not establish hardware backing, release signing, browser login, App Link
delivery, or Vault ciphertext access.

Later on 2026-09-30, the dedicated verification-signed release-mode APK with
the registered mobile client ID replaced the Pixel's debug installation.
Android reported the callback domain as `verified`; an implicit callback URL
intent reached the app without a forced component or manually approved
domain state. This confirms OS association and URL delivery. After unlocking,
ordinary login returned to the app and passed Rust's token validation twice,
including after native-session clearing. D1 confirmed two token issues with
PKCE; the first used an authentication context one second old, the second
reused that SSO. The Passkey prompt itself was not directly observed.
Force-stopping and reopening the app removed the in-memory logged-in state;
the Keystore signature check passed again after restart. Browser SSO was
preserved. Native Vault access/decryption, iPhone and remaining cancellation/
timeout/interception cases are still unqualified.
