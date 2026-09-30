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
and app-association behavior has not been tested in a signed installed app.
Wallet, NFC and PDS remain unimplemented. The icon is temporary and release
signing is not configured.

## Desktop setup

Apply the normal OP migrations through `0026_native_loopback_redirect.sql` and
register a public desktop client with a separate client ID, sector
`127.0.0.1`, and redirect URI `http://127.0.0.1:0/oidc/callback`. The operator
command and input format are in the architecture review. The client ID is
public but must match the registration. Set `MIKAKI_DESKTOP_CLIENT_ID` in the
build environment, then build from `src-tauri` with `cargo check` or the Tauri
CLI. The issuer is pinned to `https://mikaki.tossa.app`.

The desktop login requires an installed OP with the matching client
registration, a system browser, a Passkey, and a local loopback listener. A
successful compile or synthetic Worker test does not qualify the installed
flow. Test login, cancel/timeout, callback interception, wrong port/issuer,
second login, and process restart on each target desktop OS before release.

## Android and iPhone setup

Register a separate public mobile client with sector `mikaki.tossa.app` and
exact redirect URI `https://mikaki.tossa.app/oidc/native/callback`. Set its
public ID as `MIKAKI_MOBILE_CLIENT_ID` **when compiling the Rust app**. The
Tauri app identifier is `app.tossa.mikaki`. Configure the production Worker
with `MIKAKI_IOS_TEAM_ID` (the ten-character Apple Developer Team ID) and
`MIKAKI_ANDROID_SHA256_CERT_FINGERPRINT` (the colon-separated SHA-256
fingerprint of the Android distribution signing certificate). Each
`/.well-known/` association response is 404 until its corresponding valid
value is configured. It must be publicly reachable over HTTPS on
`mikaki.tossa.app`; redirects or a mismatched signing identity will prevent
the OS from delivering the callback.

The pending PKCE transaction lives only in app memory and expires after three
minutes. If the OS terminates the app during browser login, restart login;
an unpaired cold-start callback is ignored. Test actual App/Universal Link
delivery, Passkey authentication in the external browser, cancellation,
wrong and duplicate callback parameters, and app restart on signed Android
and iPhone builds. Compilation alone does not qualify this flow.

The generated iOS entitlement contains `applinks:mikaki.tossa.app`. A signed
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
