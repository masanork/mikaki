# Native client activation checkpoint

Status: production OP/schema/mobile registration activated on 2026-09-30.
Signed Android ordinary OIDC app return and token validation are verified.
Fresh Passkey prompt observation and the remaining negative/device cases
are separate qualification steps.

## Activation result

The user approved this activation after reviewing the prepared checkpoint.
Migrations 0014–0029 were applied; no pending migration remains. Before and
after the update, D1 contained one account, one credential, three existing
clients and one Vault head. `PRAGMA foreign_key_check` returned no violations.
The active runtime policy remains schema 5, generation 2, projection
`0900d2cf091a3b06e8f07e8a7fcb1fc26dd99bb0701067c041bab8f05f7ea9b9`.
The pre-update D1 Time Travel bookmark is recorded in ignored
`local/generated/native-activation-before.json`. A historical DB restore is
not a safe code rollback by itself.

A separate clean checkout of commit
`193264893675098ffea9c9f1737c1f7c8e485de0` supplied the build. Its OP code is
unchanged from the successful [CI run for 6706cf1](https://github.com/masanork/mikaki/actions/runs/36680440787).
Both Workers were uploaded as non-active versions and their bindings were
inspected before 100% activation:

| Worker | Previous version | Activated version |
| --- | --- | --- |
| OP | `4046b879-ae02-4b7d-9600-b5dc01827ddf` | `eeea96e0-12f6-4d14-993a-9b73e562e0e4` |
| UserInfo Claim | `92adc947-4831-4adc-93b8-5b7bc7eaa175` | `381f73cf-94b2-4b1c-b7e7-28a35560cea3` |

The Claim Worker update supplies the readiness endpoint required by the new
OP. Its existing DB and Secret Store recipient binding were preserved, with
the current Vault R2 and issuer bindings added. Its remote service readiness
returned 204. The OP preserves DB, Vault R2, UserInfo service and signing-key
bindings, with version metadata and the new monitoring token. That token was
also provisioned to GitHub Actions without logging its value.

The callback Custom Domain and existing Cron schedules were applied with
`wrangler triggers deploy`. The Android certificate below is now configured
on the OP and persisted in the production config. Apple association is still
unconfigured. `MIKAKI_NATIVE_VAULT_OAUTH` remains unset.

[Public smoke](https://github.com/masanork/mikaki/actions/runs/36683839335)
passed health, Discovery, JWKS, the exact OP version/clean source commit,
authenticated readiness 204, the exact Android association JSON, and
callback-host isolation (callback and `/authorize` both 404, no-store and
no-referrer on the callback). This is public-host evidence, not Android OS
domain-verification or app-return evidence.

The public mobile registration was applied with audit operation
`36cf6290-2727-4823-9039-5175d41f783e`. Readback confirms active revision 1,
`client_type=native`, `auth_method=none`, `allow_missing_pkce=0` and the exact
active callback. Existing web client activity flags were preserved.

[Post-registration public smoke](https://github.com/masanork/mikaki/actions/runs/36684240729)
also passed. An unauthenticated request using this mobile registration,
`scope=openid` and S256 PKCE reached the OP's same-origin `/login?tx=...`
with a 302 response. It did not authenticate a user or exchange an OAuth
code; the synthetic browser login transaction expires normally.

Build-output SHA-256 inventory for these uploads:

| Input | SHA-256 |
| --- | --- |
| OP `build/index.js` | `e41e15f50eb2c6807f76414f6c96764cb7aa0e113f0f90adc5c5459f01862485` |
| OP `build/index_bg.wasm` | `18bc0eea51060704ae596371f7a8b98ab43ebf4679ae5d7800e655139ad890bc` |
| Claim `build/index.js` | `9b2cbdcaa5f92c48a89ad40db8ed11c98ffbde1379ca1feceecc8bc39f2d8406` |
| Claim `build/index_bg.wasm` | `3f3ab6a96c8a9aa431a69f59017a6931952454f7c392c9dda0031fd9dbf72615` |

Wrangler bundled these inputs during upload. These hashes identify the local
build outputs, not an independent attestation of remotely served bytes.

## Recorded production state before activation

Read-only Wrangler inspection found OP version
`4046b879-ae02-4b7d-9600-b5dc01827ddf` active, created on 2026-09-27.
Production D1 has migrations through `0013_logout_outbox.sql`;
`0014_agent_delegation.sql` through `0029_native_vault_token_context.sql`
are pending. Native registration therefore cannot be applied to the current
schema. The version has `OP_PRIVATE_JWK`, DB, Vault R2 and the UserInfo Claim
Worker binding. It predates version/readiness endpoints.

At preflight, the local production secret file was mode 0600 and contained
the signing key but not the required `MIKAKI_READY_TOKEN`. Preserve the
signing key. Provision a fresh monitoring token in that ignored file and
the GitHub Actions secret before uploading the new OP version. Never print
the values or place them in command arguments.

The existing [migration recovery rehearsal](../scripts/migration-recovery.test.ts)
passed an upgrade from schema 0013 through all 29 migrations, with synthetic
account, credential, session and encrypted Vault data. It checks integrity,
preservation of existing records, and restore boundaries. This is SQLite
evidence; it is not an applied remote D1 migration or a production backup.

## Public mobile registration

[mobile-client-registration.json](../apps/mikaki-client/mobile-client-registration.json)
reserves public client ID `dfd936fd-f33d-4f82-ae39-f25e08ec7948`, sector
`mikaki-native.tossa.app`, and exactly
`https://mikaki-native.tossa.app/oidc/native/callback`. The operator CLI
validated the file with `--apply no` before the audited activation above.
The app is the public RP. This registration requires no client secret or app
backend. It is separate from a user's Passkey enrollment.

After the reviewed OP/schema activation:

```sh
node scripts/client-admin.ts \
  --config crates/worker/wrangler.production.jsonc --remote yes \
  --action register-native \
  --input apps/mikaki-client/mobile-client-registration.json \
  --actor masanork --reason 'Qualify installed Mikaki mobile OIDC client' \
  --apply yes
```

Check the registration inventory before applying to avoid duplicating an
already completed operation. Registration is intentionally not an upsert.

## Android signing

The Android Gradle project accepts the ignored
`apps/mikaki-client/src-tauri/gen/android/keystore.properties`:

```properties
storeFile=/absolute/path/to/private/mikaki-keystore.jks
keyAlias=mikaki
password=<private keystore and key password>
```

Use mode 0600. The keystore and properties must remain outside Git and public
artifacts. The configuration uses the same password for the store and key,
following [Tauri's Android signing procedure](https://v2.tauri.app/distribute/sign/android/).
Missing properties leave release output unsigned; incomplete existing
properties fail configuration. Debug builds retain the local debug identity.
Verify the final APK with `apksigner verify --print-certs` before installing
or publishing its fingerprint. If distributing through Play App Signing,
use the certificate of the APK delivered to users for App Links.

Use a dedicated signed verification APK or the intended distribution key
for the callback association. The previous Pixel APK used a local debug
certificate whose fingerprint was not published. Following user approval,
that installation and its local DPoP key were removed for the signed APK
transition below.

A dedicated verification keystore was created at the ignored
`local/generated/mikaki-android-verification.jks`, with mode 0600. The ignored
signing properties are also mode 0600. This is a local device-test identity,
not a chosen Play distribution identity. Its public certificate fingerprint is:

```text
FC:51:38:FE:5C:6E:05:55:AD:08:5E:4D:68:DA:F9:DB:F6:76:93:63:1E:72:C9:41:A1:7D:17:80:0D:EB:00:66
```

Back up the private keystore and its password securely before depending on
this identity. The certificate is now in the production association.

The signed arm64 release-mode verification APK built successfully with
`MIKAKI_MOBILE_CLIENT_ID=dfd936fd-f33d-4f82-ae39-f25e08ec7948` and
`MIKAKI_NATIVE_VAULT_PREVIEW=1`. Output:
`apps/mikaki-client/src-tauri/gen/android/app/build/outputs/apk/universal/release/app-universal-release.apk`.
It is 17,365,928 bytes, with SHA-256
`6ee6a6db479c766e1a954a288b27163ed0e544a8a93b01a1da09d07b79f19210`.
`apksigner verify --print-certs` passed with the certificate above; the APK
manifest is not debuggable and the arm64 library contains the selected client
ID. It was subsequently installed on the Pixel after removing the differently
signed debug installation. Android reported the domain as `verified` and
listed this app as a verified owner. A normal implicit `ACTION_VIEW` request
for the callback URL, without OAuth parameters or a forced component,
delivered the intent to `app.tossa.mikaki/.MainActivity`. This qualifies OS
association and URL delivery; it is not a completed browser OAuth callback.
After the owner unlocked the phone, the installed app's login action returned
to the app and displayed `ログインしました。` twice, including after explicit
native-session clearing. This phase is reached only after callback
state/issuer validation, S256 PKCE code exchange and signed ID Token/nonce/
access-token-hash validation in Rust. D1 aggregation confirmed two token
issues for this native client and a 43-character PKCE challenge; no token,
code, subject, account identifier or SSO secret was retrieved for this check.
The SSO authentication context was one second old at the first issue and
121 seconds old at the second. This supports initial fresh authentication
followed by SSO reuse. The operator did not directly observe the Passkey
selection/biometric prompt, so that ceremony's UI/device path is not separately
qualified by these screenshots.

The native session-clear action displayed its success message; after another
successful login, force-stopping and reopening the app showed no logged-in
session. The verification APK's Android Keystore DPoP signature check
succeeded before and after the process restart. This does not prove hardware
backing, Vault API access or PRF decryption. Browser SSO was preserved.
The phone's 30-second screen-off timeout was temporarily extended to five
minutes during the test and restored to 30 seconds afterward. Device temporary
screenshots were removed; no device serial or personal screen was committed.

Signed iPhone, fresh Passkey prompt observation, cancellation/timeout and
interception cases, native Vault consent/read/unlock and card reading remain
separate gates. Release build mode here does not mean the experimental app is
qualified for distribution.

## Reviewed activation order

1. Select a clean committed source revision with successful CI. Keep separate
   working-tree UI changes out of the activation build. Record the exact
   commit, bundle hashes, secrets/service bindings, and previous version.
2. Record a D1 Time Travel bookmark and inspect schema/authority inventory.
   Apply and verify migrations 0014–0029 as a reviewed production operation.
   This includes agent and Vault schema updates, beyond client registration.
3. Prepare a non-activating Worker version upload with the preserved signing
   secret, readiness secret and existing bindings. Validate runtime policy
   compatibility and record the returned version ID before activation.
4. Publish `mikaki-native.tossa.app` and set
   `MIKAKI_ANDROID_SHA256_CERT_FINGERPRINT` to the selected APK certificate.
   Verify the exact HTTPS assetlinks response without redirects. Configure
   Apple association separately when a Team ID and signed device build exist.
5. Activate the reviewed OP version, verify version-matched public/readiness
   smoke and the existing RP path, then apply the mobile registration above.
6. Build with `MIKAKI_MOBILE_CLIENT_ID=dfd936fd-f33d-4f82-ae39-f25e08ec7948`.
   Check Android reports the domain as **verified**, then exercise external
   browser Passkey login, app return, token validation, cancellation, timeout
   and restart. Manual link selection is not domain-verification evidence.

Keep `MIKAKI_NATIVE_VAULT_OAUTH` unset in production. The first activation
qualifies ordinary OIDC login. Native Vault consent identity, PRF/envelope
unlock, iPhone device tests and card reading have separate remaining gates.

Use [release and recovery](release-and-recovery.md) for activation records and
compatible code rollback. Do not restore historical D1 authority merely to
roll back a Worker version.

## Android App Links recovery observed on 2026-10-01

On the signed Pixel build, a fresh Passkey attempt opened Android's biometric
prompt, but Chrome then showed the HTTPS callback as `not found` and the app
stayed on its waiting screen. `pm get-app-links --user 0 app.tossa.mikaki`
reported the domain as `verified` while its **user selection was Disabled**.
Verification alone therefore did not establish that this user would open the
callback in the app. After enabling the `mikaki-native.tossa.app` selection,
another fresh login returned to the app and displayed `ログイン済み`. Cancelling
the orphaned pending login returned the app to its signed-out welcome screen.

For a user, open Android Settings → Apps → mikaki → Open by default, enable
supported links and select `mikaki-native.tossa.app`, then cancel the pending
app login and retry. For device qualification, inspect both the domain state
and user selection with:

```sh
adb shell pm get-app-links --user 0 app.tossa.mikaki
```

The source now redirects a callback that reaches the browser to a fixed,
query-free recovery page with no-store and no-referrer headers. This fallback
is **not deployed** in the active production Worker. It must be reviewed and
activated from a clean commit before claiming browser recovery is available.
Do not copy a callback URL, authorization code, state, or token into an issue,
log, screenshot, or support request.
