# Native client activation checkpoint

Status: prepared locally on 2026-09-30; no production mutation performed.

## Recorded production state

Read-only Wrangler inspection found OP version
`4046b879-ae02-4b7d-9600-b5dc01827ddf` active, created on 2026-09-27.
Production D1 has migrations through `0013_logout_outbox.sql`;
`0014_agent_delegation.sql` through `0029_native_vault_token_context.sql`
are pending. Native registration therefore cannot be applied to the current
schema. The version has `OP_PRIVATE_JWK`, DB, Vault R2 and the UserInfo Claim
Worker binding. It predates version/readiness endpoints.

The local production secret file is mode 0600 and contains the signing key,
but does not yet contain the required `MIKAKI_READY_TOKEN`. Preserve the
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
validated the file with `--apply no`; no client row has been written.
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
for the callback association. The currently installed Pixel APK uses a local
debug certificate; its fingerprint has not been published. A differently
signed APK cannot update that install. Removing it would delete its local
DPoP key; review that device transition before uninstalling.

A dedicated verification keystore was created at the ignored
`local/generated/mikaki-android-verification.jks`, with mode 0600. The ignored
signing properties are also mode 0600. This is a local device-test identity,
not a chosen Play distribution identity. Its public certificate fingerprint is:

```text
FC:51:38:FE:5C:6E:05:55:AD:08:5E:4D:68:DA:F9:DB:F6:76:93:63:1E:72:C9:41:A1:7D:17:80:0D:EB:00:66
```

Back up the private keystore and its password securely before depending on
this identity. The certificate has not been added to the production association.

The signed arm64 release-mode verification APK built successfully with
`MIKAKI_MOBILE_CLIENT_ID=dfd936fd-f33d-4f82-ae39-f25e08ec7948` and
`MIKAKI_NATIVE_VAULT_PREVIEW=1`. Output:
`apps/mikaki-client/src-tauri/gen/android/app/build/outputs/apk/universal/release/app-universal-release.apk`.
It is 17,365,928 bytes, with SHA-256
`6ee6a6db479c766e1a954a288b27163ed0e544a8a93b01a1da09d07b79f19210`.
`apksigner verify --print-certs` passed with the certificate above; the APK
manifest is not debuggable and the arm64 library contains the selected client
ID. It has not been installed on the Pixel and does not establish working
browser login or callback association. Release build mode here does not mean
the experimental app is qualified for distribution.

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
