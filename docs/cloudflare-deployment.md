# Cloudflare deployment

The normal-profile issuer is `https://mikaki.tossa.app`. Its Worker and D1 are configured in [`crates/worker/wrangler.production.jsonc`](../crates/worker/wrangler.production.jsonc). The production deployment defaults to `normal`; the conformance profile must use a different Worker, issuer, D1, and signing key.

The initial D1 migration, generation 1 runtime policy, and ES256 public signing key were applied on 2026-09-23. The signing private JWK is a Worker secret, not a repository file. The ignored local secret file is `local/generated/mikaki-production-secrets.json` and must remain mode 0600. Preserve it securely for future deployments or rotate the key with an overlapping public key before replacement.

The owner-only Vault uses the `mikaki-vault` R2 bucket, D1 migration `0002_vault_attribute_storage.sql`, and a daily UTC 03:00 cleanup trigger. Apply the migration before deploying a Worker with the R2 binding. The `/vault` page needs an existing SSO session and a PRF-capable passkey; it is not an account enrollment or recovery flow. Keep R2 public access disabled.

The bucket and migration were deployed on 2026-09-23. D1 migrations `0003_client_administration.sql` through `0006_session_validation_policy.sql` were applied, and the active runtime policy was moved to schema 5, generation 2, projection `0900d2cf091a3b06e8f07e8a7fcb1fc26dd99bb0701067c041bab8f05f7ea9b9`. Worker version `261b8697-c0a3-4b69-a248-55dbbb21a1b3` introduced the Svelte 5 screens, Vault assets, RP redirect lifecycle, invitation-based Passkey enrollment, and client-authenticated session checks. Initial smoke checks returned 200 for health and Discovery, 302 from `/enroll` to its login transaction, 401 for unauthenticated `/admin`, and 400 for an incomplete `/session/check` request.

On 2026-09-24, Worker version `f960a316-18d9-42bf-9635-7ddfadd04462` added a PRF request during passkey registration and disabled Vault unlock until its record load completes. The deployment included `OP_PRIVATE_JWK`; health and Discovery returned 200 and anonymous `/vault` returned 401. A local Chromium test passed PRF-backed Vault creation, reload/unlock, and update. Production D1 now has one administrator account and credential; the bootstrap gate is closed. In Chrome, the administrator saved the requested display name through `/vault`, reloaded the page, and reopened the matching value with Touch ID. D1 showed an active `name` head at revision 1. The page was reloaded afterward so the value is no longer displayed. No production RP has been registered. Cross-device restore and credential replacement remain unverified. Passkeys enrolled before the PRF request may not be usable for Vault.

Later on 2026-09-24, migration `0008_vault_attribute_sharing.sql` was applied and the claim Worker (`92adc947-4831-4adc-93b8-5b7bc7eaa175`) and OP Worker (`1a0ae130-64f0-4577-9c04-c25c12a850cf`) were deployed. The OP deployment included both `OP_PRIVATE_JWK` and `USERINFO_CLAIMS`. D1 confirmed `vault_share_policy.enabled=0`, a seven-day TTL, and zero Grants. The active recipient key passed the remote service-binding verification. `npm run probe:recipient-envelope` sent synthetic ciphertext through the product sender and live Claim Worker; the valid envelope returned 204, while a different account and modified ciphertext returned 503. The probe did not write D1 or R2. TLS handshakes to `mikaki.tossa.app` and `tossa.app` were reset before a certificate was received from this local network, including in Chrome. A [GitHub-hosted public smoke run](https://github.com/masanork/mikaki/actions/runs/35945106521) subsequently reached health, Discovery, and JWKS successfully. The local connection problem remains; use the [manual production smoke workflow](../.github/workflows/production-smoke.yml) to distinguish it from an issuer outage.

Migration `0009_vault_recipient_disable_grants.sql` was applied on 2026-09-24. It revokes active system Grants when their recipient key is disabled and reconciles older rows. D1 confirmed the trigger is installed while the sharing policy remains disabled with zero Grants. No Worker redeployment was needed for this D1-only change. A local workerd test covers key stop and owner re-sharing to a new generation; production key rotation and owner recovery were not performed.

Migration `0010_vault_claim_release.sql` was applied on 2026-09-24, followed by OP Worker version `dbe5e19f-4431-4a0c-9d4d-4f6d5a6ea036`. It adds a separate RP-specific `name` consent ledger and owner controls. D1 confirmed `vault_claim_release_policy.enabled=0`, a one-day TTL, and zero active releases. UserInfo still returns only `sub`; the release policy must stay disabled until `profile` scope, token binding, and claim retrieval are wired together.

On 2026-09-27, OP Worker version `553636c6-c309-4dd8-8882-962a43bee5a6` added a login cue whose colors use the current page and registered RP redirect URIs. The deploy included `OP_PRIVATE_JWK` and `USERINFO_CLAIMS`. Public checks returned 200 for health, Discovery, and `/login/login.js`. No production RP login transaction was exercised.

Later on 2026-09-27, OP Worker version `b2b65612-85bb-4a00-96ae-a129493e4fe3` added a browser-bound, roughly 20-second rolling cue for active login transactions. The deploy included `OP_PRIVATE_JWK` and `USERINFO_CLAIMS`. Public checks returned 200 for health, Discovery, and `/login/login.js`; `/login/cue` without a transaction returned 400. A production RP login transaction was not exercised.

OP Worker version `4046b879-ae02-4b7d-9600-b5dc01827ddf` added a public issuer entry page after the bare domain was found to return 404. The page explains that OIDC sign-in begins at a connected app and links invitation holders to `/enroll`. The deploy included `OP_PRIVATE_JWK` and `USERINFO_CLAIMS`. Public checks returned 200 for `/`, `/?lang=en`, `/login/login.css`, and `/health`; direct `/login` without a transaction still returned 400. No production RP login transaction was exercised.

Later on 2026-09-27, a narashi RP login exposed three pending production D1 migrations: `0011_issued_id_token_hash.sql`, `0012_client_logout_registration.sql`, and `0013_logout_outbox.sql`. The deployed token exchange writes `token_issue.id_token_hash`, so leaving `0011` unapplied could fail the code exchange. A D1 Time Travel bookmark was recorded before applying all three migrations. `wrangler d1 migrations list` then reported no pending migrations, and the client administration list confirmed narashi's active client, exact callback, and key. A fresh browser path reached the Mikaki login page from narashi; passkey completion and the RP callback still require an owner browser check.

Managed RP registration and key changes are described in [RP client operations](rp-client-operations.md). The first administrator and subsequent invitation flow is described in [account enrollment](account-enrollment.md). The managed RP lease contract is in [RP session check](rp-session-check.md). Apply new migrations before deploying a Worker that queries new columns.

After modifying the Worker, build and deploy with the secret included in the **same** version:

```sh
design/probes/workers-rs/target/tools/bin/worker-build --release crates/worker
npx wrangler deploy --config crates/worker/wrangler.production.jsonc \
  --secrets-file local/generated/mikaki-production-secrets.json
```

The `--secrets-file` argument is required here. A deploy without it produced a version whose binding list omitted `OP_PRIVATE_JWK`. The current production config declares both `OP_PRIVATE_JWK` and `MIKAKI_READY_TOKEN` as required. Generate a separate 32-byte base64url monitoring token (`node -e "console.log(require('node:crypto').randomBytes(32).toString('base64url'))"`), place it alongside `OP_PRIVATE_JWK` in the ignored, mode-0600 secret JSON, and provision the identical value as the GitHub Actions repository secret `MIKAKI_READY_TOKEN` before using version-aware production smoke. Keep it out of `vars`, URLs, logs and release artifacts. Check the deployed binding inventory for both secret names before activation; if either value is missing or malformed, `/ready` fails closed. Rotate both copies together and rerun version-aware smoke.

Before deploying code that uses new D1 columns or tables, list and apply pending production migrations with the same production config and `--remote`. Confirm the list is empty afterward; a healthy `/health` response does not prove the token exchange schema is current.

```sh
npx wrangler d1 migrations list mikaki-op --config crates/worker/wrangler.production.jsonc --remote
npx wrangler d1 migrations apply mikaki-op --config crates/worker/wrangler.production.jsonc --remote
npx wrangler d1 migrations list mikaki-op --config crates/worker/wrangler.production.jsonc --remote
```

Smoke endpoints:

```sh
curl -fsS https://mikaki.tossa.app/health
curl -fsS https://mikaki.tossa.app/.well-known/openid-configuration
curl -fsS https://mikaki.tossa.app/jwks
```

After activating a version with the `CF_VERSION_METADATA` binding, fetch `/version` and compare its Cloudflare version ID and clean source commit with the activation record and verified release manifest. Check authenticated `/ready` for 204 before functional qualification; missing or incorrect bearer credentials receive 404 before dependency checks. Readiness checks policy, migration, signing-key alignment and essential bindings but cannot replace an actual Vault/RP flow. The [manual production smoke workflow](../.github/workflows/production-smoke.yml) accepts both expected values and retains the version/readiness comparison result. A response from `/version` identifies the running source revision, not the digest of the uploaded Worker bytes; record that mapping separately as described in [release and recovery](release-and-recovery.md). The currently deployed version predates both endpoints.

The recorded deployment has one administrator and an active narashi registration, but a completed RP callback, production logout delivery, and account recovery remain unverified. Do not treat its availability as a user-ready launch or an OIDF certification result.

## Local changes awaiting activation

The 2026-09-29 [Vault and account UI](product-ui-preview.md), additional Passkey/typed-note flows, agent/OAuth endpoints, and optional DPoP/PAR work originally had local evidence only. The 2026-09-30 native-client activation below deployed the committed OP code and applied migrations `0014`–`0029`. Intended-device PRF, completed RP callback/logout, agent user flows and native Vault unlock still require their separate qualification gates in [product quality](product-quality.md). Native Vault OAuth remains disabled.

The new [release inventory and recovery rehearsal](release-and-recovery.md) checks local archive/migration bytes and documents activation records, backup boundaries and historical authority reconciliation. It does not promote CI-built bytes, create a production backup or execute a restore. Keep actual Worker versions, preserved bindings and RP/device results tied to a reviewed activation record.

For a future attested release, use the [prepared upload directory](release-and-recovery.md) from the reusable build after trusted attestation verification. It contains both verified archives' pinned Wrangler dry-run bundles; verify that directory immediately before a reviewed `versions upload --no-bundle`. Record the returned version IDs and all bindings, then activate only the qualified versions. This path has local dry-run evidence only and has not changed the deployed Workers.

## Native public client activation, 2026-09-30

Following user approval, a clean checkout of commit
`193264893675098ffea9c9f1737c1f7c8e485de0` supplied OP version
`eeea96e0-12f6-4d14-993a-9b73e562e0e4` and Claim Worker version
`381f73cf-94b2-4b1c-b7e7-28a35560cea3`, both activated at 100% after
non-activating upload and binding inspection. A pre-update D1 Time Travel
bookmark was recorded; migrations 0014–0029 were applied and verified.
Account, credential, existing client and Vault-head counts were preserved,
with no foreign-key violations. Runtime policy generation 2 was preserved.
The signing secret was retained, and the new readiness token was provisioned
both to the OP version and GitHub Actions. The Claim Worker update supplies
the new OP's readiness dependency and retains its recipient Secret Store
binding. See [native activation](native-client-activation.md) for versions,
build hashes, public certificate and mobile registration audit operation.

`mikaki-native.tossa.app` is now a deployed Custom Domain. It publishes
Android association for the dedicated local device-verification signing
certificate. It does not serve OP endpoints or a browser fallback callback.
Apple association remains unconfigured. The mobile public client is active
with PKCE mandatory, no client secret and its exact HTTPS callback.
[Version-matched public smoke](https://github.com/masanork/mikaki/actions/runs/36683839335)
passed health, Discovery, JWKS, clean source/version identity, readiness 204
and Android association/callback-host isolation. No installed-app Passkey
completion, native app return or Vault ciphertext read is established by this
activation. [Post-registration smoke](https://github.com/masanork/mikaki/actions/runs/36684240729)
also confirmed that this mobile client reaches the OP's browser login using
S256 PKCE, without completing authentication or token exchange.
`MIKAKI_NATIVE_VAULT_OAUTH` remains unset.
