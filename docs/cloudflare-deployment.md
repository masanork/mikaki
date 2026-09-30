# Cloudflare deployment

The normal-profile issuer is `https://mikaki.tossa.app`. Its Worker and D1 are configured in [`crates/worker/wrangler.production.jsonc`](../crates/worker/wrangler.production.jsonc). The production deployment defaults to `normal`; the conformance profile must use a different Worker, issuer, D1, and signing key.

The initial D1 migration, generation 1 runtime policy, and ES256 public signing key were applied on 2026-09-23. The signing private JWK is a Worker secret, not a repository file. The ignored local secret file is `local/generated/mikaki-production-secrets.json` and must remain mode 0600. Preserve it securely for future deployments or rotate the key with an overlapping public key before replacement.

The owner-only Vault uses the `mikaki-vault` R2 bucket, D1 migration `0002_vault_attribute_storage.sql`, and a daily UTC 03:00 cleanup trigger. Apply the migration before deploying a Worker with the R2 binding. The `/vault` page needs an existing SSO session and a PRF-capable passkey; it is not an account enrollment or recovery flow. Keep R2 public access disabled.

The bucket and migration were deployed on 2026-09-23. D1 migrations `0003_client_administration.sql` through `0006_session_validation_policy.sql` were applied, and the active runtime policy was moved to schema 5, generation 2, projection `0900d2cf091a3b06e8f07e8a7fcb1fc26dd99bb0701067c041bab8f05f7ea9b9`. Worker version `261b8697-c0a3-4b69-a248-55dbbb21a1b3` introduced the Svelte 5 screens, Vault assets, RP redirect lifecycle, invitation-based Passkey enrollment, and client-authenticated session checks. Initial smoke checks returned 200 for health and Discovery, 302 from `/enroll` to its login transaction, 401 for unauthenticated `/admin`, and 400 for an incomplete `/session/check` request.

On 2026-09-24, Worker version `f960a316-18d9-42bf-9635-7ddfadd04462` added a PRF request during passkey registration and disabled Vault unlock until its record load completes. The deployment included `OP_PRIVATE_JWK`; health and Discovery returned 200 and anonymous `/vault` returned 401. A local Chromium test passed PRF-backed Vault creation, reload/unlock, and update. Production D1 then had one administrator account and credential; the bootstrap gate was closed. In Chrome, the administrator saved the requested display name through `/vault`, reloaded the page, and reopened the matching value with Touch ID. D1 showed an active `name` head at revision 1. The page was reloaded afterward so the value is no longer displayed. No production RP had been registered at that date. Cross-device restore and credential replacement remain unverified. Passkeys enrolled before the PRF request may not be usable for Vault.

Later on 2026-09-24, migration `0008_vault_attribute_sharing.sql` was applied and the claim Worker (`92adc947-4831-4adc-93b8-5b7bc7eaa175`) and OP Worker (`1a0ae130-64f0-4577-9c04-c25c12a850cf`) were deployed. The OP deployment included both `OP_PRIVATE_JWK` and `USERINFO_CLAIMS`. D1 confirmed `vault_share_policy.enabled=0`, a seven-day TTL, and zero Grants. The active recipient key passed the remote service-binding verification. `npm run probe:recipient-envelope` sent synthetic ciphertext through the product sender and live Claim Worker; the valid envelope returned 204, while a different account and modified ciphertext returned 503. The probe did not write D1 or R2. TLS handshakes to `mikaki.tossa.app` and `tossa.app` were reset before a certificate was received from this local network, including in Chrome. A [GitHub-hosted public smoke run](https://github.com/masanork/mikaki/actions/runs/35945106521) subsequently reached health, Discovery, and JWKS successfully. The local connection problem remains; use the [manual production smoke workflow](../.github/workflows/production-smoke.yml) to distinguish it from an issuer outage.

Migration `0009_vault_recipient_disable_grants.sql` was applied on 2026-09-24. It revokes active system Grants when their recipient key is disabled and reconciles older rows. D1 confirmed the trigger is installed while the sharing policy remains disabled with zero Grants. No Worker redeployment was needed for this D1-only change. A local workerd test covers key stop and owner re-sharing to a new generation; production key rotation and owner recovery were not performed.

Migration `0010_vault_claim_release.sql` was applied on 2026-09-24, followed by OP Worker version `dbe5e19f-4431-4a0c-9d4d-4f6d5a6ea036`. It adds a separate RP-specific `name` consent ledger and owner controls. D1 confirmed `vault_claim_release_policy.enabled=0`, a one-day TTL, and zero active releases. UserInfo still returns only `sub`; the release policy must stay disabled until `profile` scope, token binding, and claim retrieval are wired together.

On 2026-09-27, OP Worker version `553636c6-c309-4dd8-8882-962a43bee5a6` added a login cue whose colors use the current page and registered RP redirect URIs. The deploy included `OP_PRIVATE_JWK` and `USERINFO_CLAIMS`. Public checks returned 200 for health, Discovery, and `/login/login.js`. No production RP login transaction was exercised.

Later on 2026-09-27, OP Worker version `b2b65612-85bb-4a00-96ae-a129493e4fe3` added a browser-bound, roughly 20-second rolling cue for active login transactions. The deploy included `OP_PRIVATE_JWK` and `USERINFO_CLAIMS`. Public checks returned 200 for health, Discovery, and `/login/login.js`; `/login/cue` without a transaction returned 400. A production RP login transaction was not exercised.

OP Worker version `4046b879-ae02-4b7d-9600-b5dc01827ddf` added a public issuer entry page after the bare domain was found to return 404. The page explains that OIDC sign-in begins at a connected app and links invitation holders to `/enroll`. The deploy included `OP_PRIVATE_JWK` and `USERINFO_CLAIMS`. Public checks returned 200 for `/`, `/?lang=en`, `/login/login.css`, and `/health`; direct `/login` without a transaction still returned 400. No production RP login transaction was exercised.

Later on 2026-09-27, a narashi RP login exposed three pending production D1 migrations: `0011_issued_id_token_hash.sql`, `0012_client_logout_registration.sql`, and `0013_logout_outbox.sql`. The deployed token exchange writes `token_issue.id_token_hash`, so leaving `0011` unapplied could fail the code exchange. A D1 Time Travel bookmark was recorded before applying all three migrations. `wrangler d1 migrations list` then reported no pending migrations, and the client administration list confirmed narashi's active client, exact callback, and key. A fresh browser path reached the Mikaki login page from narashi; passkey completion and the RP callback still require an owner browser check.

## Current production snapshot (checked 2026-09-30)

The active production OP Worker is version `eeea96e0-12f6-4d14-993a-9b73e562e0e4`, activated on 2026-09-30 from clean source commit `193264893675098ffea9c9f1737c1f7c8e485de0` on draft PR [#28](https://github.com/masanork/mikaki/pull/28). The UserInfo Claim Worker was also updated to `381f73cf-94b2-4b1c-b7e7-28a35560cea3`. The active OP source descends from the account-page and Vault UI changes in PRs [#27](https://github.com/masanork/mikaki/pull/27) and [#29](https://github.com/masanork/mikaki/pull/29), so those changes are deployed. The [version-aware public smoke](https://github.com/masanork/mikaki/actions/runs/36683839335) checked the exact Worker version and source commit, health, Discovery, JWKS, authenticated readiness, and Android association. A [post-registration smoke](https://github.com/masanork/mikaki/actions/runs/36684240729) passed after the native client was added. These checks do not complete a Passkey login or RP callback.

Production D1 has no pending migrations through `0029` in the native-enabled source. A read-only count found one active web RP and one active native public client, excluding the internal enrollment client. The OP secret list contains `OP_PRIVATE_JWK` and `MIKAKI_READY_TOKEN`. Android App Links were verified on a signed Pixel test install, but external-browser Passkey completion and app return remain unverified. Native Vault OAuth is disabled. The [main CI run](https://github.com/masanork/mikaki/actions/runs/36680537354) passed, but current `main` does not contain the native Worker code, production config, or migrations `0014`–`0029`.

**Do not deploy current `main` to production.** Its older config would replace the native-enabled Worker, remove the callback Custom Domain and readiness binding, and leave a code/schema mismatch. Reconcile and qualify the native source on `main` before a new deployment. A migration list run from an old checkout only compares that checkout's migration files; “no migrations to apply” there does not mean its code matches the newer production schema.

Managed RP registration and key changes are described in [RP client operations](rp-client-operations.md). The first administrator and subsequent invitation flow is described in [account enrollment](account-enrollment.md). The managed RP lease contract is in [RP session check](rp-session-check.md).

## Deploy a reviewed commit

Run the following from the repository root, using an exact reviewed commit in a clean checkout that preserves the active native capabilities and schema. Record that commit and the current Worker version before changing production. The guards below must pass; they intentionally fail on current `main`. The commands use the repository-pinned Wrangler and production config. Set `MIKAKI_SECRETS_FILE` to the ignored local file or its absolute path when deploying from an isolated checkout; verify that it exists, contains both required secret names, and is mode 0600. Never commit or print the file or its values.

```sh
git status --short
git rev-parse HEAD
test -f crates/worker/migrations/0029_native_vault_token_context.sql
rg -q 'MIKAKI_READY_TOKEN' crates/worker/wrangler.production.jsonc
rg -q 'mikaki-native.tossa.app' crates/worker/wrangler.production.jsonc
MIKAKI_SECRETS_FILE=local/generated/mikaki-production-secrets.json
test -f "$MIKAKI_SECRETS_FILE"
npx wrangler deployments list --config crates/worker/wrangler.production.jsonc
npx wrangler d1 migrations list mikaki-op --config crates/worker/wrangler.production.jsonc --remote
```

Review any pending migration against the code and active Worker. Take and record a fresh D1 [Time Travel bookmark](https://developers.cloudflare.com/d1/reference/time-travel/) immediately before a migration. Apply migrations with the production config and `--remote` **only if** the list shows pending files, then confirm it is empty. Migrations change production D1 independently of the Worker and can affect the old version before the deploy.

```sh
npx wrangler d1 time-travel info mikaki-op --config crates/worker/wrangler.production.jsonc
# Only when the preceding list showed reviewed, pending migrations:
npx wrangler d1 migrations apply mikaki-op --config crates/worker/wrangler.production.jsonc --remote
npx wrangler d1 migrations list mikaki-op --config crates/worker/wrangler.production.jsonc --remote
```

Build and run a dry run from that same commit. Confirm the output lists D1, R2, service, issuer, version metadata, `OP_PRIVATE_JWK`, and `MIKAKI_READY_TOKEN` bindings, plus the native callback Custom Domain. A dry run checks the bundle and declared bindings, not remote secret correctness or runtime behavior.

```sh
design/probes/workers-rs/target/tools/bin/worker-build --release crates/worker
npx wrangler deploy --dry-run --config crates/worker/wrangler.production.jsonc \
  --secrets-file "$MIKAKI_SECRETS_FILE"
```

Deploy the same bundle with both secrets included in the **same** Worker version. Cloudflare documents [`--secrets-file`](https://developers.cloudflare.com/workers/configuration/secrets/) for uploading secrets alongside code. An earlier deployment without this flag omitted `OP_PRIVATE_JWK`; confirm both secret bindings appear in the deploy output and record the new version ID. Preserve the Claim Worker compatibility and callback-domain routing. Follow the native activation record on draft PR [#28](https://github.com/masanork/mikaki/pull/28) for version-matched readiness checks before activating another native-enabled version.

```sh
npx wrangler deploy --config crates/worker/wrangler.production.jsonc \
  --secrets-file "$MIKAKI_SECRETS_FILE"
npx wrangler deployments list --config crates/worker/wrangler.production.jsonc
```

Check public endpoints from a network that can reach the issuer. From this local network, TLS connections have reset before the certificate arrived; use the [manual production smoke workflow](../.github/workflows/production-smoke.yml) and save its run URL if that recurs. A passed public smoke check does not establish that login works.

```sh
curl -fsS https://mikaki.tossa.app/health
curl -fsS https://mikaki.tossa.app/.well-known/openid-configuration
curl -fsS https://mikaki.tossa.app/jwks
```

Before calling the rollout complete, run an owner-browser check on the intended device: start at the registered RP, complete the passkey transaction, confirm the callback and RP session, open and unlock the Vault with PRF, then exercise RP and OP logout and verify the session is rejected. Include both language and small-screen checks for the updated account and Vault pages. Record the commit, Worker version, migration state, smoke run, authenticated result, and any remaining failure. If the owner-browser check cannot run, record the deployment as **public-endpoint checked only**.

If the Worker fails, inspect the deployment and use the [Worker rollback procedure](https://developers.cloudflare.com/workers/versions-and-deployments/rollbacks/) with a version compatible with the current D1 schema. A Worker rollback does not restore D1. A D1 Time Travel restore overwrites the database in place; assess data loss and coordinate it separately before using the recorded bookmark. Neither rollback substitutes for checking the RP and Vault after recovery.

This deployment has no tested recovery path or fully verified production web or native RP flow. Do not treat its availability as a user-ready launch or an OIDF certification result.
