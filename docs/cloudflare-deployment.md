# Cloudflare deployment

The normal-profile issuer is `https://mikaki.tossa.app`. Its Worker and D1 are configured in [`crates/worker/wrangler.production.jsonc`](../crates/worker/wrangler.production.jsonc). The production deployment defaults to `normal`; the conformance profile must use a different Worker, issuer, D1, and signing key.

The initial D1 migration, generation 1 runtime policy, and ES256 public signing key were applied on 2026-09-23. The signing private JWK is a Worker secret, not a repository file. The ignored local secret file is `local/generated/mikaki-production-secrets.json` and must remain mode 0600. Preserve it securely for future deployments or rotate the key with an overlapping public key before replacement.

The owner-only Vault uses the `mikaki-vault` R2 bucket, D1 migration `0002_vault_attribute_storage.sql`, and a daily UTC 03:00 cleanup trigger. Apply the migration before deploying a Worker with the R2 binding. The `/vault` page needs an existing SSO session and a PRF-capable passkey; it is not an account enrollment or recovery flow. Keep R2 public access disabled.

The bucket and migration were deployed on 2026-09-23. D1 migrations `0003_client_administration.sql` through `0006_session_validation_policy.sql` were applied, and the active runtime policy was moved to schema 5, generation 2, projection `0900d2cf091a3b06e8f07e8a7fcb1fc26dd99bb0701067c041bab8f05f7ea9b9`. Worker version `261b8697-c0a3-4b69-a248-55dbbb21a1b3` introduced the Svelte 5 screens, Vault assets, RP redirect lifecycle, invitation-based Passkey enrollment, and client-authenticated session checks. Initial smoke checks returned 200 for health and Discovery, 302 from `/enroll` to its login transaction, 401 for unauthenticated `/admin`, and 400 for an incomplete `/session/check` request.

On 2026-09-24, Worker version `f960a316-18d9-42bf-9635-7ddfadd04462` added a PRF request during passkey registration and disabled Vault unlock until its record load completes. The deployment included `OP_PRIVATE_JWK`; health and Discovery returned 200 and anonymous `/vault` returned 401. A local Chromium test passed PRF-backed Vault creation, reload/unlock, and update. Production D1 now has one administrator account and credential; the bootstrap gate is closed. In Chrome, the administrator saved the requested display name through `/vault`, reloaded the page, and reopened the matching value with Touch ID. D1 showed an active `name` head at revision 1. The page was reloaded afterward so the value is no longer displayed. No production RP has been registered. Cross-device restore and credential replacement remain unverified. Passkeys enrolled before the PRF request may not be usable for Vault.

Later on 2026-09-24, migration `0008_vault_attribute_sharing.sql` was applied and the claim Worker (`92adc947-4831-4adc-93b8-5b7bc7eaa175`) and OP Worker (`1a0ae130-64f0-4577-9c04-c25c12a850cf`) were deployed. The OP deployment included both `OP_PRIVATE_JWK` and `USERINFO_CLAIMS`. D1 confirmed `vault_share_policy.enabled=0`, a seven-day TTL, and zero Grants. The active recipient key passed the remote service-binding verification. `npm run probe:recipient-envelope` sent synthetic ciphertext through the product sender and live Claim Worker; the valid envelope returned 204, while a different account and modified ciphertext returned 503. The probe did not write D1 or R2. TLS handshakes to `mikaki.tossa.app` and `tossa.app` were reset before a certificate was received from this local network, including in Chrome. A [GitHub-hosted public smoke run](https://github.com/masanork/mikaki/actions/runs/35945106521) subsequently reached health, Discovery, and JWKS successfully. The local connection problem remains; use the [manual production smoke workflow](../.github/workflows/production-smoke.yml) to distinguish it from an issuer outage.

Migration `0009_vault_recipient_disable_grants.sql` was applied on 2026-09-24. It revokes active system Grants when their recipient key is disabled and reconciles older rows. D1 confirmed the trigger is installed while the sharing policy remains disabled with zero Grants. No Worker redeployment was needed for this D1-only change. A local workerd test covers key stop and owner re-sharing to a new generation; production key rotation and owner recovery were not performed.

Managed RP registration and key changes are described in [RP client operations](rp-client-operations.md). The first administrator and subsequent invitation flow is described in [account enrollment](account-enrollment.md). The managed RP lease contract is in [RP session check](rp-session-check.md). Apply new migrations before deploying a Worker that queries new columns.

After modifying the Worker, build and deploy with the secret included in the **same** version:

```sh
design/probes/workers-rs/target/tools/bin/worker-build --release crates/worker
npx wrangler deploy --config crates/worker/wrangler.production.jsonc \
  --secrets-file local/generated/mikaki-production-secrets.json
```

The `--secrets-file` argument is required here. A deploy without it produced a version whose binding list omitted `OP_PRIVATE_JWK`. Check the deploy output for that binding before considering the update complete.

Smoke endpoints:

```sh
curl -fsS https://mikaki.tossa.app/health
curl -fsS https://mikaki.tossa.app/.well-known/openid-configuration
curl -fsS https://mikaki.tossa.app/jwks
```

This deployment has no recovery or registered production clients. Do not treat its availability as a user-ready launch or an OIDF certification result.
