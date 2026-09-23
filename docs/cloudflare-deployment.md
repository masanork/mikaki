# Cloudflare deployment

The normal-profile issuer is `https://mikaki.tossa.app`. Its Worker and D1 are configured in [`crates/worker/wrangler.production.jsonc`](../crates/worker/wrangler.production.jsonc). The production deployment defaults to `normal`; the conformance profile must use a different Worker, issuer, D1, and signing key.

The initial D1 migration, generation 1 runtime policy, and ES256 public signing key were applied on 2026-09-23. The signing private JWK is a Worker secret, not a repository file. The ignored local secret file is `local/generated/mikaki-production-secrets.json` and must remain mode 0600. Preserve it securely for future deployments or rotate the key with an overlapping public key before replacement.

The owner-only Vault uses the `mikaki-vault` R2 bucket, D1 migration `0002_vault_attribute_storage.sql`, and a daily UTC 03:00 cleanup trigger. Apply the migration before deploying a Worker with the R2 binding. The `/vault` page needs an existing SSO session and a PRF-capable passkey; it is not an account enrollment or recovery flow. Keep R2 public access disabled.

The bucket and migration were deployed on 2026-09-23. D1 migrations `0003_client_administration.sql` through `0006_session_validation_policy.sql` were applied, and the active runtime policy was moved to schema 5, generation 2, projection `0900d2cf091a3b06e8f07e8a7fcb1fc26dd99bb0701067c041bab8f05f7ea9b9`. Worker version `261b8697-c0a3-4b69-a248-55dbbb21a1b3` serves the Svelte 5 screens, Vault assets, RP redirect lifecycle, invitation-based Passkey enrollment, and client-authenticated session checks. Smoke checks returned 200 for health and Discovery, 302 from `/enroll` to its login transaction, 401 for unauthenticated `/admin`, and 400 for an incomplete `/session/check` request. Production still has no registered RP or account; an authenticated Vault write and PRF unlock have not been exercised. No bootstrap invitation has been issued yet.

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
