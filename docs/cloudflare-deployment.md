# Cloudflare deployment

The normal-profile issuer is `https://mikaki.tossa.app`. Its Worker and D1 are configured in [`crates/worker/wrangler.production.jsonc`](../crates/worker/wrangler.production.jsonc). The production deployment defaults to `normal`; the conformance profile must use a different Worker, issuer, D1, and signing key.

The initial D1 migration, generation 1 runtime policy, and ES256 public signing key were applied on 2026-09-23. The signing private JWK is a Worker secret, not a repository file. The ignored local secret file is `local/generated/mikaki-production-secrets.json` and must remain mode 0600. Preserve it securely for future deployments or rotate the key with an overlapping public key before replacement.

The owner-only Vault uses the `mikaki-vault` R2 bucket, D1 migration `0002_vault_attribute_storage.sql`, and a daily UTC 03:00 cleanup trigger. Apply the migration before deploying a Worker with the R2 binding. The `/vault` page needs an existing SSO session and a PRF-capable passkey; it is not an account enrollment or recovery flow. Keep R2 public access disabled.

The bucket and migration were deployed on 2026-09-23. D1 migrations `0003_client_administration.sql` and `0004_client_redirect_lifecycle.sql` were applied, and the active runtime policy was moved to schema 5, generation 2, projection `0900d2cf091a3b06e8f07e8a7fcb1fc26dd99bb0701067c041bab8f05f7ea9b9`. Worker version `40dcdda1-a8de-46a4-b0c4-64b003a66b88` serves the Svelte 5 screens, Vault assets, and RP redirect lifecycle. Smoke checks returned 200 for health, Discovery, JWKS and login JS, while unauthenticated `/vault` returned 401. Production still has no registered RP or account; an authenticated Vault write and PRF unlock have not been exercised.

Managed RP registration and key changes are described in [RP client operations](rp-client-operations.md). The first administrator and subsequent invitation flow is described in [account enrollment](account-enrollment.md). Apply new migrations before deploying a Worker that queries new columns.

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
