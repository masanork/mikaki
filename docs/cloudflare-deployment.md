# Cloudflare deployment

The normal-profile issuer is `https://mikaki.tossa.app`. Its Worker and D1 are configured in [`crates/worker/wrangler.production.jsonc`](../crates/worker/wrangler.production.jsonc). The production deployment defaults to `normal`; the conformance profile must use a different Worker, issuer, D1, and signing key.

The initial D1 migration, generation 1 runtime policy, and ES256 public signing key were applied on 2026-09-23. The signing private JWK is a Worker secret, not a repository file. The ignored local secret file is `local/generated/mikaki-production-secrets.json` and must remain mode 0600. Preserve it securely for future deployments or rotate the key with an overlapping public key before replacement.

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

This deployment serves protocol endpoints but has no self-service account enrollment, recovery, or registered public clients. Do not treat its availability as a user-ready launch or an OIDF certification result.
