# UserInfo recipient key boundary

This Worker holds the future UserInfo recipient's ML-KEM private seed binding. Its only current operation, `GET /internal/recipient-keys/{key_id}/verify`, reads the key directory from the OP's D1 database and the seed from Cloudflare Secrets Store. It derives the public key and SHA-256 key ID, then returns 204 only if both match the D1 row. Missing bindings, disabled keys, and mismatches fail closed. No key material is returned.

The [local config](wrangler.local.jsonc) has no secret binding and is used to test failure behavior. The [deployment template](wrangler.example.jsonc) needs the OP D1 ID, Secrets Store ID, and per-key secret name. It has `workers_dev: false` and no public route. The OP service binding, activation, recipient envelopes, Grants, and claim release are still to be connected. Do not deploy the template with placeholder IDs or activate a key yet.

```sh
worker-build --release crates/userinfo-claim-worker
node --test local/conformance/userinfo-claim-worker.test.mjs
cargo test --locked -p mikaki-userinfo-claim-worker
```

The offline [key generator](../../design/probes/pqc/src/bin/recipient_key.rs) creates a seed and public record. The [admin CLI](../../scripts/recipient-key-admin.mjs) validates that public record before staging it in D1, and can immediately disable a key. Each write has an actor and reason in `vault_recipient_key_audit`. It deliberately has no activation operation; that requires a successful verification through the deployed service binding.
