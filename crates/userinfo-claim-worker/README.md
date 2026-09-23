# UserInfo recipient key boundary

This Worker holds the future UserInfo recipient's ML-KEM private seed binding. Its only current operation, `GET /internal/recipient-keys/{key_id}/verify`, reads the key directory from the OP's D1 database and the seed from Cloudflare Secrets Store. It derives the public key and SHA-256 key ID, then returns 204 only if both match the D1 row. Missing bindings, disabled keys, and mismatches fail closed. No key material is returned.

The [local config](wrangler.local.jsonc) has no secret binding and is used to test failure behavior. The [production config](wrangler.production.jsonc) binds the generation-1 secret and has `workers_dev: false`, disabled preview URLs, and no public route. The OP uses a service binding. Recipient envelopes, Grants, and claim release remain to be connected.

```sh
worker-build --release crates/userinfo-claim-worker
node --test local/conformance/userinfo-claim-worker.test.ts
cargo test --locked -p mikaki-userinfo-claim-worker
```

The offline [key generator](../../design/probes/pqc/src/bin/recipient_key.rs) creates a seed and public record. The [secret administration CLI](../../scripts/recipient-secret-admin.ts) checks the seed and provisions Secrets Store through standard input. The [key administration CLI](../../scripts/recipient-key-admin.ts) stages, verifies, activates, rotates, or immediately disables a key. Activation and rotation require the deployed claim Worker to verify every involved key through the [remote `USERINFO_CLAIMS` service binding](../worker/wrangler.recipient-admin.jsonc). Each state change has an actor and reason in `vault_recipient_key_audit`. Generation 1 is active in production; no recipient envelope or Grant is issued yet.
