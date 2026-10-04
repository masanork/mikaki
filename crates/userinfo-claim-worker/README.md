# UserInfo recipient boundary

This private Rust Worker holds the UserInfo recipient ML-KEM seed in Secrets Store. It implements recipient-key verification, envelope validation, readiness and consented name decryption. The OP calls it through `USERINFO_CLAIMS`; it has no public route or preview URL.

The production configuration has no D1 or R2 binding. `CLAIM_STORE` selects eligible ciphertext and metadata through the OP's named `ClaimStore` entrypoint. A conditional disclosure audit repeats live authorization after decryption, so changed consent/head/session/key state prevents release. The private seed never leaves this Worker. Missing bindings, invalid envelopes, disabled keys, secret mismatches and failed audit fail closed.

The local fixture configuration explicitly enables `MIKAKI_LEGACY_CLAIM_STORE=local-test` for direct test storage. The positive live-secret suite runs the new service boundary with no downstream storage bindings. Requests are read with streaming size bounds. This isolates storage authority, not plaintext: the recipient and OP temporarily see an approved disclosed name, and the RP receives that plaintext.

```sh
worker-build --release crates/worker
worker-build --release crates/userinfo-claim-worker
worker-build --release -d build-conformance crates/userinfo-claim-worker --features conformance-gate
node --test local/conformance/userinfo-claim-worker.test.ts local/conformance/userinfo-live-secret.test.ts local/conformance/service-boundaries.test.ts
cargo test --locked -p mikaki-userinfo-claim-worker
```

The conformance build's pause hook tests revocation during decryption and must never enter a release artifact. Offline seed generation and administration are described in [recipient-key lifecycle](../../docs/vault-recipient-key-lifecycle.md). Generation 1 is provisioned in production; system/RP sharing policies remain disabled in recorded deployment evidence. Local success does not qualify production owner approval or profile delivery. See [service ownership/rollout](../../docs/adr/0015-service-data-ownership.md) and [architecture](../../docs/architecture.md).
