# ES256, JOSE, and local D1 probes

These are isolated technical probes, not product code. The ES256 private key comes from a public RFC test vector; account, client, and token values are synthetic. Statements about work “not implemented” in the original 2026-09-22 probe applied to the probe at that time, not the later [Rust Worker](../../docs/status.md). ML-KEM and ML-DSA experiments live separately in [`pqc/`](pqc/).

## workers-rs adapter probe

[`workers-rs/`](workers-rs/) is a Rust Worker proof of concept using `worker 0.8.6`. Under local Wrangler/workerd it exercised async fetch, D1 batch rollback and `FirstPrimary` reads, one-winner concurrent code exchange, Workers WebCrypto CSPRNG feeding Rust OIDC code preparation, and async ES256 signing.

An additional RS256 case checked a synthetic 2048-bit RSA key in Rust, imported a nonextractable private JWK into Workers WebCrypto, signed an ID Token, and verified the JWS with the Rust/Wasm [`jose-custom`](jose-custom/) verifier. A modified signature was rejected. The Node test process generates keys at runtime and passes them only to the local Worker. No remote D1 or Cloudflare account is used.

From the repository root, with worker-build 0.8.6, wasm32 target, and probe npm dependencies:

```sh
cargo build --locked --manifest-path design/probes/workers-rs/Cargo.toml --target wasm32-unknown-unknown
worker-build --release design/probes/workers-rs
worker-build --release crates/worker
wasm-pack build design/probes/jose-custom --target nodejs --release --out-dir pkg -- --locked
node design/probes/workers-rs/test.ts
node design/probes/workers-rs/token-exchange.ts
node design/probes/workers-rs/secret-auth.ts
cargo audit --file design/probes/workers-rs/Cargo.lock
```

`token-exchange.ts` needs `local/generated/worker-policy.json` from `npm run build:policy`. It builds isolated D1, activates a policy, seeds synthetic client/session rows, and tests fail-closed preactivation, revision changes, stale/concurrent activation rejection, authorization through `private_key_jwt` token exchange and UserInfo, replay revocation, and concurrent exchange with one winner. `secret-auth.ts` checks profile-specific Discovery, two Basic and one Post secret client, normal-profile rejection, wrong/mixed methods, cross-client binding, replay, revision enforcement, and per-client secret-attempt limits. Secrets and signing keys are generated in memory.

By 2026-09-23 those local D1, signing, and CSPRNG/code-preparation checks passed. Cargo audit reported no advisory among the 93 locked probe crates. An earlier optimized probe `index_bg.wasm` measured 321,262 bytes raw and 104,541 gzip, before the RS256 addition. It is not a full-Worker size or cold-start measurement. `FirstPrimary` on local workerd confirms the API path, not production replica freshness. Remaining gates are in [ADR 0009](../../docs/adr/0009-rust-oidc-and-worker-stack.md).

## Environment and repeatable commands

The 2026-09-22 baseline ran on macOS arm64 with Rust 1.98.1, Node 26.9.0, and wasm-pack 0.15.0. It pinned p256 0.14.0, wasm-bindgen 0.2.128, jose 6.2.12, and Wrangler 4.136.2. That Wrangler bundled workerd 1.20260921.1 and Miniflare 5.20260921.0-alpha; local compatibility does not establish remote D1 equivalence.

```sh
npm ci --prefix design/probes
cargo test --locked --manifest-path design/probes/es256/Cargo.toml
cargo build --locked --manifest-path design/probes/es256/Cargo.toml --bin fixture
wasm-pack build design/probes/es256 --target nodejs --release --out-dir pkg -- --locked
npm run test:crypto --prefix design/probes
npm run test:crypto:workers --prefix design/probes
npm run test:d1 --prefix design/probes
cargo clippy --locked --manifest-path design/probes/es256/Cargo.toml --all-targets -- -D warnings
cargo audit --file design/probes/es256/Cargo.lock
```

wasm-pack may fetch a matching wasm-bindgen tool. D1 tests use Wrangler `getPlatformProxy` with `remoteBindings=false` and `persist=false`; they create fresh local databases, requiring localhost interprocess communication and local Wrangler logs. They do not create remote databases or deploy. The fixed [SQL design model](../sql/oidc-critical-schema.sql) is adapted for D1 `bind` by a narrow helper, not a general SQL parser. The probe's HTTP entry originally returned 404 rather than exposing test signing or DB operations.

The baseline recorded 3/3 native ES256 checks, 6/6 Wasm/Node JOSE checks, and 6/6 local D1/workerd checks. They covered RFC 6979, altered signatures, raw versus DER forms, issuer/audience/expiry and algorithm rejection, one-winner exchange, zero-row guards, rollback, and revoked or unissued sid rejection. Cargo audit found no advisory in 54 locked Rust dependencies and npm audit found none in 37 packages at that time. The isolated ES256 Wasm was 82,464 bytes raw and 33,952 gzip, excluding glue, JOSE, and product authentication code.

## Interpretation and JOSE comparison

The baseline showed that p256 ES256 signing can feed the chosen JOSE boundary under those test conditions. It did not settle product JOSE library choice, claim validation, secret custody, timing properties, load behavior, browser passkeys, or OP conformance. Node WebCrypto results do not equal Workers or browser results; local D1 rollback does not prove remote replica freshness. Never copy the public test private key or fixture-only signing helpers into product code.

The isolated [`jose/`](jose/) crate evaluated jsonwebtoken 11.1.0 native/Wasm APIs. Wasm needed target-scoped `getrandom 0.2` `js`. Its lockfile held 87 crates and had no advisory at the recorded check. Node jose/WebCrypto generated synthetic keys; 18 shared native/Wasm cases covered ES256/RS256, async WebCrypto JWS handoff, key/algorithm/tamper rejection, rotation, issuer/audience/expiry, missing claims, duplicate `sub`, and malformed JWK/token. This was a probe claim type, not Mikaki's OIDC implementation. Private-key Rust signing and an injected time source were not verified.

The built-in RustCrypto-backed JOSE Wasm was 637,956 bytes raw and 253,443 gzip. In 10,000 local operations with JWK parsing on each call, native/Wasm ES256 verification was about 214/690 µs and RS256 about 109/461 µs. These are not product forecasts or cached-key measurements; the feature includes RSA and other bundled cryptography. Audit alone does not authorize RSA private-key signing given the known timing advisory.

The [`jose-custom/`](jose-custom/) variant disabled the built-in crypto backend and supplied ES256/RS256 verification providers. It accepted independent tokens and rejected the same negative cases. Its probe converted RSA JWK n/e to PKCS#1 DER because the chosen API did not expose those fields to the custom provider. Wasm measured 307,963 bytes raw and 120,871 gzip, about 52% less raw than the built-in variant. Native/Wasm local verification was about 216/681 µs ES256 and 228/417 µs RS256, also including repeated key conversion.

Node and then local workerd used asynchronous WebCrypto signing over JWS signing input, assembled a compact JWS through the public `jsonwebtoken::jws::Jws` structure, and passed it to native/Wasm verification. Payload modification was rejected. This demonstrates a possible async signing boundary without synchronous `JwtSigner`; it does not verify persistent KMS binding, production key formats, or operational failure handling.
