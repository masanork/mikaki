# Local development

The local runner demonstrates a disposable end-to-end slice: invitation enrollment, a discoverable passkey, OIDC Authorization Code with PKCE S256, an RP session, and logout. It is not the production Worker. The more detailed [local harness record](../local/README.md) describes its implementation and test boundaries.

## Prerequisites

- Node.js matching [.node-version](../.node-version)
- Rust matching [rust-toolchain.toml](../rust-toolchain.toml)
- Python 3.14
- `wasm-pack` 0.15.0
- A browser that treats loopback HTTP as a secure context for WebAuthn

## Run the flow

```sh
npm ci
npm run build
npm run dev
```

Open `http://127.0.0.1:18878` and enter the bootstrap invitation printed by the runner. The local OP uses `http://localhost:18877`; the different hosts keep their cookies separate. The runner creates fresh keys and databases each time. A passkey registered during an earlier run cannot authenticate against the new database.

The bootstrap invitation lasts 15 minutes and can be used once. The runner does not expose a public bootstrap endpoint. Keep this loopback configuration local; its browser secure-context treatment does not apply to arbitrary HTTP origins.

## Checks

```sh
cargo test --workspace
npm run test:e2e
npm run check:node
npm run check:ui
npm run check:i18n
```

The local runner's TypeScript OP adapter, test RP, D1 fixtures, and generated configuration are verification tools. They do not establish that the production Rust Worker has passed the same browser flow. For the exact deployed capabilities and test results, see [status](status.md). For code organization and review expectations, see [contributing](contributing.md).
