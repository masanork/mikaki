---
type: article
profile: sorane-okf/0.1
title: 'Run a local RP integration example with mikaki'
description: 'Start the Helpdesk relying party locally and exercise passkey registration, OIDC login, PKCE, private_key_jwt, session revocation and logout.'
lang: en
translation_key: integration-example
updated: 2026-10-03
---

Use the existing [Helpdesk RP](https://github.com/masanork/mikaki/tree/main/crates/helpdesk-rp) as an executable integration example. This small Rust/Wasm and Worker application has login and protected pages. **It connects to a disposable local OP, not a registered public IdP client or a production support service.**

## Prepare and start

Use the Node and Rust versions pinned in [.node-version](https://github.com/masanork/mikaki/blob/main/.node-version) and [rust-toolchain.toml](https://github.com/masanork/mikaki/blob/main/rust-toolchain.toml). Install the Rust Wasm target and wasm-pack as described in [development setup](https://github.com/masanork/mikaki/blob/main/docs/getting-started.md).

```sh
git clone https://github.com/masanork/mikaki.git
cd mikaki
npm ci
npm run build
npm run dev:helpdesk
```

The build generates policy, browser Wasm, Helpdesk Wasm and UI. Building only the RP Wasm leaves the OP UI assets missing.

Open `http://127.0.0.1:18878`; the OP is `http://localhost:18877`. Keep these ports free and do not interchange the hostnames: the setup uses distinct origins. The runner prints a single-use invitation valid for 15 minutes.

## Exercise the first login

1. Press the RP login button and follow the redirect to the local OP.
2. Register using the invitation and a browser supporting discoverable passkeys.
3. Confirm the callback returns to the protected tickets page.
4. Create, reply to and close a synthetic ticket. Ticket text is plaintext in the RP D1 database.
5. Try RP logout. It clears the application cookie/session separately from ending OP SSO.

Ctrl+C destroys this runner's keys and databases. This procedure does not use public-service accounts or saved Vault data.

## Where to read the implementation

| Source | Behavior |
| --- | --- |
| [RP Worker](https://github.com/masanork/mikaki/blob/main/crates/helpdesk-rp/worker.ts) | Browser-bound state/nonce, S256 PKCE, ES256 assertions, ID Token validation, cookies, leases and Back-Channel receipt |
| [Rust application](https://github.com/masanork/mikaki/tree/main/crates/helpdesk-rp/src) | Public articles and ticket validation |
| [Local runner](https://github.com/masanork/mikaki/blob/main/local/runtime.ts) | Separate OP/RP keys, disposable D1, client/invitation initialization |
| [Browser test](https://github.com/masanork/mikaki/blob/main/local/test/helpdesk.test.ts) | Virtual-passkey registration/login, other-user ticket rejection, permissions, revocation and signed logout notifications |

Keep state, nonce, signature validation and session expiry even in a small integration. Replace ticket functionality with your own protected page.

## Reproduce automatically

After building, stop the development runner and run the following. Install Playwright Chromium first if absent.

```sh
npx playwright install chromium
node --test local/test/helpdesk.test.ts
```

The test uses a Chromium virtual authenticator rather than requiring physical biometric interaction. It exercises registration/login, ticket authorization, session renewal/revocation, invalid signatures and duplicate logout delivery. Success does not qualify real devices or a production OP/RP connection.

## Differences when connecting to the public IdP

The local OP is a TypeScript test adapter, distinct from the production Rust OP. In particular, the runner's `LOCAL_ONLY=true` selects a form-based `/session/check`, while **the public IdP requires JSON**. Do not reuse local configuration in production.

A real deployment needs its own HTTPS origin and D1, registered client ID, exact callback and RP-specific P-256 public JWK registration. Keep its private key in the RP Worker's `RP_PRIVATE_JWK` secret; do not share OP keys or databases. Check the RP's two migrations, Back-Channel receiver, operational policy and failure behavior. The [RP README](https://github.com/masanork/mikaki/blob/main/crates/helpdesk-rp/README.md) lists preparation requirements.

Deploying this example also requires staff provisioning, abuse controls, ticket retention/deletion and backups, monitoring and real-device checks.

## Read next

- [API reference](api.md): Check requests and responses for the public OP.
- [Application integration](integration.md): Proceed from registration to public-environment qualification.
