# Public OIDC login demo

The login-only mode of `crates/helpdesk-rp/worker.ts` is configured for `https://demo.mikaki.org`, with issuer `https://auth.mikaki.org`. It requests only `openid`; no UserInfo, profile or Vault data is requested or exposed. `/session` shows confirmation/expiry times without displaying `sub`, `sid`, tokens or assertions. Tickets, staff access and help article routes return 404 in this mode, including direct POSTs.

## Dedicated configuration

- Worker: `mikaki-demo-rp`; config [wrangler.demo.jsonc](../crates/helpdesk-rp/wrangler.demo.jsonc).
- Separate D1: `mikaki-demo-rp`, ID `ce11d383-758b-4574-8bcc-7febc505a408`. Both existing RP migrations are applied; the ticket/staff tables remain unused.
- Client: `77551450-ec73-4222-972d-cd912d9493d4`, sector `demo.mikaki.org`, exact redirect `https://demo.mikaki.org/callback`.
- Client authentication: RP-specific P-256 key, kid `demo-rp-2026-10`. Only the public key is registered in the OP. The private JWK is stored as `RP_PRIVATE_JWK` on the RP Worker; it is never committed or published.
- Back-Channel receiver: `https://demo.mikaki.org/backchannel`, registered separately by the audited client CLI. Registration alone does not demonstrate live notification delivery.

The RP caps its parent/idle/lease expiry at one hour when committing a callback. Renewal cannot extend that cap or the earlier OP parent expiry. Explicit session checks remove the RP session on a confirmed inactive/expired OP response. Outages fail closed on new or explicit checks and never extend an old lease; regular requests can use a still-valid prior lease. An arriving signed logout deletes sessions and commits a tombstone before acknowledging, preventing a delayed callback from restoring that sid.

## Deploy and maintain

Use a clean checkout and the repository's pinned toolchains/dependencies. Build Wasm before bundling the Worker:

```sh
npm ci
npm run build:helpdesk
npm run check:helpdesk
node_modules/.bin/wrangler deploy --config crates/helpdesk-rp/wrangler.demo.jsonc --dry-run
node_modules/.bin/wrangler deploy --config crates/helpdesk-rp/wrangler.demo.jsonc
```

Provision the dedicated DB/migrations and private key before deployment. Use [managed client operations](rp-client-operations.md) for public key/redirect registration and rotation. Never apply RP migrations to the OP database. Do not recreate keys during an ordinary deploy. Keep recovery material in the operator's secret storage; a repository checkout contains no private key. The demo is deployed independently of the OP; no OP release or schema migration is necessary for its registration.

The configuration disables workers.dev/previews and routes only the dedicated custom domain. `DEMO_ONLY=true` is required for this deployment. Login/explicit check routes have a Cloudflare rate-limit binding (namespace `2026100401`, 60 requests per 60 seconds per route/location). This is a permissive service protection bound, not global accounting; it is shared by demo users in that location. There is no IP address collection in application storage. Health checks include the schema and required binding/secret presence; they do not prove OIDC login.

Responses are no-store and noindex. Strict-origin referrers prevent callback queries from becoming referrers while preserving same-origin POST Origin/CSRF checks. Worker invocation logs and traces are disabled to avoid recording callback URL codes/state; unexpected error logs include only the error class. Cron runs every 15 minutes and removes expired login transactions, sessions and logout tombstones. Expiry is enforced at request time even if cleanup is delayed. The browser cookie used for CSRF expires after one day; the locale preference after one year. These cookies do not carry account identifiers.

To suspend sign-in, disable this client using the audited CLI and remove the demo link if necessary. Do not disable other clients or rotate OP signing keys. Registered client keys and operator audit rows follow the OP's retention policy and are not removed by the RP cleanup.

## Qualification

```sh
npm run build
npx playwright install chromium
node --test --test-concurrency=1 local/test/demo-rp.test.ts local/test/helpdesk.test.ts
```

The demo test uses a disposable local OP and virtual passkey, verifies login and explicit checks, the one-hour cap, forbidden ticket routes, CSRF rejection, RP logout without OP logout, and known-revocation removal even while an older lease is valid. The existing Helpdesk test verifies signed/duplicate Back-Channel delivery and callback/revocation races. These tests do not establish public Rust OP interoperability or real-device authentication.

For the public test, use a browser and participant-controlled registered passkey: open the demo, confirm its origin at the OP, complete the connection, return to `/session`, explicitly check the session, and log out of the RP. Record only status/outcome and source/deployment versions; do not record callback queries, cookies, sub/sid, passkey material or token bodies. Public Back-Channel delivery needs a separately controlled SSO logout and receiver/session verification; avoid ending another participant's session to manufacture a passing result. Mark unperformed checks as unverified.
