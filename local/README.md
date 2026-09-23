# Disposable local authentication slice

The local harness connects invitation enrollment, a discoverable passkey, OIDC Authorization Code with PKCE S256, an RP session, and logout through two local Workers and D1. It is a verification fixture, not a public deployment. The original slice was recorded on 2026-09-22; later local logout, retention, and operator operations are described below. See [project status](../docs/status.md) for production evidence.

## Start

Use [.node-version](../.node-version), [rust-toolchain.toml](../rust-toolchain.toml), Python 3.14, and wasm-pack 0.15.0:

```sh
npm ci
npm run build
npm run dev
```

Open `http://127.0.0.1:18878` and enter the bootstrap invitation printed by the runner. The OP uses `http://localhost:18877`; distinct hosts keep cookies separate while retaining Secure, HttpOnly, and SameSite=Lax. This requires a browser that treats loopback HTTP as a secure context. Do not reuse this setup on an ordinary HTTP site.

The runner recreates keys and databases on startup. Accounts disappear when it stops, and an old browser passkey cannot log into the new database. The bootstrap invitation is single-use, lasts 15 minutes, and is consumed in the same D1 batch that creates the administrator. There is no public HTTP bootstrap endpoint.

## Boundaries

- Rust owns WebAuthn verification, JSON/CBOR limits, ceremony purpose/browser/expiry/attempt rules, and OIDC request/PKCE core logic. The separate [WebAuthn core](../crates/webauthn/README.md) has broader conformance capabilities than the local product profile.
- The TypeScript local OP adapter owns HTTP, D1 atomic operations, the harness OIDC flow, and JWT signing/verification through `jose` and WebCrypto. It is a behavior fixture, not the product state-machine authority. `mikaki-browser-wasm` is the browser/test Wasm boundary; `mikaki-worker` is the separate Cloudflare adapter.
- The OP UI uses Svelte 5 and a small typed Japanese/English catalog. The RP UI is diagnostic HTML.
- Local tables extend the [atomic SQL model](../design/sql/oidc-critical-schema.sql); they are not production migrations.
- A validated TOML policy is converted to second-based JSON and a revision at build time. Rebuild after a local config change. Some fields describe later features and are not used by the local slice.

The initial local slice used one RP and a static ES256 key. Do not infer production readiness or support for every later Worker feature from this harness. Production RP registration, remote monitoring and audit retention, recovery, actual authenticator coverage, and app integrations have separate gates.

## Logout delivery

The [delivery module](logout-delivery.ts) stores a single-SSO `sso_logout_event` in the same D1 batch as revocation, then expands notifications in batches of 100. This differs from an account-wide `revocation_event`. Immediate delivery uses `waitUntil`; a scheduled handler resumes work if that invocation is lost.

It acquires an atomic lease immediately before sending, limits concurrency per client, and rejects results from stale lease owners. Retryable 408/429/5xx and transport failures use backoff, jitter, Retry-After, attempt limits, and a deadline measured from committed revocation. It does not follow 3xx; other 4xx and 3xx are permanent failures. Each attempt signs a fresh Logout Token and limits response-body reading. Neither tokens nor response bodies are logged.

The module counts unexpanded events, outstanding deliveries, oldest backlog, permanent failures, and expiry, emitting structured warnings at thresholds. The local runner invokes the Worker scheduled handler at `scheduler_interval` (initially one minute); DB leases coordinate with other invocation paths. Backoff is an earliest send time because the next scan may occur later. There is no production Cron Trigger, alert destination, or production administrator authentication here. A runner restart also resets D1, so it does not prove persistence across process restarts. [Integration tests](test/logout-delivery.test.ts) cover batch rollback, concurrent fanout, leases, deadlines, permanent failure, and scheduled recovery.

## Retention and garbage collection

[GC](gc.ts) runs through OP and RP scheduled handlers at `retention.gc_interval` (initially one hour), deleting at most `gc_batch_size` rows per database/run (initially 500). Each DELETE rechecks its own conditions atomically; logs contain counts only.

It covers expired ceremonies and transactions, safe replay-prevention records and rate windows, expired RP sessions and revocation evidence, and completed SSO/logout histories after their retention conditions. It never deletes an unfinished delivery solely because a time passed. `gc_after` is fixed at issuance from expiry, clock skew, and grace, not recalculated under a later shorter policy. RP revoked-sid retention covers the actual parent SSO expiry, pending transactions, and retries, increasing monotonically for duplicate notifications.

Callback commit and idle renewal recheck expiry and any lease, so a long-paused callback cannot restore a session after GC. SSO records persist beyond absolute expiry when audit, issued-code evidence, or outstanding logout work requires them. Deletion proceeds from delivery children through events, issuance records, client sessions, and finally SSO parents, checking references at every step; a partial batch can resume next time. Invitations, accounts, credentials, consents, subjects, and keys are outside this GC.

Account-wide events are removed only after expansion, audit retention, and removal of affected old-epoch SSO records. This local harness does not provide production audit storage, migration, Cron, or administrator authentication. See [GC tests](test/gc.test.ts) and [lifecycle tests](test/gc-lifecycle.test.ts).

## Local operator commands

The trusted user controlling the `npm run dev` terminal may inspect and retry delivery through standard input. This is not a production management HTTP API or step-up authentication. The OS username is recorded as actor:

```text
logout-list
logout-retry EVENT_ID REVISION DEADLINE_UTC RETAIN_UNTIL_UTC REASON
```

`logout-list` shows up to 100 events and their revision, deadline, delivery counts, and retry candidates. The two timestamps use UTC such as `2026-10-01T00:00:00Z`. Reasons are `network_recovered`, `configuration_fixed`, or `operator_retry`. The new deadline must exceed now and the prior deadline; retention must cover the deadline plus result TTL, skew, and GC grace. Longer old retention is not shortened.

Only fully expanded events whose deliveries are terminal and include a failed or expired delivery can be retried. Successful notifications are not resent. The selected attempt count resets, then normal signing, leasing, and backoff resume on the next scheduled run. One D1 batch extends deadlines, increments revision, records audit, and requeues work. Audit keeps operation/event IDs, old revision, actor, reason, timestamps, old/new deadlines, requested retention, sid, and previous delivery state; it never stores tokens, cookies, or response bodies. Audit can outlive the event.

The batch refuses a retry if some delivery rows were already GC'd, if the event is not eligible, or if a concurrent operator won the revision. It leaves no partial audit or deadline change on failure. See [retry tests](test/logout-admin.test.ts).

For account-wide session invalidation:

```text
account-list
account-revoke ACCOUNT_ID EXPECTED_EPOCH REASON
```

`account-list` shows up to 100 accounts. A matching active account may advance its epoch and create a `revocation_event` in one batch, with reason `session_reset` or `security_incident`. Duplicate or stale-epoch operations fail. Old-epoch SSO is invalid at the OP immediately; RPs observe notification or lease expiry. Scheduled fanout expands up to 100 old-epoch SSO records at a time into single-SSO events without resetting the original retry deadline. Overlapping logouts converge on one SSO event; an already failed delivery needs explicit `logout-retry`.

Pending account events protect affected SSO/delivery records from GC and appear in backlog metrics. New-epoch SSO is unaffected, and old-epoch SSO is excluded from the concurrent-session limit. Credentials remain usable for a fresh passkey login; account suspension and credential removal are separate. [Account tests](test/account-admin.test.ts) cover races, rollback, fanout, GC, and delayed-notification safety.

## TypeScript and checks

At the recorded tool versions, `svelte-check 4.7.6 --tsgo` uses the TypeScript 7 native checker but still calls TypeScript 6 JavaScript APIs to transform Svelte source. The two packages are development tools; TypeScript 6 is not shipped to browsers. Remove it when upstream no longer needs it.

```sh
cargo test --locked --workspace
cargo clippy --locked --workspace --all-targets -- -D warnings
npm run check:ui
npm run check:i18n
npm run format:check
npx playwright install chromium
npm run test:e2e
```

Integration tests cover concurrent registration/code exchange, one-time assertions, PKCE, expiry, key suspension, UserInfo, SSO reuse, logout delivery, delayed callbacks, expired leases, and bootstrap reuse. The [CI workflow](../.github/workflows/ci.yml) also runs dependency audit, native coverage, and size measurements; check current CI results before claiming a GitHub run. Coverage is for native default-feature auth/OIDC/WebAuthn code and excludes Wasm adapters and JS/Svelte. See [metrics](../metrics/README.md).

Browser tests use a CDP virtual authenticator. The [device matrix](../docs/webauthn-device-compatibility.md) separates that from real hardware. The registration UI checks `credProps.rk===true` as a client compatibility condition, not signed identity evidence; see [extensions](../docs/webauthn-extensions.md). Diagnostic errors are normalized at the Wasm/JS boundary; see [error contract](../docs/webauthn-errors.md).
