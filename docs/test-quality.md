# Product test coverage and CI evidence

Reviewed on 2026-09-29 against the current working tree. Local results below do not identify deployed bytes or a successful remote CI run. [Product quality gates](product-quality.md) own activation requirements.

## Checks before merging

| Command | Boundary and assertions |
| --- | --- |
| `npm run test:worker-contracts` | Actual Rust OP and claim Worker bundles in local workerd with disposable D1/R2. Registration, bootstrap invitation lifecycle, client/key changes, owner-scoped attributes, exact retries, sharing/consent/revocation, recipient verification, missing secret custody, and authenticated session checks. |
| `npm run test:release` | Archive/member/migration/source integrity and dirty-check negatives; disposable SQLite migration/backup/object exercise with explicit historical authority resurrection. No Cloudflare restore/promotion qualification. See [release and recovery](release-and-recovery.md). |
| `npm run test:worker-browser` | Actual UI bundles under Chromium: registration with eight competing finish requests (one success, seven client rejections) and rollback/retry after injected storage failure, login cue/locale/reduced motion, profile failure/retry, draft/initial-deletion confirmation and cancelled navigation/language changes, sharing/logout, Vault display disposal and resume, plus the complete product journey below. Also checks that failure evidence can be saved. PR CI records source-mapped execution from the product screen journey. |
| `npm run test:frontend-coverage` | Node/V8 coverage of handwritten flat `crates/worker/ui/*.ts`, including modules never loaded by these tests. Excludes Vite config, generated catalogs, and Svelte components. Runs crypto, typed note, saved-head, session lifecycle, and recipient-directory tests, with per-module line/branch regression floors for the five directly tested modules. |
| `npm run test:agent-integration`, `test:vault-transfer`, `test:vault-notes`, `test:attribute-proposals`, `test:attribute-commit`, `test:agent-oauth` | Additional scoped browser/workerd/SDK checks for AI access, saved-content transfer, proposal/approval authority and OAuth. These remain separate from the basic journey. |
| `npm run test:e2e` | Existing local OP/RP/Helpdesk reference-runtime tests, including lease and backchannel races. Their local OP is a TypeScript adapter; this is distinct from testing the Rust OP bundle. |

PR verification now builds both Rust product Workers and runs the Worker contract/browser commands. The main-only attested build invokes the same commands before creating provenance artifacts, and also runs frontend TypeScript coverage. The product enrollment and authorization checks no longer depend solely on a post-merge build. This changes workflow configuration; the local results do not prove a GitHub run has completed.

## Connected product journey

`local/conformance/product-journey.test.ts` uses a disposable local HTTPS bridge, the actual Rust OP bundle, actual migrations, random signing/client keys and a fresh bootstrap invitation. Chromium resolves only the two fixture hostnames to loopback for this journey and accepts its ephemeral self-signed certificate. OpenSSL must be available; no production endpoint or account is used.

The browser registers a discoverable virtual CTAP2 authenticator with user verification and PRF, saves and reopens an encrypted Vault name, and signs into a reference RP. The reference RP validates the signed ID Token, issuer, audience, nonce, callback state and browser binding, exchanges the code with S256 PKCE and `private_key_jwt`, and calls the Rust `/session/check` endpoint. Both reused callback state and code exchange are rejected; code reuse also invalidates the earlier token family. A new login restores access before logout is exercised. OP logout then denies both Vault access and RP protected requests despite retention of the RP cookie.

The RP in this journey is a small disposable fixture, **not narashi or the deployed Helpdesk**. Its server-to-server calls use the local Worker handle and it checks session status on every protected request. This does not qualify a real RP's caching lease, backchannel delivery, DNS/TLS configuration, or production callback. PRF is exercised through Chromium's virtual authenticator rather than replaced with a fixed output, but physical devices, platform UI, synced passkeys and OS sleep remain unqualified.

## Failure evidence

Instrumented account/Vault browser suites save `artifacts/browser-failures/<suite>-<unique-id>/` **only on failure**, before closing the browser:

- `trace.zip`: Playwright trace, DOM snapshots, screenshots and source references.
- `page-<index>.png`: best-effort full-page screenshots of open tabs.
- `diagnostics.json`: a bounded summary of console warnings/errors, page errors, failed requests and HTTP errors. URL query/fragment and bearer-like values are removed from this summary.

Passing traces are discarded. The recorder self-check deliberately fails internally, verifies usable files and redaction, and removes only its own temporary evidence directory. Other failing suites preserve their original assertion even if evidence cleanup fails. The PR workflow uploads the artifacts through `authentication-measurements` even after a failure; the attested build has a separate failure upload. Retention is fourteen days.

Inspect a trace with `npx playwright show-trace <path-to-trace.zip>`. **Traces and screenshots are not redacted**: they can contain synthetic cookies, keys and plaintext. The recorder is limited to disposable local fixtures and must not be attached to real user or production sessions. The summary removes common secret formats but is not a general-purpose sanitizer.

## Coverage baseline and limits

Local native measurement on 2026-09-29 used Rust 1.98.1 and cargo-llvm-cov 0.8.7; CI pins its own version. With the same current code and measurement rules, adding four OIDC boundary tests changed native line coverage from **78.1% (2354/3013) to 86.9% (2618/3013)** and region coverage from **76.8% to 83.1%**. This comparison isolates the added tests; the older 2026-09-27 chart used an earlier code denominator.

The new tests exercise registered-key signature verification, claim/endpoint/client rebinding, duplicate and untrusted JWT fields, canonical encoding, exact expiry/skew, PKCE vectors, optional-PKCE isolation and authenticated exchange binding. Previously unexecuted native `client_assertion.rs` and `exchange.rs` now measure **97.5% and 99.1% lines** respectively. D1 atomicity, single use and replay invalidation still require Worker integration tests; pure Rust tests do not establish those storage guarantees.

The initial Node/V8 TypeScript baseline was **52.6% lines (757/1439)** over sixteen files, including unloaded bootstrap/browser modules. The exercised Vault lifecycle module measured **95.3% lines / 80.6% branches**. The current command now fails if coverage for any of five directly tested modules falls below its line/branch floors: recipient directory 90/80%, Vault crypto 85/70%, saved-head freshness 95/90%, Vault lifecycle 90/75%, and typed note 95/90%. It also fails when a selected module or metric is unmeasured. These deliberately lower floors catch substantial test loss while allowing small source changes; they are not a whole-product threshold. Coverage excludes Svelte DOM behavior and browser execution: zero Node coverage of a browser bootstrap is not proof it lacks browser tests. Node reports zero-denominator branch/function percentages as 100%; the JSON report represents those as `null`.

CI exports native summary JSON, HTML and LCOV, plus frontend LCOV and JSON. Frontend JSON records Node version, timestamp and per-file SHA-256 of the measured working-tree source. Native chart history remains CI-owned and tied to main commits; this local result does not replace that history. Reports are local artifacts or CI downloads, not checked-in generated coverage.

PR CI additionally builds the Worker UI with hidden Vite source maps kept in Cargo's local output, then runs the product screen journey with Chromium precise JavaScript coverage. The recorder rejects a map unless its adjacent bundle bytes exactly match the JavaScript served to the browser. `artifacts/browser-source-coverage.json` reports executed and total mapped source lines with source hashes for Svelte and TypeScript files; a local run mapped Vault, administration and registration-completion bundles to 23 UI files. It contains no script bodies, source-map contents or browser state. This is **mapped-line execution evidence for one journey**, not Istanbul line/branch coverage, a whole-product percentage, or proof that every rendered branch is usable. Logout currently renders server-side HTML and loads a separate session-event script, so it is outside the three mapped Vite bundles in this report. No numerical threshold is applied to these Svelte results yet.

```sh
npm run build
worker-build --release crates/worker
worker-build --release crates/userinfo-claim-worker
npx playwright install chromium
npm run test:worker-contracts
npm run test:worker-browser
npm run test:frontend-coverage
cargo llvm-cov --locked --workspace --exclude mikaki-browser-wasm --exclude mikaki-worker --ignore-filename-regex '/tests\.rs$' --json --summary-only --output-path artifacts/native-coverage.json
cargo llvm-cov report --locked --ignore-filename-regex '/tests\.rs$' --html --output-dir artifacts/native-coverage
cargo llvm-cov report --locked --ignore-filename-regex '/tests\.rs$' --lcov --output-path artifacts/native-coverage.lcov
```

Next gates are broader browser journeys and risk-based Svelte thresholds informed by this source-mapped evidence, supported-browser/device qualification, actual production RP/callback/logout evidence, accessibility checks and operational restore/rollback drills. Coverage reports guide additions; they do not certify security or production readiness.
