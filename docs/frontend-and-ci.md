# Frontend, localization, and quality CI

The local and Worker served login/Vault UI uses Svelte 5 and Vite. A shared Paraglide JS 2 catalog generates typed Japanese and English messages. Type checks use `svelte-check --tsgo` with TypeScript 7 through `@typescript/native`; TypeScript 6 remains a development dependency for current Svelte tooling internals. Handwritten Node scripts, local harnesses, and design probes use `.ts` files run directly by Node 26 and checked with `npm run check:node`. That check currently uses non-strict mode while dynamic D1, Worker, and conformance boundaries are typed incrementally; the Svelte UI keeps its strict settings. Generated Wasm and Worker glue remains JavaScript. See [project status](status.md) and current workflows for implementation evidence. The targets below are quality policy proposals, not proof that every gate is live.

## Frontend boundary

Keep initial screens focused on login, first client connection, account selection, credentials, and session/connection management. Use Svelte runes and small modules, native HTML controls, and shared design tokens. Serve static UI on the Worker origin while Rust handles protocol endpoints, final authorization, and cookies. The browser may display a server bound transaction but cannot decide identity or authorization. Locale changes must not recreate state, nonce, PKCE, or consent context.

Keep WebAuthn calls in a thin adapter. PRF output and key material stay out of component display state and persistent stores; ordinary login does not request PRF. Do not render user, client, or translation text as HTML. Test CSP, focus order, screen reader messages, cancellation, and retries in real browsers. Avoid external scripts on authentication/unlock pages.

## Localization

Support Japanese and English from the start. Choose the first supported `ui_locales` value, then saved user choice, `Accept-Language`, then Japanese default. An explicit UI switch changes the current transaction's presentation only; issuer, origin, redirect URI, and subject stay fixed. Validate supported BCP 47 tags. Set `html lang`; format dates/numbers with `Intl`, while comparison and signed timestamps remain UTC. Translate stable server error codes in UI, never raw exception strings. Pre-JavaScript error pages need both languages.

CI should detect missing/extra message keys, parameter mismatches, empty translations, and hard coded UI strings with context aware linting. Test long pseudo translations, wrapping, button widths, and focus in both languages. Runtime fallback does not count as complete translation.

## Growth and coverage

Measure base/head under identical rules for handwritten Rust, TypeScript/Svelte, SQL, tests, docs, generated files, and bundled assets. Exclude generated/vendor lines from handwritten counts, while still measuring shipped bundle bytes. Review public APIs, largest files, dependencies, raw/gzip Wasm and frontend sizes, build/test duration, TODOs, unsafe/allow suppressions, and coverage exclusions. Treat 500 handwritten lines in a product file as a review signal and growth beyond 800 as requiring a reason, not an automatic split. Do not fail CI merely because total code grows.

Record measurement JSON, HTML, LCOV, graphs, commit SHA, toolchain, features, exclusions, and metric version as CI artifacts and Job Summary. PR jobs should not get write tokens for a metrics history branch. The README links to [codebase growth](../README.md) and coverage reports.

Measure Rust line/region/function with cargo-llvm-cov and frontend line/branch/function/statement with Vitest V8. Rust regions are not branches. Proposed starting targets: auth/OIDC core 90% line and 85% region; handwritten frontend logic 85% line and 80% branch. Establish baseline against real implementation before enforcing. Coverage is evidence of executed code, not proof of security properties. Verify protocol invariants with dedicated tests, fuzzing, integration/browser cases, and failure injection.

CI should run format/lint/type checks, native and Wasm builds/tests where applicable, design/config validation, dependency audit, localization checks, code growth and coverage reports. Keep release gates tied to meaningful contracts and record toolchain versions and exceptions. See [contributing](contributing.md) and repository workflows for exact current commands.
