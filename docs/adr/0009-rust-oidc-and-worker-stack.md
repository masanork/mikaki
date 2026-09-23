# ADR 0009: Keep OIDC state transitions in Rust and browser code in TypeScript

**Status:** Accepted direction, 2026-09-23. Local probe evidence and remaining gates are below.

## Context

Authentication and authorization depend on allowed state transitions, single-use operations, and what commits when a step fails, not only signature verification. Rust owns these rules. Browser UI, WebAuthn APIs, IndexedDB, and Cloudflare bindings remain narrow platform boundaries.

The disposable local slice originally implemented OIDC and D1 operations in `local/op.mjs` and `local/rp.mjs`; `mikaki-oidc` held authorization-request and PKCE core logic. The former Worker JSON/Wasm boundary was renamed `mikaki-browser-wasm`, leaving `mikaki-worker` for Cloudflare fetch and binding adaptation. The local JavaScript implementation remains a test fixture, not the product authority.

## Decision

1. Keep OIDC, client assertions, single-use operations, authentication/authorization evidence, sessions, logout, and outbox use cases in `mikaki-oidc` and `mikaki-auth`. Make transitions from raw HTTP/JWT/UUID input explicit. Use private-field validated types and exhaustive results; do not deserialize HTTP or DB rows directly into trusted domain states.
2. Prefer a Rust production Cloudflare Worker adapter using `worker`/workers-rs. Confine HTTP, configuration, clock, randomness, async signing, D1, and Service Bindings to `mikaki-worker`. D1 conditional batches still decide durable single-use and concurrency; Rust types alone do not provide atomicity. Generated Wasm/JavaScript glue is an adapter detail, not a business API.
3. Use TypeScript 7 for Svelte UI, WebAuthn and IndexedDB calls, browser state, and local development code where Rust is an awkward boundary. UI does not decide authorization. Browser cryptography uses platform APIs and does not invent protocols.
4. Retain the local JavaScript slice as an end-to-end regression fixture while useful, and run the same contract cases against it and the Rust implementation during migration. Do not maintain two permanent product state machines.
5. Keep the initial crate set small: WebAuthn, auth, OIDC, and Worker. Do not introduce crates solely for JWT, D1 repositories, policy loading, or a general plugin framework.

## Worker feasibility gate

Before full migration, verify in an isolated runtime: typed Rust async fetch, input limits, cookies and response mapping; D1 batch rollback, one-winner concurrent code exchange, revocation races and primary reads; WebCrypto, scheduled and `waitUntil` support; common native/Wasm tests, size, cold start, and dependency audit. The probe must not use a production secret, remote D1, or external Cloudflare account.

The 2026-09-23 local probe used `worker 0.8.6`, Wrangler 4.136.2, and workerd 1.20260921.1. It demonstrated an async fetch handler, D1 batch rollback and `FirstPrimary` read, one-winner code exchange, Workers CSPRNG, async ES256 signing, and verification in existing Rust/Wasm code. A small product adapter served health and 404 locally. The isolated probe lockfile had 93 crates and no cargo-audit finding; the workspace lockfile then had 180 crates and no finding. Optimized probe Wasm measured 321,262 bytes raw and 104,541 gzip. See the [probe record](../../design/probes/README.md). These were partial local findings, not completion of the gate.

A follow-up passed an ephemeral 2048-bit RSA JWK from a Node test process to local workerd. Rust checked matching public/private JWKs, imported a nonextractable private key into WebCrypto, signed an RS256 ID Token input, and an independent Rust/Wasm verifier accepted it and rejected tampering. The probe omitted persistent secrets, D1 key rows, and real token exchange.

Still to validate were production Cloudflare D1 failure and session semantics, product SQL, scheduled/`waitUntil`, logout races, common native/Wasm tests, full Worker artifact and cold start, and real configuration and HTTP/cookie boundaries. If workers-rs fails the gate, use a thin TypeScript 7 Worker platform adapter while keeping protocol state transitions in Rust.

## TypeScript and verification

Use the TypeScript 7 native checker for UI code, not as a substitute for runtime validation. At the recorded time, `svelte-check` also needed TypeScript 6 API compatibility, so both packages were development dependencies. UI enables `strict`, `noUncheckedIndexedAccess`, and `exactOptionalPropertyTypes`. Generate Cloudflare binding types with Wrangler and explicitly type D1 rows.

Rust forbids project `unsafe`, denies Clippy warnings, pins dependencies, and uses native/Wasm tests and fuzzing. Independently test duplicate JSON rejection, durable rollback, and domain transitions. If `local/*.mjs` becomes product-like before migration, add it to TypeScript 7 `checkJs`; a permanent JavaScript product implementation would require resolving duplicate logic.

## Alternatives and trade-offs

An all-TypeScript implementation would simplify bindings but move core state evidence out of Rust; it was rejected. Rust core with TypeScript Worker is the explicit fallback, though DTO and D1 ownership become harder to separate. Rust core and Worker with TypeScript UI gives one state-machine owner at the cost of SDK constraints, Wasm size, and debugging work. Rust itself does not prove SQL atomicity or WebAuthn/JWT conformance; types, tests, and deployed measurements provide different evidence.
