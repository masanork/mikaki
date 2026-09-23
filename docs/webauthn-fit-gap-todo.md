# WebAuthn fit/gap and quality backlog

**Comparison snapshot, 2026-09-23.** This prioritizes WebAuthn quality work, not the project's entire P0 or a new release requirement. Keep the compact native/Wasm core and separation from HTTP, DB, clock, and network in [ADR 0006](adr/0006-compact-portable-webauthn.md), and the ES256/UV/discoverable/`none` product defaults in [ADR 0008](adr/0008-webauthn-conformance.md). Matching every webauthn-rs feature is not a goal.

The comparison used Mikaki and [webauthn-rs commit be696b79](https://github.com/kanidm/webauthn-rs/tree/be696b79800bd1953df78e87d0215571733cc26f) (published version 0.5.5). It was source/public-material review, not matched performance or security audit. At that snapshot, Mikaki `crates/webauthn/src` had 1,811 physical lines (520 in `tests.rs`), versus 17,144 across selected webauthn-rs core/API/proto/attestation/base64/MDS source. Counts include comments, blanks, embedded tests and exclude dependencies and other project components. Different coverage prevents a “same features at one-tenth size” claim.

## Fit to preserve

| Property | Boundary |
| --- | --- |
| Native/Wasm reuse | Same Rust verifier; no OS, HTTP, or DB in core |
| Explicit trust input | Challenge, origin, RP ID, time, and metadata come from saved server state, not credential response |
| Validated result type | External construction/deserialization forbidden; signature success still requires atomic challenge/credential commit |
| Parser boundary | Maintain size, depth, duplicate, and trailing-data checks as formats grow |
| Test evidence | 155/155 mandatory in Tools 1.9.1 native/Wasm and later Tools 1.9.2 ARM64 native, distinct from optional tests, certification, audit, and physical devices |

The [1.9.1 result](../local/conformance/results-2026-09-22.md) and [1.9.2 ARM64 rerun](../local/conformance/performance-arm64-2026-09-23.md) are the evidence. The source comparison reran 17 native tests and two compile-fail checks, but did not rerun the official suite.

## Work items

| ID | Status | Contract or remaining gate |
| --- | --- | --- |
| WG-01 | Completed | Stable payload-free internal diagnostic codes; keep detailed reasons out of public credential responses and raw secrets out of logs. See [errors](webauthn-errors.md). |
| WG-02 | Contract reviewed | Validate context at both core entry points and reject empty browser binding. Durable issuance-time policy snapshots remain. See [ceremonies](webauthn-ceremony-contract.md). |
| WG-03 | Completed | Separate trusted-attestation requirement from trust input; return unforgeable evidence while keeping product `none` request and optional policy. See [attestation](webauthn-attestation.md). |
| WG-04 | Scope documented | Distinguish extension structure, signature integrity, specific meaning, and client output. `credProps.rk` is a browser compatibility check. See [extensions](webauthn-extensions.md). |
| WG-05 | First fuzz run completed | Three independent-fixture parser/MDS targets; carry valid findings into shared regressions. Long, structured mutation and differential review remain. See [fuzzing](webauthn-fuzzing.md). |
| WG-06 | Virtual browsers tested; real devices open | Record device/OS/browser/authenticator, sync, UV, discoverability, and counter/backup without treating CDP simulation as hardware. See [matrix](webauthn-device-compatibility.md). |
| WG-07 | Core fields improved; product operation open | MDS `iat`, BLOB number, optional `nextUpdate`, U2F ID, and status details are retained. Add durable snapshot, number rollback prevention, atomic refresh, failure/freshness policy before product MDS. See [MDS](webauthn-mds-operation.md). |
| WG-08 | Scoped comparison completed | Measure matched fixture/core boundaries; do not rank differing product artifacts by suite duration. See [native](../local/conformance/performance-2026-09-23.md) and [cross-implementation](../local/conformance/performance-cross-impl-2026-09-23.md). |
| WG-09 | Open | Fix reviewed revision and external reviewer, record findings, maintain vulnerability route and dependency advisory rationale. See [brief](webauthn-security-review.md). |
| WG-10 | Demand-driven | Consider Apple/Android Key attestation, additional algorithms, and cross-origin iframes only with a user need, failure policy, native/Wasm checks, dependency/size cost. |

## Recorded milestones and limits

On 2026-09-23, WG-01 tests covered native/Wasm diagnostic code/stage, JS normalization, and equal public 400 responses for modified challenge/origin; WG-02 added trusted-context validation with 22 shared tests per target; WG-03 added `required_trusted` and evidence with 24 shared tests and four type-boundary checks; WG-04 checked nonstring extension IDs, signed unknown extension tampering, and `credProps.rk`; WG-05 ran registration 268,184/42 seeds, assertion 363,762/4, and metadata 259,561/43 for 25 seconds each without panic/timeout. These specific changes did not each rerun the official GUI suite.

WG-06's headless Playwright Chromium 153, Chrome 154, and Canary 156 runs passed 49 tests each using CDP virtual CTAP2.1. Touch ID, iOS/Android/Windows Hello, external keys, and Safari remained untested. WG-07 added MDS 3.1.1 field retention and a U2F attestation fixture; its durable operational adapter remains absent despite native/Wasm and Node checks.

WG-08 recorded full-Worker Wasm 644,011 bytes and conformance server 2,604,224 bytes, neither core-only. Under the same Tools 1.9.2 suite both iwato and Mikaki passed 155/155 twice, with median totals 5.385/3.285 seconds; the fixture/core comparison, Wasm assertion, heap, and process memory have separate boundaries in the linked record. The ARM64 native suite's second 3,085.945 ms run contained 42.374 ms handler and 14.773 ms Rust verification work. No result justifies dropping crypto or DB durability to reduce GUI time. Further tuning requires a user latency regression or reproducible hotspot.

WG-09's recorded scans covered 129 Rust dependencies with only the documented [RSA public-verification exception](adr/0008-webauthn-conformance.md) and npm audit with zero findings; CI and weekly Dependabot are configured. An external review had not occurred at this snapshot. Review the current [security policy](../SECURITY.md) for reporting availability.

Reference implementations and materials: [Mikaki core](../crates/webauthn/README.md), [webauthn-rs API](https://github.com/kanidm/webauthn-rs/blob/be696b79800bd1953df78e87d0215571733cc26f/webauthn-rs/src/lib.rs), [errors](https://github.com/kanidm/webauthn-rs/blob/be696b79800bd1953df78e87d0215571733cc26f/webauthn-rs-core/src/error.rs), [MDS](https://github.com/kanidm/webauthn-rs/tree/be696b79800bd1953df78e87d0215571733cc26f/fido-mds/src), and its [README](https://github.com/kanidm/webauthn-rs/blob/be696b79800bd1953df78e87d0215571733cc26f/README.md) and [security policy](https://github.com/kanidm/webauthn-rs/blob/be696b79800bd1953df78e87d0215571733cc26f/SECURITY.md). Another project's audit statement does not certify its current code or Mikaki.
