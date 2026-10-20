# Mikaki security assurance plan

Prioritize account and object authorization, key custody, revocation, and recovery. Extend the existing CI with focused security checks, exercise attacks against disposable environments, and commission an independent review of the highest-risk boundaries.

The initial scope uses main commit `8cd807ab2f8da837d3e0c98cd6146eacf19c94fc` on 2026-10-20. The Wallet/Chat candidate is tracked separately in the [verification inventory](security-verification-inventory.md). Every assessment must identify its own immutable revision and enabled profiles. This is an execution plan; acceptance requires the evidence below.

Use the [threat model and twenty attack scenarios](security-threat-model.md) to select tests. Follow [SECURITY.md](../SECURITY.md) for private vulnerability reports.

## Verification standard

Use [OWASP ASVS 5.0.0](https://owasp.org/projects/asvs) Level 2 as the application baseline, adding applicable Level 3 requirements for authentication, cryptography, privileged operations, and recovery. Use the [Web Security Testing Guide](https://owasp.org/projects/web-security-testing-guide) for test procedures. Select requirement IDs from the versioned standard when implementing each test; a topic match alone does not establish compliance.

For every selected requirement, record the affected component, attacker capability, intended property, test or review evidence, environment, result, and any exception. Keep core, actual Worker, browser, physical-device, deployment, and independent-review evidence distinct. [Product authorities](implementation-authorities.md) identifies the implementation that owns each guarantee.

## Delivery sequence

The stages are ordered by dependency. Assign named owners and estimate effort after the first inventory review.

| Stage | Work | Completion evidence |
| --- | --- | --- |
| 1. Fix the assessment scope | Confirm the threat model, active profiles, API and named-entrypoint inventory, effective dependency graphs, and test-environment ownership. | A reviewed target revision, scope decisions for all twenty scenarios, dependency coverage decisions, and an engagement scope. |
| 2. Strengthen frequent checks | Pilot secret detection and zizmor; close dependency scan omissions; extend actual Worker authorization tests; evaluate CodeQL on representative Rust and TS paths. | Reproducible reports, deliberately failing fixtures that demonstrate detection, and reviewed false-positive handling. |
| 3. Explore behavior | Run authenticated ZAP, longer fuzz campaigns, generated operation sequences, concurrency and lost-response tests, and manual Burp sessions. | Request coverage, authentication checks, corpus and execution statistics, minimized failures, and regression tests for confirmed defects. |
| 4. Obtain independent review | Review source and staging behavior for WebAuthn/OIDC, Vault, Work delegation, and enabled Wallet/Chat paths. Retest accepted findings. | Reviewer, revision, scope, exclusions, evidence, fixes, retest results, and residual-risk decisions. |

Start Stage 2 with secrets, workflow safety, dependency scope, and object authorization. Add expensive scanners after the harness can prove which authenticated paths they reached. Keep unrelated in-flight CI changes in their own branches.

## Tools and skills

| Tool or workflow | Intended role | Adoption check |
| --- | --- | --- |
| Existing SonarQube and [CodeQL](https://codeql.github.com/docs/codeql-overview/supported-languages-and-frameworks/) | Security-focused source review across Rust, JS/TS, and Actions; assess Kotlin separately. | Pilot relevant queries against known unsafe and safe fixtures. Measure how `workers-rs`, Wasm glue, service bindings, and Svelte-generated code are represented. Confirm repository entitlement before enabling hosted features. |
| [zizmor](https://docs.zizmor.sh/quickstart/) | Review workflow input handling, credentials, permissions, and artifact trust. | Run against workflows and composite actions. Review each finding; pin the selected tool version before adding a required job. |
| [GitHub secret scanning and push protection](https://docs.github.com/en/code-security/concepts/secret-security/push-protection) | Detect credentials and prevent supported secrets from being pushed. | Inspect repository settings, entitlement, pattern coverage, and bypass permissions. Test with a documented inert fixture; redact evidence. |
| Existing Cargo/npm audit and [cargo-deny](https://embarkstudios.github.io/cargo-deny/checks/index.html) | Check known advisories and Rust dependency/source policy. | Cover each effective graph in the inventory. Select a compatible JVM advisory check for Gradle; cargo-deny does not inspect JVM dependencies. Preserve narrowly justified, expiring exceptions. |
| Existing cargo-fuzz and [proptest](https://proptest-rs.github.io/proptest/intro.html) | Explore parsers and generated state transitions. | Preserve useful corpus inputs, minimize failures, and define acceptance/rejection oracles. Replay regressions on native and Wasm where applicable. |
| Playwright and [ZAP Automation Framework](https://www.zaproxy.org/docs/automate/automation-framework/) | Reach authenticated browser/API surfaces and automate dynamic checks. | Supply disposable users through normal authentication. Verify login state before and after scanning and compare reached routes with the target inventory. Scope active scanning to disposable environments. |
| [Burp Suite](https://portswigger.net/burp/documentation/desktop/testing-workflow/vulnerabilities/access-controls) | Manual access-control, replay, and workflow testing. | Use separate identities and correlate modified requests with durable effects, not HTTP status alone. Evaluate the paid edition when manual testing needs it. |
| [Codex Security](https://learn.chatgpt.com/docs/security/plugin) | Review the codebase and sensitive diffs using the threat model as context. | Local availability and account access remain to be established. Require source evidence, attacker prerequisites, validation method, and uncertainty for findings. The documented `$codex-security:security-diff-scan` workflow targets changes; use a full scan for a baseline. |

Use the available `workers-best-practices` skill for Worker runtime and binding reviews and `wrangler` for configuration inspection. Use `durable-objects` if a reviewed component actually uses that state authority. A future `mikaki-security-review` skill should carry the threat model, scenario IDs, entrypoint map, required evidence, and private-reporting rules; create it with `skill-creator` after the first review stabilizes those inputs.

AI-assisted review produces candidate findings. Accept a finding after reviewing its reachable attack path and evidence, then verify the fix against the relevant product authority. Keep automated source inspection and executed reproduction explicitly identified in the report.

## Design properties to strengthen

Review these properties across all exposed paths, retaining existing implementations where they already satisfy the contract:

- Derive account authority from a validated session or explicit capability. Apply object ownership and scope checks to reads, writes, lists, exports, sharing, and internal named entrypoints.
- Recheck expiry, revocation, generation, and policy revisions at the conditional commit that authorizes a durable change. Preserve unknown outcomes without blindly repeating external effects.
- Keep root keys, PRF material, holder keys, signing keys, recipient keys, and delegated tokens in their distinct custody domains. Bound token scope, audience, validity, and replay windows.
- Reduce plaintext exposure through safe rendering, reviewed content security policy, bounded inputs, and redacted errors, telemetry, browser traces, and test artifacts.
- Exercise restoration and revocation together. Retain the independent state needed to prevent a restored database or client checkpoint from resurrecting authority.

See the existing [OIDC commit contract](oidc-store-contract.md), [owner-key contract](vault-owner-key-contract.md), and [Work checkpoint](work-authority-checkpoint.md) before changing these behaviors.

## CI execution policy

| Frequency | Work | Result handling |
| --- | --- | --- |
| Pull request | Secret and workflow checks, affected dependency graphs, deterministic authorization/replay regressions, selected source checks. | Require configured checks to finish on the reviewed revision. A tool error, missing input, or unmeasured target is an explicit failure or recorded unavailable result. |
| Nightly or weekly | Longer fuzzing, generated operation sequences, authenticated DAST, and broader source analysis. | Track target coverage, login verification, corpus retention, execution budget, and new findings. Begin with a 30-minute fuzz budget per target and adjust from resource measurements. |
| Sensitive change or release | Full relevant source review, the scenario matrix for enabled profiles, manual testing, dependency/configuration review, and promotion verification. | Retain evidence tied to the exact candidate, bundles, migrations, feature flags, and environment. Device qualification remains a distinct result. |

Keep PR checks bounded by measuring the pilot before setting timeouts. Pin scanners and their Actions. Give untrusted PR analysis read-only permissions and no deployment credentials. Keep scanners that require credentials in appropriately scoped jobs, and review artifact and cache trust when crossing workflow boundaries.

Existing findings need individual triage. Prevent newly introduced confirmed Critical/High issues from merging; assign existing issues a severity, owner, treatment deadline, and compensating controls. Release with an unresolved confirmed Critical/High issue requires an explicit, time-limited risk decision by the release owner. Do not suppress an entire rule to clear one finding.

## Penetration test engagement

Use a source-assisted assessment with disposable data and an isolated Cloudflare environment. Include WebAuthn and cryptographic-protocol expertise in the review scope, using the existing [WebAuthn brief](webauthn-security-review.md). Retain separate results for browser/HTTP testing, source review, and native-device testing.

Complete the following engagement record before active testing:

| Field | Required value |
| --- | --- |
| Target | Immutable source revision; exact hostnames; endpoint and named-entrypoint inventory; enabled profiles and feature flags. |
| Environment | Dedicated Worker names, D1/R2 resources, queues and any checkpoint service; disposable signing/recipient/holder keys. |
| Identities | Unauthenticated client, owners A/B, distinct RP clients, limited agent, administrator, and revoked device/capability. |
| Authorization | Named system owner and tester, allowed techniques and test window, third-party exclusions, and permitted external effects. |
| Limits | Initial request rate and concurrency, storage/CPU/cost budget, monitoring thresholds, and an owner who can stop the run. |
| Stop conditions | Unexpected access to non-test data, effects outside the dedicated resources, budget breach, or service degradation beyond the agreed threshold. |
| Recovery | Tested cleanup and rollback steps; preserve evidence before cleanup; never reset an existing production or Work authority checkpoint. |
| Evidence | Restricted report location, redaction rules, access list, retention/deletion date, and private vulnerability-reporting route. |

Normal authentication is part of the harness. Keep test-profile controls isolated from production credentials and deployments. Verify the disabled default profile as well as each deliberately enabled test profile. Reachability of an administrative entrypoint in a fixture must not imply public reachability.

## Findings and acceptance

Each finding must identify the revision, affected authority and profile, attacker prerequisites, violated invariant/scenario ID, minimal synthetic reproduction or source-validation method, durable impact, severity rationale, and fix/retest evidence. Distinguish confirmed findings from hypotheses and hardening proposals. Keep exploitable details and sensitive artifacts in the private reporting channel.

Each scenario in the threat model receives a result of `pass`, `fail`, `blocked`, or `not_applicable`, with the environment and evidence attached. A `blocked` result identifies its missing prerequisite; `not_applicable` requires a reviewed reason. Existing nearby test files are starting points, not completed scenario results.

The first assessment is complete when all twenty scenarios have dispositions, effective dependency graphs have scan coverage or reviewed exclusions, confirmed findings have treatment decisions, accepted fixes have regression and retest evidence, and the independent review record identifies its scope and exclusions. Record remaining device and production qualification separately.

Track confirmed unresolved Critical/High findings, the proportion of in-scope scenarios with current evidence, missing scanner targets, time to triage/fix/retest, and recurring defects. Use these measures to decide the next hardening work.
