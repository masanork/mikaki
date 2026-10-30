# Security CI operations

The [security workflow](../.github/workflows/security-checks.yml) runs Gitleaks and zizmor with inert detection fixtures. The main [CI workflow](../.github/workflows/ci.yml) includes its result in `verify`, so a failing security job prevents the existing verified attestation and deployment paths from proceeding.

## Scanner scope

| Check                 | Scope and enforcement                                                                                                                                                                                                                                          |
| --------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Gitleaks 8.30.1       | All commit history reachable from the checked-out `HEAD`, with checkout depth zero. This includes intermediate commits, not just the final tree. Other branches and unreachable commits are outside this run.                                                  |
| Historical exceptions | [.gitleaksignore](../.gitleaksignore) contains 204 exact historical fingerprints across 14 paths. There are no path-wide or rule-wide exclusions. New commits at those paths remain scanned.                                                                   |
| Redaction and failure | Redact complete credential values, ignore inline `gitleaks:allow` annotations, and fail for unreviewed findings or tool failure. CI does not upload secret reports.                                                                                            |
| zizmor 1.31.1         | Strict collection of workflows, composite actions and Dependabot configuration under `.github`. Gate Medium/High findings using the regular persona in offline mode. Low/informational, pedantic-only and online-only audits remain outside the required gate. |
| Tool integrity        | [Installer](../scripts/install-security-tools.sh) pins Gitleaks, zizmor and OSV-Scanner release versions and SHA-256 asset digests for Linux x86_64 and macOS arm64. A digest mismatch aborts installation. No deployment credential is needed.                |

The [scanner integration tests](../scripts/security-checks.test.ts) verify clean-history acceptance, detection of a new inert provider-shaped credential inside a previously reviewed fixture path, complete report redaction, unsafe event interpolation detection, and failure on malformed workflow collection. They generate the inert credential at runtime in a disposable repository and never push it.

## Historical findings review

The initial Gitleaks run against the history through planning commit `842e80dc86904d789d667b57479b8e9df0f48008` reported 249 matches with 202 distinct commit/path/rule/line fingerprints. Review grouped them as follows:

| Paths                                                                 | Reviewed interpretation                               |
| --------------------------------------------------------------------- | ----------------------------------------------------- |
| `docs/sonarqube-triage-2026-10-17.json`                               | Public analysis and issue identifiers.                |
| `crates/worker/wrangler.production.jsonc`                             | Public operator-card key SHA-256 identifier.          |
| `scripts/plan-owner-vault-reset.test.ts`                              | Synthetic resource identifiers in offline assertions. |
| `local/conformance/support/official-wallet-suite.ts`                  | Public OpenID conformance test identifier.            |
| `local/conformance/worker-readiness.test.ts`                          | Synthetic local Worker readiness token.               |
| `crates/webauthn/testdata/interop-node.json`, `optional.json`         | Offline authenticator-data vectors.                   |
| `crates/webauthn/testdata/attestations.json`, `mds-operations.json`   | Synthetic offline attestation/MDS JWT vectors.        |
| `design/probes/pqc/hpke-pq-draft05-vector.json`                       | Published HPKE test-vector key and shared secret.     |
| `local/conformance/manifest-2026-09-22.json`, `results-2026-09-22.md` | Public source/module SHA-256 measurements.            |

Rebasing onto Wallet/Chat merge `2c139b07` added two generic-rule matches: adjacent `libcrux` dependency names in `design/probes/mls/Cargo.lock`, and ordinary product-scope prose in `docs/wallet-chat-release-readiness.md`. Both received exact historical fingerprints, bringing the total to 204 across 14 paths.

These findings do not establish that every historical credential or secret format is detectable. For a new alert, inspect its provenance privately, revoke/rotate a real credential before treating history cleanup as remediation, and retain the disposition. Add an exact fingerprint only after review with a reason in the ignore file; do not exclude whole test or documentation directories. Review changes to the scanner, installer, workflow and ignore file as security-sensitive changes.

## Workflow hardening

The initial zizmor run identified seven Medium findings: three reusable workflows inherited every caller secret, and four Dependabot ecosystems lacked an explicit seven-day cooldown. The caller now passes only each workflow's named secrets; deployment workflows declare the same optional inputs, preserving their existing runtime validation and environment-secret behavior. The smoke workflow receives only its readiness token.

Dependabot version updates now wait seven days after a release. This setting does not delay Dependabot security updates, according to the [GitHub cooldown reference](https://docs.github.com/en/code-security/reference/supply-chain-security/dependabot-options-reference#cooldown). Automated security updates were separately enabled on 2026-10-21.

Low-severity suggestions to replace existing `./` local action/workflow references with the newer self-repository syntax remain visible in a full zizmor run. The current gate uses the explicit Medium threshold without rule-specific ignore configuration.

## Run locally

Install checksum-verified tools into the ignored generated directory, then run the detection fixtures:

```sh
bash scripts/install-security-tools.sh
MIKAKI_GITLEAKS_BIN="$PWD/local/generated/security-tools/gitleaks" MIKAKI_ZIZMOR_BIN="$PWD/local/generated/security-tools/zizmor" node --test scripts/security-checks.test.ts
local/generated/security-tools/gitleaks git --log-opts=HEAD --ignore-gitleaks-allow --redact=100 --no-banner --log-level=warn --timeout=300 .
local/generated/security-tools/zizmor --offline --strict-collection --min-severity=medium --no-progress .github
```

The history command scans committed changes. Run it again after committing a fix and retain the resulting commit. Untracked/generated files and an uncommitted patch are not equivalent to that history target.

To inspect Low and informational workflow findings, omit `--min-severity=medium`. If a security fixture fails, resolve the tool or detection failure before accepting a clean repository result.

## Dependency advisory policy

[OSV-Scanner 2.7.0](https://github.com/google/osv-scanner/releases/tag/v2.7.0) covers all 18 tracked Cargo/npm/Gradle lockfiles, including native, probe, vendor and fuzz graphs. The [driver](../scripts/check-dependency-advisories.ts) supplies every path explicitly, disables manifest resolution and call analysis, and uses an empty explicit scanner config. It does not run dependency build scripts or honor directory-specific vulnerability suppressions. `--all-packages --all-vulns` retains the complete returned package inventory and findings. OSV network access is required; failure is not accepted as a clean scan.

The gate validates exactly one nonempty, ecosystem-matched result per input. It removes stale reports before invocation and rejects tool errors, malformed reports and incomplete coverage. Git uses `/usr/bin/git`; the scanner must have an absolute executable path, selected from the checksum-verified installation. Children receive the fixed OS `PATH=/usr/bin:/bin`. CI explicitly supplies its runner-temporary scanner path; local runs default to `local/generated/security-tools/osv-scanner`. `artifacts/dependencies/summary.json` records source commit, input hashes, scan time, tool version, graph/package counts, blocking findings, scoped dispositions and maintenance notices. CI retains it and the OSV report for 14 days. A passing policy result means there are no unaccepted actionable findings; it does not mean every dependency is free of vulnerabilities or every code path was analyzed.

Only RustSec records whose every affected entry is explicitly `informational = unmaintained` become maintenance warnings. An `unsound` record remains actionable. The initial scan has six maintenance notices across the GTK and MLS graphs: `proc-macro-error`, `proc-macro-error2`, `zbus_names`, `zvariant` and `zvariant_derive`. They remain in the report for migration planning.

[Reviewed exceptions](../.github/dependency-advisory-exceptions.json) name one lockfile, package, exact version and advisory ID, with owner, reason and expiry. Wildcard versions, expired/invalid entries and unused dispositions fail the gate. Existing `.cargo/audit.toml` does not suppress this scan. The initial 12 exact records expire at **2026-11-20 00:00 UTC**:

| Finding                                                                        | Current disposition and unresolved work                                                                                                                                                                                                                                                                                                         |
| ------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `rsa` 0.9.10 / 0.10.0-rc.19, RUSTSEC-2023-0071 (8 graph/version records)       | The Rust crate performs product public-key verification. Product RS256 private-key signing uses runtime WebCrypto; offline tests use synthetic private keys. Re-review before any Rust-crate private-key operation. Native OIDC/probe graphs retain the same restriction. This is a usage-based disposition, not a patched library.             |
| `glib` 0.18.5, RUSTSEC-2024-0429 and GHSA-wrw7-89jp-8q8g (4 records, 2 graphs) | Tauri GTK3's selected stack requires 0.18; the fix is in 0.20+. No direct `VariantStrIter` use was found in application source, but transitive reachability is not proven safe. **Linux release qualification remains blocked** until a compatible migration/remediation and Linux tests pass. macOS/Android results do not close this finding. |

This change patches `rustls-webpki` to 0.103.16 in all four affected graphs (RUSTSEC-2026-0382), and `webpki-roots` to 1.0.10 in both affected graphs (RUSTSEC-2026-0381). Neither certificate-trust advisory receives an exception. The Identity suite and fresh RustSec scans validate the patch locally; full target builds remain CI evidence.

For RUSTSEC-2026-0387, current `crypto-bigint` graphs are patched to 0.7.6 with
`ctutils` 0.4.5. Three legacy 0.5.5 graphs remain constrained by upstream OIDC/JOSE
dependencies. Their public-verification/HTTP-only usage receives three additional
exact dispositions expiring **2026-11-07 00:00 UTC**, with the dependency paths,
source review and restrictions recorded in [the advisory review](crypto-bigint-advisory-review.md).
Wallet signing and ECDH use the separately patched current dependency. These
three dispositions do not assert that the legacy library is patched or authorize
private-key operations through it.

Run locally after installing the tools:

```sh
node --test scripts/check-dependency-advisories.test.ts
MIKAKI_OSV_BIN="$PWD/local/generated/security-tools/osv-scanner" node scripts/check-dependency-advisories.ts
```

The [policy tests](../scripts/check-dependency-advisories.test.ts) exercise missing/duplicate/outside/empty inputs, malformed data, wrong ecosystems, expired or broadened exceptions, maintenance versus unsound records, and scanner failures with stale reports. A writable-PATH fixture attempts to shadow Git and a scanner child command; both must remain unexecuted. The live scan separately exercises the real three-ecosystem parser and OSV service. See the [inventory](security-verification-inventory.md) for scope that lockfile scanning does not cover.

## Owner authorization attack matrix

`npm run test:security-authorization` runs ten attack/control cases against the emitted default service package (`build/worker/service.mjs`), its Rust Wasm handler, and disposable local D1/R2 in workerd. It supplements the broader [record-store suite](../local/conformance/vault-owner-record-store.test.ts). The `worker-contracts` CI job builds the service package, runs the [matrix](../local/conformance/security-owner-authorization.test.ts), and retains its output, checked-out source commit, and service/shim/Wasm SHA-256 hashes in `authentication-worker-contracts-*` for 14 days. A failed matrix fails the job and therefore `verify`.

| Scenario subset                                                                  | Executed oracle                                                                                                                                                                                                                                                                                     |
| -------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| SEC-01: guessed record IDs, owner headers/query/body, foreign operation receipts | Owner B receives neither A's record nor A's receipt; rejected requests leave heads, mutation receipts, pending-GC uploads, R2 object inventory and ciphertext hashes unchanged.                                                                                                                     |
| SEC-01: identical vault/collection/record/operation IDs in A and B               | Valid B create/update/delete and historical retry operate in B's namespace. A's heads, receipts and referenced ciphertext stay unchanged. A stale update acknowledgment cannot resurrect B's deleted record.                                                                                        |
| SEC-06: absent/revoked session                                                   | Read, list, update and delete return only an authentication error and have no record-storage effects.                                                                                                                                                                                               |
| SEC-06: invalidation after initial authorization                                 | Session revocation, account-epoch change and credential deactivation occur immediately before the real DELETE commit or immediately after the real list query. The commit cannot publish a tombstone/receipt, and the list cannot release selected metadata. Each fault must actually execute once. |

The fixture directly seeds synthetic, valid SSO state and bootstraps wrapped owner keys through HTTP with the product crypto. It does not qualify Passkey login, a browser unlock, exports, Work authorization, lease/logout delivery, enabled Chat, a deployed environment, or physical devices. The narrow binding wrapper only schedules authority changes; it does not substitute SQL or authorization decisions. These are partial SEC-01/06 regressions, not a complete scenario disposition or ASVS compliance assessment.

The selected [ASVS 5.0.0 authorization requirements](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x17-V8-Authorization.md) are `v5.0.0-8.2.2` (L1, access to specific data), `v5.0.0-8.3.1` (L1, enforcement in the trusted service) and `v5.0.0-8.3.2` (L3, immediate authorization changes). The matrix supplies evidence for these requirements only within the record-API scope above. The test checks the running bundle's `/version` commit against the checkout and logs its build cleanliness; an old bundle fails even if its behavior would otherwise pass.

Build and run locally:

```sh
npm ci
npm run build:policy
GITHUB_SHA="$(git rev-parse HEAD)" worker-build --release crates/worker --locked
npm run build:op-authority
npm run test:security-authorization
```

Passing `GITHUB_SHA` locally makes Cargo rerun its source-metadata build script after a new commit; CI already supplies it. Rebuilding the Rust source alone can retain older cached build-script metadata.

Work qualification also sets `pipefail` before piping its test process through `tee`. Without it, the log writer's success can hide a failed test command: main run `39537412997` displayed a successful product job despite two failed, obsolete navigation assertions. The updated journey verifies the Wallet/Chat entry, then explicitly navigates to the separately enabled Work deep link with the real login cookie; it does not restore Work links to normal navigation. Dependent WebMCP cases propagate a failed prerequisite, bound held-request waits, and retain synthetic browser failure evidence instead of stalling until the CI job limit.

## Authentication mix-up and code-race matrix

`npm run test:security-authentication` runs four grouped attack/control cases against the emitted Rust Worker package in two workerd isolates sharing one disposable D1 authority. It creates two native public clients for one synthetic owner through the real administration helper, issues authorization codes through `/authorize`, and exchanges them through `/token`. Both Workers' `/version` source commits must match the checkout. CI retains the source commit, shim/Wasm hashes and output under `security-authentication/` in `authentication-worker-contracts-*` for 14 days; `pipefail` makes a failed matrix fail `verify`.

| Scenario subset                                                             | Executed oracle                                                                                                                                                              |
| --------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| SEC-04: client A names client B's registered callback                       | The OP returns a direct 400 without a redirect and creates no authorization code.                                                                                            |
| SEC-04: client, callback or PKCE substitution at token exchange             | Every attempt returns `invalid_grant`; the exact code remains unconsumed and no token row exists. The original client, callback and verifier still exchange it successfully. |
| SEC-03: the same code is exchanged concurrently through two Worker isolates | Exactly one response succeeds and one token row exists. The configured code-reuse policy revokes that raced issuance rather than leaving an uncertain winner usable.         |
| SEC-03: a valid code is replayed after a successful response                | The matching issuance is revoked. A token issued from another client's independent code remains active.                                                                      |

The matrix compares the actual `authorization_code` and `token_issue` rows, not HTTP status alone. It deliberately uses synthetic seeded SSO state so it does not qualify Passkey ceremony concurrency, an RP's local state/nonce validation, confidential-client assertions, DPoP, browser navigation, remote D1, deployment or physical devices. It is partial SEC-03/04 evidence rather than a complete scenario disposition or ASVS assessment.

Build with the owner matrix prerequisites above, then run:

```sh
npm run test:security-authentication
```

## Service capability attack matrix

`npm run test:security-boundaries` runs nine attack/control cases against the emitted default `service.mjs`, its actual named `AgentStore`, and disposable local D1/R2 in workerd. The calling Worker has named service bindings but no D1/R2 bindings. `/version` must match the checkout's commit; the diagnostic records build cleanliness and the profile. The `worker-contracts` job retains source, service/shim/Wasm hashes and output under `security-boundaries/` in `authentication-worker-contracts-*` for 14 days, with `pipefail` propagating a failed test to `verify`.

| Scenario subset                                                              | Executed oracle                                                                                                                                                                                                                                                                                                                               |
| ---------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| SEC-02: public HTTP or a different named role submits a valid Agent mutation | The public endpoint, default binding and six other named roles return 404; neither forged owner/admin headers nor the valid catalog ID grants AgentStore access. Wrong HTTP methods also deny.                                                                                                                                                |
| SEC-02: uncatalogued OP SQL, caller SQL/owner fields, or SQL-looking values  | Unknown IDs and extra fields deny; SQL-looking bound strings stay literal. A valid mutation followed by an unknown capability has no partial effects.                                                                                                                                                                                         |
| SEC-02: a later statement fails inside the real D1 batch                     | A disposable trigger aborts the second catalogued DELETE. Both rows survive, and all application state stays unchanged. Removing the trigger allows the identical two-statement batch to commit both deletes. This exercises the [D1 batch transaction contract](https://developers.cloudflare.com/d1/worker-api/d1-database/#batch) locally. |
| SEC-18: invalid decoding or input bounds                                     | 64 statements and a 65,536-byte body can perform the positive-control mutation. A 65th statement, one extra body byte, an empty batch, malformed values/JSON, or invalid UTF-8 deny. Every denial has the exact generic error without echoing input.                                                                                          |

Rejected requests compare every application table and table/trigger definition plus the complete R2 object inventory and byte hashes. Internal SQLite/Cloudflare bookkeeping is excluded. Successful controls prove that the tested capability can read and actually commit; they restore their synthetic fixture. The trigger changes only the disposable database, without replacing product SQL, authorization code or D1 adapters.

AgentStore is a privileged binding carrying the complete Agent catalog. It does not derive an owner session or constrain each caller to one owner's parameters; those checks belong to the Agent/OP request paths and SQL predicates. This matrix therefore does not qualify per-owner Agent grants, OAuth, selected release, Work admission, enabled Chat, remote D1, deployment, or devices. It supplements the existing service and package boundary suites and supplies partial SEC-02/18 evidence, not a complete scenario disposition or ASVS assessment.

Local sensitivity checks separately weakened strict-field validation, replaced the transaction with individual statement runs, enabled lossy UTF-8 decoding, and raised the body limit by one byte. Each mutation failed its intended case. The original source was restored byte-for-byte, the service package rebuilt, and all nine cases passed again. These are detection checks, not confirmed vulnerabilities in the original implementation.

Build with the same prerequisites as the owner matrix above, then run:

```sh
npm run test:security-boundaries
```

## Agent grant disclosure and commit matrix

`npm run test:security-grants` runs sixteen attack/control cases against the emitted default OP package, the actual checked-in Agent Worker, real service bindings, and disposable local D1/R2. It supplements the [Node/SQLite grant model](../local/conformance/agent-record-grants.test.ts) and the [paired Worker integration](../local/conformance/agent-worker.test.ts). The Agent has neither a D1 nor an R2 binding. Synthetic SSO state is seeded directly; wrapped owner keys, encrypted personal records, grants, consent and token exchange use actual HTTP routes and product crypto. OAuth redirects are inspected without following them to external hosts.

| Scenario subset                   | Executed oracle                                                                                                                                                                                                                                                                                                                                                                                                                              |
| --------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Selected ownership and scope      | Owners A/B use the same vault/record names but receive their own selected snapshots. A read-only OAuth token cannot list or propose; B's revoke of A's known grant ID is a no-op. Status is owner-scoped. Mismatched owner, digest or key authority cannot become approved consent or issue a token; a matching control succeeds.                                                                                                            |
| Token lifecycle                   | Concurrent redemption of one Agent OAuth code creates one token and one invalid-grant response. The issued token remains usable. Expired grants reject both direct and OAuth tokens at the HTTP authentication gate. The expiry fixture moves its synthetic stored deadline into the past; it does not simulate a browser clock.                                                                                                             |
| Final disclosure authority        | Token/client revocation, source revision, recipient disable, credential disable and account-epoch changes commit after the authorized-access audit but before its service response returns. The final Agent gate suppresses all decrypted content and metadata. A retry receives the authentication challenge. Token/client revocation leaves the separate direct grant usable; source/key/account invalidation stops and clears that grant. |
| Exact private-draft admission     | A changed approval hash or another owner's grant cannot create a draft. Token, grant or client revocation committed immediately before the real execute batch prevents a draft and an executed audit outcome, even when initial authentication already succeeded.                                                                                                                                                                            |
| Unknown outcome and audit failure | A deliberately lost execute acknowledgment leaves one committed, exact owner-approved private draft. Concurrent retries recover the same draft ID without adding a draft. An unavailable access audit suppresses plaintext; restoring the audit permits the valid read.                                                                                                                                                                      |

The narrow named-entrypoint wrapper schedules real D1 mutations or loses one actual service acknowledgment. It preserves input bytes, catalogued SQL, results and authorization decisions. Each armed fault must complete exactly once. A disposable trigger supplies the audit-write failure. Record heads, mutation receipts and the complete R2 inventory/byte hashes are compared; the declared source-revision fault is the only expected head change. Proposal/draft identities, owner, payload, state and audit counts establish durable effects. An `authorized` audit row records an authorization decision, not successful plaintext delivery; the post-audit cases also require a denied outcome and a response with no structured content.

The `worker-contracts` job saves source commit, OP service/shim/Wasm hashes, checked-in Agent source hashes and results under `security-grants/` in `authentication-worker-contracts-*` for 14 days. `pipefail` propagates test failures. `/version` must match the checkout; the diagnostic reports build cleanliness and fixture profile. The Agent source is bundled by the test harness, not qualified as a promoted release artifact.

The local sensitivity pilot separately removed the final grant refresh, the execute batch's token condition, and its approved-hash comparison. SQL mutations retained bind arity and regenerated the capability catalog. The intended cases detected returned plaintext or a durable unauthorized draft despite an error response. Original source and catalog bytes were restored, the OP service rebuilt, and all sixteen cases passed. These controlled regressions validate the response and storage oracles.

This supplies scoped evidence for [ASVS 5.0.0 authorization requirements](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x17-V8-Authorization.md) `8.2.1`/`8.2.2` (L1, function/data permissions), `8.3.1` (L1, trusted service enforcement) and `8.3.2` (L3, immediate authorization changes). It is partial SEC-06/09 evidence, not complete ASVS compliance. It does not qualify browser/physical Passkeys, an external OAuth/MCP consumer, native/OP OIDC code-reuse policies, selected recipient UserInfo, remote D1, enabled Chat or Work external effects. A private-draft retry is not evidence that a remote side effect can safely be repeated.

Build with the owner matrix prerequisites above, then run:

```sh
npm run test:security-grants
```

## Identity trust expiry monitoring

The read-only [trust freshness workflow](../.github/workflows/identity-trust-freshness.yml)
runs every six hours at minute 17 UTC, after relevant changes reach main, and by
manual dispatch. `npm run check:identity-trust-freshness` invokes the actual Rust
`check_haip_pki` example with the current clock. It validates the public bundle,
including both Issuer and Wallet credential chains and CRLs, and preserves the
seven rejection checks. It reports the earliest certificate/CRL freshness deadline
for each credential purpose and the Attester certificate chain. The report is
bound to the public bundle's byte SHA-256 and checked-out source commit.

For the operator card policy, the public
[deadline records](../crates/worker/config/identity-card-trust-deadlines.public.json)
contain only exact compact-policy hashes and reviewed expiry timestamps. The
monitor selects the hash in `wrangler.production.jsonc`; an unknown hash or a
duplicate/malformed record fails validation. The original policy ends at
`2026-10-21T13:14:39Z`. The separately reviewed renewal in
[PR #288](https://github.com/masanork/mikaki/pull/288) ends at
`2026-10-28T21:43:47Z`. Retaining both records does not select or authorize the
renewal: an expired selected policy still fails while its renewal is unselected.
The approved 2026-10-30 renewal selects exact policy
`2ff30cc2bfa66e9f4db008456e3c1f18a7425bc7983d48d84ef3162f47e8258f`,
ending `2026-11-06T09:38:47Z`; all three historical records are retained.
Record any future approved policy's exact hash and minimum `not_after` together
with its source selection; preserve the previous record for review.

Any selected deadline at or within **48 hours** fails the monitor and emits an
Actions error annotation; an expired deadline is marked separately. The JSON
report is retained for 14 days even when the check fails. The job has read-only
repository permission, no production environment and no deployment or CA secrets.
It does not renew CRLs, extend approval periods or change runtime configuration.
The existing deployment preflight independently checks the actual secret policy's
live validity and exact reviewed hash. Public deadline metadata cannot prove that
the matching secret is provisioned or that the selected bytes reached production
or an installed Wallet; deployment smoke and device qualification remain separate.

An already expired certificate or CRL still fails the current-time Rust check.
For a structurally readable bundle, the checker preserves public time bounds as
**unverified diagnostics**, with a separate nonzero-exit report. The monitor keeps
overall `status: invalid` and `pki_validation: rejected`, labels elapsed PKI bounds
`expired`, and labels other unvalidated PKI bounds `unverified`. These diagnostics
cannot produce a healthy result or establish signature/path validity. Successful
validation still requires the actual Issuer/Wallet validators and all rejection
controls. Malformed or otherwise invalid inputs retain the generic failure path.

The [boundary and failure tests](../scripts/check-identity-trust-freshness.test.ts)
run in main CI, covering all six deadline slots, the exact warning/expiry
boundaries, selected versus unselected policies, incomplete/stale/substituted PKI
reports, unknown policy records, sanitized validator failures and executable
shadowing. A genuine expired, signed public CRL fixture also passes through the
actual Rust checker and CLI; the check must retain its component/deadline while
failing. The fixture's signature is checked independently, without changing the
clock, and the test never accepts expired trust. On Linux/macOS the CLI uses
`/usr/bin/git` and Cargo from the absolute
trusted `CARGO_HOME` installation (default `~/.cargo`), bypassing npm/PATH executable
shadowing. Relative or empty `CARGO_HOME` values fail validation. The scheduled
monitor is independent of the PR's required `verify` gate, so urgent repairs can
still pass normal verification while a deadline alert is active.

Scheduled runs start after this workflow reaches the default branch. GitHub may
delay scheduled execution; the six-hour cadence is not an availability guarantee.
Keep the workflow enabled and check its Actions status. Email/web delivery depends
on the maintainer's [Actions notification settings](https://docs.github.com/en/actions/concepts/workflows-and-actions/notifications-for-workflow-runs);
no external messages or notification integrations are configured here. See
[GitHub's schedule behavior](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule)
and the [same-CA CRL renewal procedure](identity-labpki.md#renew-the-selected-snapshots-without-rotating-trust).

## Hosted repository settings

GitHub Secret Protection and repository Push protection were enabled and observed in the repository settings on 2026-10-20. Private vulnerability reporting was already enabled. These settings are independent of the source-controlled Gitleaks gate and its fingerprints.

On 2026-10-21, the dependency graph was confirmed available through its SBOM endpoint (1,667 packages at inspection); Dependabot alerts and automated security updates were enabled and read back through the API. That provider-side graph is independent of the 18 explicit lockfile scans and does not establish identical coverage.

The [main integrity ruleset](../.github/main-integrity-ruleset.json), ID `25512697`, is active: no deletion or non-fast-forward update of `main`, with no bypass actors. The separate [main verification configuration](../.github/main-verification-ruleset.json), ID `25512913`, now declares the **active** target. It requires a PR, resolved review threads, and seven checks from the GitHub Actions app (15368): `verify`, `dependency-advisories`, `native-client`, `jose-probes`, `android-client`, `android-verifier`, `website`, against an up-to-date main. Zero mandatory approvals supports this single-maintainer repository; this is not an independent-review requirement. The checked-in target alone does not prove enforcement; confirm hosted state through the API below.

The metrics prerequisite merged in PR #280: CI has read-only contents permission and saves `project-metrics-*` artifacts for reviewed publication instead of pushing directly to `main`. Before applying the active target, confirm that the seven named checks have succeeded on the current main commit. Recheck main's SHA before applying; a cancelled or superseded run does not satisfy this gate. Do not grant the Actions app a broad bypass. Checked-in charts/history now need a publication PR; see [metrics operations](../metrics/README.md). The old `publish-metrics.sh` is no longer invoked by CI and cannot bypass the new rules with its token.

After the prerequisite is merged and verified, activate the reviewed configuration and read it back:

```sh
ruleset_file="$(mktemp)"
jq '.enforcement = "active"' .github/main-verification-ruleset.json > "$ruleset_file"
gh api --method PUT repos/masanork/mikaki/rulesets/25512913 --input "$ruleset_file"
rm "$ruleset_file"
gh api repos/masanork/mikaki/rulesets/25512913 --jq '{id, enforcement, bypass_actors, rules}'
```

Keep the checked-in enforcement value aligned when activation happens. Required checks are a separate control from release attestations and deployed runtime verification.

Use the [verification inventory](security-verification-inventory.md) for the next dependency-coverage work and the [assurance plan](security-assurance-plan.md) for authorization tests, DAST and independent review.
