# Security CI operations

The [security workflow](../.github/workflows/security-checks.yml) runs Gitleaks and zizmor with inert detection fixtures. The main [CI workflow](../.github/workflows/ci.yml) includes its result in `verify`, so a failing security job prevents the existing verified attestation and deployment paths from proceeding.

## Scanner scope

| Check | Scope and enforcement |
| --- | --- |
| Gitleaks 8.30.1 | All commit history reachable from the checked-out `HEAD`, with checkout depth zero. This includes intermediate commits, not just the final tree. Other branches and unreachable commits are outside this run. |
| Historical exceptions | [.gitleaksignore](../.gitleaksignore) contains 204 exact historical fingerprints across 14 paths. There are no path-wide or rule-wide exclusions. New commits at those paths remain scanned. |
| Redaction and failure | Redact complete credential values, ignore inline `gitleaks:allow` annotations, and fail for unreviewed findings or tool failure. CI does not upload secret reports. |
| zizmor 1.31.1 | Strict collection of workflows, composite actions and Dependabot configuration under `.github`. Gate Medium/High findings using the regular persona in offline mode. Low/informational, pedantic-only and online-only audits remain outside the required gate. |
| Tool integrity | [Installer](../scripts/install-security-tools.sh) pins Gitleaks, zizmor and OSV-Scanner release versions and SHA-256 asset digests for Linux x86_64 and macOS arm64. A digest mismatch aborts installation. No deployment credential is needed. |

The [scanner integration tests](../scripts/security-checks.test.ts) verify clean-history acceptance, detection of a new inert provider-shaped credential inside a previously reviewed fixture path, complete report redaction, unsafe event interpolation detection, and failure on malformed workflow collection. They generate the inert credential at runtime in a disposable repository and never push it.

## Historical findings review

The initial Gitleaks run against the history through planning commit `842e80dc86904d789d667b57479b8e9df0f48008` reported 249 matches with 202 distinct commit/path/rule/line fingerprints. Review grouped them as follows:

| Paths | Reviewed interpretation |
| --- | --- |
| `docs/sonarqube-triage-2026-10-17.json` | Public analysis and issue identifiers. |
| `crates/worker/wrangler.production.jsonc` | Public operator-card key SHA-256 identifier. |
| `scripts/plan-owner-vault-reset.test.ts` | Synthetic resource identifiers in offline assertions. |
| `local/conformance/support/official-wallet-suite.ts` | Public OpenID conformance test identifier. |
| `local/conformance/worker-readiness.test.ts` | Synthetic local Worker readiness token. |
| `crates/webauthn/testdata/interop-node.json`, `optional.json` | Offline authenticator-data vectors. |
| `crates/webauthn/testdata/attestations.json`, `mds-operations.json` | Synthetic offline attestation/MDS JWT vectors. |
| `design/probes/pqc/hpke-pq-draft05-vector.json` | Published HPKE test-vector key and shared secret. |
| `local/conformance/manifest-2026-09-22.json`, `results-2026-09-22.md` | Public source/module SHA-256 measurements. |

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

The gate validates exactly one nonempty, ecosystem-matched result per input. It removes stale reports before invocation and rejects tool errors, malformed reports and incomplete coverage. `artifacts/dependencies/summary.json` records source commit, input hashes, scan time, tool version, graph/package counts, blocking findings, scoped dispositions and maintenance notices. CI retains it and the OSV report for 14 days. A passing policy result means there are no unaccepted actionable findings; it does not mean every dependency is free of vulnerabilities or every code path was analyzed.

Only RustSec records whose every affected entry is explicitly `informational = unmaintained` become maintenance warnings. An `unsound` record remains actionable. The initial scan has six maintenance notices across the GTK and MLS graphs: `proc-macro-error`, `proc-macro-error2`, `zbus_names`, `zvariant` and `zvariant_derive`. They remain in the report for migration planning.

[Reviewed exceptions](../.github/dependency-advisory-exceptions.json) name one lockfile, package, exact version and advisory ID, with owner, reason and expiry. Wildcard versions, expired/invalid entries and unused dispositions fail the gate. Existing `.cargo/audit.toml` does not suppress this scan. The initial 12 exact records expire at **2026-11-20 00:00 UTC**:

| Finding | Current disposition and unresolved work |
| --- | --- |
| `rsa` 0.9.10 / 0.10.0-rc.19, RUSTSEC-2023-0071 (8 graph/version records) | The Rust crate performs product public-key verification. Product RS256 private-key signing uses runtime WebCrypto; offline tests use synthetic private keys. Re-review before any Rust-crate private-key operation. Native OIDC/probe graphs retain the same restriction. This is a usage-based disposition, not a patched library. |
| `glib` 0.18.5, RUSTSEC-2024-0429 and GHSA-wrw7-89jp-8q8g (4 records, 2 graphs) | Tauri GTK3's selected stack requires 0.18; the fix is in 0.20+. No direct `VariantStrIter` use was found in application source, but transitive reachability is not proven safe. **Linux release qualification remains blocked** until a compatible migration/remediation and Linux tests pass. macOS/Android results do not close this finding. |

This change patches `rustls-webpki` to 0.103.16 in all four affected graphs (RUSTSEC-2026-0382), and `webpki-roots` to 1.0.10 in both affected graphs (RUSTSEC-2026-0381). Neither certificate-trust advisory receives an exception. The Identity suite and fresh RustSec scans validate the patch locally; full target builds remain CI evidence.

Run locally after installing the tools:

```sh
node --test scripts/check-dependency-advisories.test.ts
MIKAKI_OSV_BIN="$PWD/local/generated/security-tools/osv-scanner" node scripts/check-dependency-advisories.ts
```

The [policy tests](../scripts/check-dependency-advisories.test.ts) exercise missing/duplicate/outside/empty inputs, malformed data, wrong ecosystems, expired or broadened exceptions, maintenance versus unsound records, and scanner failures with stale reports. The live scan separately exercises the real three-ecosystem parser and OSV service. See the [inventory](security-verification-inventory.md) for scope that lockfile scanning does not cover.

## Hosted repository settings

GitHub Secret Protection and repository Push protection were enabled and observed in the repository settings on 2026-10-20. Private vulnerability reporting was already enabled. These settings are independent of the source-controlled Gitleaks gate and its fingerprints.

On 2026-10-21, the dependency graph was confirmed available through its SBOM endpoint (1,667 packages at inspection); Dependabot alerts and automated security updates were enabled and read back through the API. That provider-side graph is independent of the 18 explicit lockfile scans and does not establish identical coverage.

The [main integrity ruleset](../.github/main-integrity-ruleset.json), ID `25512697`, is active: no deletion or non-fast-forward update of `main`, with no bypass actors. The separate [main verification ruleset](../.github/main-verification-ruleset.json), ID `25512913`, is staged **disabled**. It requires a PR, resolved review threads, and seven checks from the GitHub Actions app (15368): `verify`, `dependency-advisories`, `native-client`, `jose-probes`, `android-client`, `android-verifier`, `website`, against an up-to-date main. Zero mandatory approvals supports this single-maintainer repository; this is not an independent-review requirement.

Before activating verification, merge this change and confirm the seven named checks on the resulting main commit. The metrics job previously pushed directly to `main`; this change removes its write permission and saves `project-metrics-*` artifacts for reviewed publication instead. Do not grant the Actions app a broad bypass. Checked-in charts/history now need a publication PR; see [metrics operations](../metrics/README.md). The old `publish-metrics.sh` is no longer invoked by CI and cannot bypass the new rules with its token.

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
