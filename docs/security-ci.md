# Security CI operations

The [security workflow](../.github/workflows/security-checks.yml) runs Gitleaks and zizmor with inert detection fixtures. The main [CI workflow](../.github/workflows/ci.yml) includes its result in `verify`, so a failing security job prevents the existing verified attestation and deployment paths from proceeding.

## Scanner scope

| Check | Scope and enforcement |
| --- | --- |
| Gitleaks 8.30.1 | All commit history reachable from the checked-out `HEAD`, with checkout depth zero. This includes intermediate commits, not just the final tree. Other branches and unreachable commits are outside this run. |
| Historical exceptions | [.gitleaksignore](../.gitleaksignore) contains 204 exact historical fingerprints across 14 paths. There are no path-wide or rule-wide exclusions. New commits at those paths remain scanned. |
| Redaction and failure | Redact complete credential values, ignore inline `gitleaks:allow` annotations, and fail for unreviewed findings or tool failure. CI does not upload secret reports. |
| zizmor 1.31.1 | Strict collection of workflows, composite actions and Dependabot configuration under `.github`. Gate Medium/High findings using the regular persona in offline mode. Low/informational, pedantic-only and online-only audits remain outside the required gate. |
| Tool integrity | [Installer](../scripts/install-security-tools.sh) pins release versions and SHA-256 archive digests for Linux x86_64 and macOS arm64. A digest mismatch aborts installation. No scanner cache or deployment credential is needed. |

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

Dependabot version updates now wait seven days after a release. This setting does not delay Dependabot security updates, according to the [GitHub cooldown reference](https://docs.github.com/en/code-security/reference/supply-chain-security/dependabot-options-reference#cooldown). Enabling automated security updates and verifying dependency graph coverage remain separate repository settings.

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

## Hosted repository settings

GitHub Secret Protection and repository Push protection were enabled and observed in the repository settings on 2026-10-20. Private vulnerability reporting was already enabled. These settings are independent of the source-controlled Gitleaks gate and its fingerprints.

At that inspection, the dependency graph, Dependabot alerts and automated security updates were disabled. The API reported no main branch protection and no rulesets. The `verify` dependency enforces the configured promotion path; enforcing successful checks before every merge or direct push requires a separately configured branch rule. Review the intended merge/update workflow before activating that rule.

Use the [verification inventory](security-verification-inventory.md) for the next dependency-coverage work and the [assurance plan](security-assurance-plan.md) for authorization tests, DAST and independent review.
