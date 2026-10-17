# SonarQube Cloud evaluation

The `SonarQube Cloud (evaluation)` job in [CI](../.github/workflows/ci.yml) analyzes handwritten Rust and JavaScript/TypeScript after `core` succeeds. It reuses that run's Clippy and coverage reports without rebuilding or rerunning tests. The job is advisory (`continue-on-error: true`); it does not wait for the quality gate or make it a required merge check. Repository configuration alone is not evidence of a completed Cloud analysis.

## Connected project

The public [Mikaki project](https://sonarcloud.io/project/overview?id=masanork_mikaki) was created in the `masanork` OSS organization on 2026-10-17. The GitHub App is restricted to `masanork/mikaki`; automatic repository import and automatic analysis are disabled. Repository Actions variables are `SONAR_ORGANIZATION=masanork` and `SONAR_PROJECT_KEY=masanork_mikaki`. The `SONAR_TOKEN` repository Actions secret was registered with the owner's approval. The initial automatic main-branch analysis completed before automatic analysis was disabled; this does not verify Rust or CI report imports. A CI-based scan must be verified separately from this connection evidence.

## One-time setup

1. Sign in to [SonarQube Cloud](https://sonarcloud.io/) with GitHub. Use the EU server region to match `sonar.host.url` in [the scanner configuration](../sonar-project.properties).
2. Create or select the SonarQube organization and choose **SonarQube for OSS**. Mikaki is a public repository with MIT / Apache-2.0 licenses. Authorize the GitHub integration for `masanork/mikaki`, import that repository, and keep the SonarQube project public. Public project source and analysis results are publicly visible.
3. Select **With GitHub Actions** as the analysis method. Disable **Automatic Analysis** if it was enabled: Rust and the imported coverage/Clippy reports require CI-based analysis.
4. Copy the actual **organization key** and **project key** shown by SonarQube Cloud. In the repository's **Settings → Secrets and variables → Actions → Variables**, create `SONAR_ORGANIZATION` and `SONAR_PROJECT_KEY` with those values. Display names and GitHub account names are not necessarily the keys.
5. Generate an analysis token in SonarQube Cloud using the account/token controls available to the OSS organization. Store it as the repository Actions **secret** `SONAR_TOKEN`. Do not put the token in repository files, Actions variables, issues, or chat. Use an expiration and rotate the secret before it expires.
6. Once this configuration is on `main`, run `local-authentication-slice` from **Actions → Run workflow**, selecting `main`. Let the main-branch analysis finish before checking PR analysis.
7. Confirm that the job's scan step ran, open the project in SonarQube Cloud, and verify the analyzed commit, Rust and TypeScript coverage imports, and PR feedback on a subsequent same-repository PR. An unconfigured skipped analysis is not a successful scan. Review scanner logs for unresolved report paths or analyzer warnings.

With an appropriately authorized GitHub CLI, the repository settings can also be applied with:

```sh
gh variable set SONAR_ORGANIZATION --repo masanork/mikaki --body '<organization-key>'
gh variable set SONAR_PROJECT_KEY --repo masanork/mikaki --body '<project-key>'
gh secret set SONAR_TOKEN --repo masanork/mikaki
```

The last command prompts for the token. Keep it out of command arguments and shell history.

## Scope and evidence

- Source roots: `crates`, `apps`, `services`, `website`, `local`, and `scripts`, restricted to Rust and JavaScript/TypeScript. Tests are classified separately, including `local/conformance`, test directories, and dedicated Rust test files. Inline Rust test modules remain in their containing files.
- Dependencies, vendored sources, generated bindings/catalogs, declaration files, build output, examples, and test data are excluded. `design/probes`, documentation previews, and fuzz targets are outside the initial source roots.
- `artifacts/clippy-report.json` comes from the existing locked workspace/all-targets Clippy invocation. The JSON stream is saved while rendered diagnostics remain visible in the CI log; `pipefail` preserves the `-D warnings` failure in `core`.
- `artifacts/native-coverage.lcov` comes from the existing native workspace measurement, excluding `mikaki-browser-wasm` and `mikaki-worker`.
- `artifacts/frontend-coverage.lcov` measures flat handwritten `crates/worker/ui/*.ts`, including unloaded modules, excluding `vite.config.ts`. It is Node/V8 coverage, not browser or Svelte DOM coverage.
- Coverage exclusions match these existing measurement boundaries. Static analysis still covers unmeasured applications, Workers, and scripts; their exclusion from the coverage percentage does not establish that they have tests. See [test evidence and limits](test-quality.md).
- Svelte, native mobile languages, dependency audits, and browser/device qualification keep their existing CI checks. This evaluation does not replace them.

## Workflow behavior

The job runs after `core` on pushes to `main`, same-repository pull requests, and manual CI runs. It skips fork PRs and Dependabot, which do not receive the analysis token. A fresh checkout with full history and the exact artifact ID exported by that run's `core` job keeps source, SCM metadata, and reports together. The `sonar-analysis-reports-<attempt>` artifact contains only the three reports, not browser traces or other build artifacts; downloads reject a digest mismatch. The scan does not execute project build scripts or install project dependencies. Only the configuration check and scanner steps receive `SONAR_TOKEN`.

Without the token or either key variable, CI emits a notice and a job summary, then skips the scan. Scanner/report failures remain visible in the job logs but do not fail CI during evaluation. The pinned scan action verifies the scanner download's GPG signature. Do not add this job or the SonarQube quality gate as a required branch-protection check during the evaluation.

After several representative PRs, assess additional actionable findings, overlap with Clippy, false positives, triage effort, and scan duration. Tune new-code scope and quality gates before deciding whether to remove `continue-on-error` and enforce a required check.

## References

- [OSS plan and features](https://docs.sonarsource.com/sonarqube-cloud/administering-sonarcloud/managing-subscription/subscription-plans#oss-plan)
- [GitHub Actions analysis](https://docs.sonarsource.com/sonarqube-cloud/analyzing-source-code/ci-based-analysis/github-actions-for-sonarcloud)
- [Rust analysis and Clippy imports](https://docs.sonarsource.com/sonarqube-cloud/analyzing-source-code/languages/rust)
- [Coverage report parameters](https://docs.sonarsource.com/sonarqube-cloud/analyzing-source-code/test-coverage/test-coverage-parameters)
