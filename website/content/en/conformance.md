---
type: article
profile: sorane-okf/0.1
title: 'mikaki conformance results — OpenID, FAPI and FIDO'
description: 'Dated OpenID Connect, logout, FAPI 2.0, FIDO2 Server and OID4VC test results, tool versions, tested configurations and remaining qualification work.'
lang: en
translation_key: conformance
updated: 2026-10-03
---

This index collects conformance evidence published in the mikaki repository. **mikaki has no formal OpenID, FAPI or FIDO certification.** Results apply only to the recorded date, version and configuration. They do not certify the current production deployment or every device.

## Reading verdicts

`PASSED` means the module succeeded. `REVIEW` requires human assessment, `SKIPPED` was not executed for the selected configuration, and `WARNING` retains a warning. Reviews and skips are not passes. Zero failures does not establish optional-feature coverage or completed certification review.

Counts below describe the latest recorded run units. Individual reruns are not added to inflate module totals; native and Wasm are separate executions.

## OpenID Connect OP

**September 29, 2026 / OIDF Conformance Suite 5.3.1, rev `4bfcdf8`.** Isolated Rust Worker, workerd, disposable D1, HTTPS and Chromium virtual passkeys.

| Plan | Result |
| --- | --- |
| Config OP | 1 PASSED |
| Basic OP, 35 modules | 22 PASSED, 4 REVIEW, 8 SKIPPED, 1 WARNING, 0 FAILED |

Reviews include authentication and unregistered-redirect screenshots. An optional name request retains a warning; unsupported optional scopes, request objects and refresh tokens can be skipped. No fabricated profile attribute was added to silence the warning.

See the [run record](https://github.com/masanork/mikaki/blob/main/docs/oidf-conformance-2026-09-29.md) and [machine-readable module/version/build evidence](https://github.com/masanork/mikaki/blob/main/design/probes/oidf/results-2026-09-29.json).

## OpenID Connect logout

**September 27, 2026 / OIDF Conformance Suite 5.3.1.** Local OP fixture, Code flow and Chromium virtual passkeys.

| Plan | Result |
| --- | --- |
| RP-Initiated Logout, 11 modules | 3 PASSED, 8 REVIEW, none unfinished |
| Back-Channel Logout | 2 PASSED: Discovery and RP-initiated notification |

Local screenshot inspection did not change the eight REVIEW verdicts. Back-Channel evidence covers one successful delivery path. **Certificate verification was disabled only in that local test process** to work around the fixture/receiver hostname mismatch. This does not qualify production TLS, all retries or receiver failures. Read the [execution and limitations](https://github.com/masanork/mikaki/blob/main/docs/oidc-logout-conformance.md).

## FAPI 2.0 Security Profile

**September 30, 2026 / OIDF Conformance Suite 5.3.1, rev `4bfcdf8`.** Isolated Final AS with the selected `plain_fapi`, `private_key_jwt`, DPoP and OIDC profile; local HTTPS relay and virtual passkeys.

| Latest complete run | Result |
| --- | --- |
| Final AS, 52 modules | 45 PASSED, 4 REVIEW, 3 SKIPPED, 0 FAILED, none unfinished |

Four reviews cover direct authorization without PAR and reused, expired or wrong-client references. Three conditional skips concern claims selection, an RSA client-signature case for the selected configuration, and refresh tokens. The first traversal recorded 36 PASSED, 8 FAILED, 3 REVIEW, 3 SKIPPED and 2 unfinished; implementation fixes and execution corrections produced the result above.

See the [fixes and rerun record](https://github.com/masanork/mikaki/blob/main/docs/fapi2-conformance-2026-09-30.md) and [readiness report](https://github.com/masanork/mikaki/blob/main/docs/fapi2-readiness.md). Production-edge TLS, independent client/resource-server qualification and human review remain separate work.

## FIDO2 Server

**September 29, 2026 / FIDO Conformance Tools 1.9.2.** Development runs of isolated adapters with all Server Tests and ten optional checkboxes selected.

| Target | Result |
| --- | --- |
| Native adapter | 167 passes, 0 failures |
| Wasm adapter | 167 passes, 0 failures |

The test configuration accepts broader algorithms and attestation than normal product settings. MDS explicitly used `mds3.0`; strict defaults were retained. The tool marked ES256K pending and did not execute it. Submission, frozen target version/configuration, MDS requirements and interoperability testing remain open.

See [certification readiness](https://github.com/masanork/mikaki/blob/main/docs/webauthn-certification-readiness.md), [detailed runs](https://github.com/masanork/mikaki/blob/main/local/conformance/results-2026-09-28.md) and [real-device evidence](https://github.com/masanork/mikaki/blob/main/docs/webauthn-device-compatibility.md).

## Bounded OID4VC component tests

**September 29, 2026 / OIDF Conformance Suite 5.3.1, rev `4bfcdf8`.** Separate synthetic-data components, not the public IdP.

| Target | Result and scope |
| --- | --- |
| OID4VCI issuer metadata | 1 PASSED; metadata from OWF 0.6.0 only |
| Nine selected OID4VP verifier modules | 7 PASSED, 2 REVIEW; verifier integration using `@openeudi/openid4vp` 0.12.0 |

The OID4VCI adapter exposes no token, nonce or credential endpoint. Metadata success does not qualify issuance or DPoP. OID4VP covers synthetic PID, URL query, `direct_post`, and `dc+sd-jwt`/ES256. Happy flow and minimal `cnf.jwk` were accepted and retain REVIEW with receipt evidence. Seven negative cases cover signatures, audience, nonce, `sd_hash` and times. Full wallet/verifier plans, HAIP, mdoc and signed requests are outside the subset. See the [targets and evidence](https://github.com/masanork/mikaki/blob/main/docs/oidf-conformance-2026-09-29.md).

## Supplementary checks and certification

CI, component tests and device checks are separate from these conformance runs. Supplementary [DPoP evidence](https://github.com/masanork/mikaki/blob/main/docs/fapi2-readiness.md), including 45 component/policy scenarios and 11 loopback HTTPS scenarios, is not added to official module pass counts.

Formal certification follows the target-version, profile, submission and review requirements of the [OpenID Foundation](https://openid.net/certification/) or [FIDO Alliance](https://fidoalliance.org/certification/functional-certification/functional-certification-servers/). A newer implementation passing CI does not change these dates or certification status. This index changes when a rerun configuration and verdicts have a published record. Private keys, tokens and raw user data are not publication artifacts.

## Read next

- [Specifications and standards](specifications.md): Check public IdP connection capabilities.
- [Security and status](security.md): Review Vault, device compatibility and adoption limits.
