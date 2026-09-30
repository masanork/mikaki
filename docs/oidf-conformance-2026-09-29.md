# OIDF network conformance evidence (2026-09-29)

This run extends the [OIDC OP record](oidc-core-conformance.md) and the bounded [OID4VCI receipt](oid4vci-probe.md) / [OID4VP presentation](oid4vp-probe.md) probes. It distinguishes the current Rust OP from synthetic credential components. The [content-free machine record](../design/probes/oidf/results-2026-09-29.json) includes every selected module, suite IDs, exact verdicts, component versions and build/lock fingerprints. No formal certification or independent wallet-application result is claimed.

## Environment and scope

The existing local OIDF suite reported **5.3.1**, revision **4bfcdf8**, tag `release-v5.3.1`, built 2026-09-25. Its server image ID was `sha256:b92d3889c334ffbfcaf80aed1d2fe5e58058418d98e210331ea1e09f482cafe1`. The host ran Node 26.10.0 on macOS. Tests used generated signing/holder keys and synthetic accounts/credentials. Raw logs, private keys, client secrets and screenshots remain ignored under `local/generated/`; only allow-listed result fields are exported.

| Target | Counterparty and profile | Qualified boundary |
| --- | --- | --- |
| OIDC | Current Rust Worker in workerd, ephemeral D1, HTTPS, Chromium virtual passkey; Basic OP discovery/static registration and Config OP | Real OP endpoints, passkey authentication, consent, token exchange, UserInfo and negative cases in the isolated conformance deployment |
| OID4VCI | Existing OWF 0.6.0 synthetic issuer metadata exposed over HTTPS; `oid4vci-1_0-issuer-metadata-test` | Credential metadata only; no token, nonce or credential endpoint is exposed by this adapter |
| OID4VP | OIDF emulated wallet posts over HTTPS to `@openeudi/openid4vp` 0.12.0 with harness-owned session/time checks | Independent verifier component integration; synthetic PID, `redirect_uri`, URL query, `direct_post`, `dc+sd-jwt`/ES256 |

The VP network adapter intentionally uses a **separate PID/redirect_uri profile**. It does not change or qualify the membership probe's preregistered verifier, exact membership disclosure, issuer identity or synthetic status policy. It pins a generated suite credential public key, verifies holder binding, DCQL, nonce, audience, signatures and time, and consumes the matching state before asynchronous verification. Its receipt page reports the actual component decision without rendering claim values. Membership/wallet/product exclusions remain open where applicable.

## Verdicts and diagnostics

Config OP discovery finished **PASSED**, plan `vQkETO2BloaIB`, module `91Z7fWD5ZkEVpvq`. Basic OP plan `AwJ4SgANFpsos` finished all 35 listed modules: **22 PASSED, 4 REVIEW, 8 SKIPPED, 1 WARNING, 0 FAILED**. The `acr_values` module that warned in the historical full run now passes. Exact results are in the machine record.

The first Basic OP attempt, `uyhLOSuRPNpVP`, left `prompt-login` and `max-age-1` waiting for screenshots. The driver could race conditional passkey navigation, and capturing the prompt as PNG exceeded the suite's **500KB decoded image limit**. Followups confirmed the suite's explicit size error. The driver now holds virtual authenticator presence while capturing the actual login prompt, uses a viewport JPEG within the limit, preserves the screenshot privately, and returns a nonzero exit code for unfinished/failed runs. These are driver corrections, not OP authentication bypasses. `auth_time` checks succeeded during the failed-upload followup, but that followup is not counted as a finished conformance result.

The voluntary `name` request can produce a **WARNING** because this OP does not release a name in UserInfo. Do not add fabricated profile data to silence the test. Optional scopes, unsupported request objects and refresh tokens can be **SKIPPED**. Screenshot-based modules remain **REVIEW** after upload; uploading a picture does not inspect its contents or turn it into PASSED.

Local visual inspection of all four Basic OP screenshots confirmed the actual passkey prompt for `prompt-login`/`max-age-1` and the unregistered redirect error for both redirect-URI modules. Their suite verdicts remain REVIEW; this inspection is not certification approval.

OID4VCI metadata finished **PASSED**, plan `vDLbeAjPfxHPJ`, module `FTV7udgzmSFLdYz`. The issuer plan's `private_key_jwt`/DPoP configuration selects the suite profile; this metadata-only adapter implements neither feature and does not claim that the issuance plan passes. The existing anonymous bearer pre-authorized receipt fixture cannot simply be labelled a DPoP/client-authenticated issuer or wallet.

OID4VP selected nine compatible verifier modules: invalid credential signature, KB audience, KB nonce, KB signature, `sd_hash`, future `iat` and past `iat` are **PASSED**; happy flow and minimal `cnf.jwk` are accepted and finish **REVIEW** with actual receipt screenshots. All nine accept/reject decisions match their expected outcomes. Request-URI/signed-request and mdoc session-transcript tests are outside this selected URL-query SD-JWT subset. It is not a complete verifier plan or HAIP profile.

## Repeatable commands

Start a local OIDF dev-mode suite with API `https://localhost:8443` and internal hostname `suite-frontend`. Docker must reach `host.docker.internal`. These adapters are fixed to local ports and use a self-signed certificate for synthetic tests; the credential client TLS exception is restricted to localhost/suite-frontend on port 8443.

```sh
npm ci --ignore-scripts
npm ci --prefix design/probes --ignore-scripts
npm run build:policy
worker-build --release crates/worker
mkdir -p local/generated
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
  -keyout local/generated/oidf-local.key -out local/generated/oidf-local.crt \
  -subj /CN=host.docker.internal \
  -addext subjectAltName=DNS:host.docker.internal,DNS:localhost
node local/conformance/oidf-local-worker.ts
```

In a second terminal, run OIDC serially against the same fixture. Use the printed signature counter as the next browser run's initial counter, or restart the fixture for a fresh credential. Config OP does not authenticate and does not increment the persisted counter.

```sh
node local/conformance/run-passkey-oidf.ts all 1 oidcc-basic-certification-test-plan
node local/conformance/run-passkey-oidf.ts all 1 oidcc-config-certification-test-plan
# Both credential adapters use port 8793; run them serially.
npm run probe:oidf-metadata --prefix design/probes
npm run probe:oidf-verifier --prefix design/probes
# Supply the actual plan IDs printed by the OIDC runs.
node design/probes/oidf/report.ts BASIC_PLAN_ID CONFIG_PLAN_ID
```

The report command exports only summary fields and returns nonzero for unfinished or failed modules or a mismatched VP decision. `REVIEW`, `WARNING` and `SKIPPED` retain their distinct verdicts; exit zero is not a statement that every module passed. The drivers close their own temporary credential servers and stop only their own unfinished suite modules. OIDF network/browser tests require local suite services and stay outside ordinary CI; the existing 70 deterministic component cases continue in CI.

## Doma reference and remaining work

The read-only reference was `~/repo/doma` at `e01061050fbbb2467b055b3856a84e9e575d0cdf`, particularly `harnesses/oidf-conformance/driver/src/{suite-client,plan-configs,driver}.ts`. Its role/variant selection and exposed authorization-endpoint orchestration informed this adapter. Doma's results are not Mikaki results, and no Doma files or running suite deployment were changed.

Doma's `harnesses/wwwallet-interop` scenario A connects a custom headless holder harness to wwWallet's issuer/authorization server. Its wallet-frontend browser VP scenario B is documented as future work. Consequently that record does not establish wallet-application E2E coverage that can be copied into Mikaki's evidence.

Next select the deployment/credential use case before expanding the receipt profile: qualify Final wire interoperability against a pinned full issuer with either the current anonymous pre-authorized contract or a deliberately added Authorization Code/PKCE, client-authentication and DPoP contract. Then run a pinned wallet application's actual import/consent/presentation UI over HTTPS. Record frontend/backend revisions, discovered profile, expected negative behavior, original artifact/holder preservation and credential trust/status. Hardware PRF, holder recovery/transfer/deletion and a production credential store remain separate adoption gates. Certification requires its own accepted profile and human-review/submission process.

The official [OP testing guide](https://openid.net/certification/connect_op_testing/), [OID4VCI guide](https://openid.net/certification/conformance-testing-for-openid-for-verifiable-credential-issuance/) and [OID4VP guide](https://openid.net/certification/conformance-testing-for-openid-for-verifiable-presentations/) define roles and certification requirements. The local plain-VP component exercise does not satisfy the HAIP credential-certification profile.
