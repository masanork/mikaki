# FAPI 2.0 Final AS local conformance run (2026-09-30)

OIDF Conformance Suite 5.3.1 (revision `4bfcdf8`) was run locally against the Rust Worker through an isolated HTTPS relay and Chromium virtual passkey. The plan was `fapi2-security-profile-final-test-plan` with `plain_fapi`, `private_key_jwt`, DPoP, simple authorization requests and OpenID Connect. The relay uses a disposable self-signed certificate and limits TLS 1.2 suites to AEAD ciphers. This is local interoperability evidence, not OIDF certification or production-edge TLS evidence. Private keys, passkeys, bearer tokens and full suite logs remain ignored under `local/generated/`.

The first broad traversal (plan `fV8Ye6x0voX6D`) recorded **52 modules: 36 PASSED, 8 FAILED, 3 REVIEW, 3 SKIPPED, 2 unfinished**. After the fixes below, the second complete traversal (plan `iPX7CdkrKVHQP`) recorded **52 modules: 45 PASSED, 4 REVIEW, 3 SKIPPED, 0 FAILED or unfinished**. The three conditional PAR audience modules in the source catalogue were absent from this selected plan (`404` when requested individually). REVIEW and SKIPPED are not counted as passes. The detailed summaries are `local/generated/oidf-passkey-summary-{fV8Ye6x0voX6D,iPX7CdkrKVHQP}.json`.

The run exposed four Worker interoperability defects, each fixed and rerun against the official module:

| Module | Root cause and correction | Rerun |
| --- | --- | --- |
| Authorization without `state` and state only outside PAR | The OP required `state` even in FAPI's code flow. FAPI mode now permits its absence, does not emit an empty callback parameter, and ignores front-channel `state` in favor of PAR. Normal mode retains its existing requirement. | `cR58RNmb8a7jxeZ`, `GdO7tppaG71gVRS`: PASSED |
| Missing PKCE verifier | The missing form field became `invalid_request`; the suite expects `invalid_grant` when redeeming the code without its verifier. | `rAdFjTa59Ba0vvF`: PASSED |
| DPoP negative tests | Resource proof comparison rejected an `htu` carrying query/fragment. RFC 9449 §4.3(9) requires these parts to be ignored when matching. | `ypMFEofQEvb031Y`: PASSED |
| PAR without duplicate front-channel parameters | The passkey login page inferred the callback URL from the front-channel query and returned 500 when the query had only `client_id` and `request_uri`. The login transaction now receives the redirect URL from the authenticated PAR request. | `aylUk5QyZP7qs65`: PASSED |

The Final happy flow, including both registered clients, PAR, passkey login, code exchange, DPoP nonce retry and UserInfo, passed after these changes (`WrdniXqprDFh9PD`). After final login callback-display hardening, both the minimal front-channel PAR module and happy flow passed together again (`Jv5Y3TBVq6fkwn0`, `OBvV7p5l7vMDYTp`). The broad traversal's happy-flow failure was a one-off UserInfo connection timeout; this module passed both before and after the broad traversal. Discovery also passed (`L0zQ1oJqUX1hxtS`). Selected PKCE, DPoP key-binding, assertion-audience and PAR-method negative tests passed independently and within the broad traversal.

The four remaining execution gaps were resolved for the second traversal. `/login/deny` consumes the login transaction once and returns `access_denied` with the authoritative PAR state (`VGksHxz0IHfOJbQ`: PASSED). FAPI mode advertises and accepts `openid profile` in either order, while normal mode retains its prior scope contract (`b6XJCEbRxED8pDF`: PASSED). The driver leaves the first PAR visit unauthenticated and records the second visit before following its callback (`Cl8j5v8k5P1EbtG`: PASSED). It also waits beyond the 300-second PAR lifetime; the expired reference was rejected and the module ended REVIEW (`hBrUI9NNqEDhWRC`).

The four REVIEW modules cover direct authorization without PAR and reused, expired, or wrong-client `request_uri` values. They need human assessment of the uploaded browser evidence. After the full traversal, the Worker was changed to show a localized 400 error page explaining a missing or invalid PAR reference. All four REVIEW modules were rerun with that page; the expired-reference case waited the full 300 seconds (`eds77oSskdBpQZz`). The driver was also corrected to capture the **second** visit's error page in the reuse case (`5HOhRPXOhxbGlGE`), and happy flow passed again (`t01qz96fbiC3d1h`). This improves review evidence; it does not turn REVIEW into an automated pass. Three conditional modules were SKIPPED. Production-edge TLS and an independent client/resource server still need separate qualification. The `profile` scope is now recognized for the ordering test, but the current account model has no additional profile attributes to return beyond `sub`.

The SKIPPED modules reflect three capabilities absent from this selected AS profile, not hidden test failures. They are not passes either:

| Module (run ID) | Suite reason | Implemented boundary and follow-up |
| --- | --- | --- |
| `test-claims-parameter-identity-claims` (`sdmBkRz0TT0KIPs`) | Discovery advertises `claims_parameter_supported: false`; the optional identity-claims request test cannot run. | PAR rejects the `claims` field. Add claim selection only with a defined attribute consent and disclosure contract; OIDC claims must not silently expose Vault data. |
| `ensure-signed-client-assertion-with-RS256-fails` (`AacMaZBB4yINqLP`) | The registered test key is ES256, while this negative module needs a PS256/RSA client key to change its signature to RS256. The suite explicitly allows skipping it for an ES256-only AS. | Discovery advertises ES256; the shared assertion verifier rejects an RS256 header. Supporting PS256 clients would require separate key registration, verification and suite coverage, not a metadata-only switch. |
| `refresh-token` (`A0xTPHdIUSeqILu`) | No refresh token is issued and discovery lists only `authorization_code`. | The token input rejects `refresh_token` grant as `unsupported_grant_type`. A long-lived confidential-client session would need a separate DPoP/client-bound refresh-token lifecycle and revocation design before enabling this module. |

The selected FAPI 2.0 Final AS requirements do not mandate these optional AS capabilities. The distinction matters for agent clients: the public Codex/Grok OAuth contract and FAPI confidential-client contract have different lifecycles, and neither SKIP proves cross-profile refresh or attribute disclosure behavior. Re-evaluate the skipped modules if a specific relying party needs OIDC claim selection, PS256 key registration, or offline access.

Reproduction, after starting the local OIDF suite:

```sh
npm run build:policy
worker-build --release crates/worker
MIKAKI_OIDF_PROFILE=fapi2 node local/conformance/oidf-local-worker.ts
# In a separate shell; start signCount at 1 for each fresh fixture.
node local/conformance/run-passkey-oidf.ts fapi2-security-profile-final-happy-flow 1 fapi2-security-profile-final-test-plan
node local/conformance/run-passkey-oidf.ts all 3 fapi2-security-profile-final-test-plan
```

The sign counter is specific to the current fixture and virtual authenticator; use the counter printed by the prior driver run when chaining commands. Core and Worker regressions: `cargo test --locked -p mikaki-oidc` and `node --test local/conformance/dpop-worker.test.ts`.
