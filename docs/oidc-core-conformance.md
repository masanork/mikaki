# OIDC Core conformance target

2026-09-23 / implementation target; first local OIDF plan run recorded below.

## Milestone

The intended first conformance milestone is the OpenID Foundation **OpenID Connect Core: Basic OP Certification Profile** plus **Config OP** tests, using Authorization Code Flow only. Passing a local plan is a test result for that profile; it is not a claim of full OIDC Core coverage or formal certification.

Included:

- static confidential clients and exact redirect URI registration;
- `response_type=code`, `scope=openid`, query response mode, and PKCE S256 by default; registered conformance secret clients may omit PKCE;
- pairwise subject identifiers;
- ES256 as the product default and RS256 support required by the Core OP profile;
- `private_key_jwt` for normal clients; `client_secret_basic` and `client_secret_post` only for explicitly registered clients in the isolated conformance deployment;
- signed ID Tokens, Discovery, JWKS, token exchange, and GET/POST UserInfo; conformance mode also accepts the bearer token in a form POST body;
- the supported `openid` scope and `sub` claim only.

Excluded from this milestone: Implicit/Hybrid flows, Dynamic Client Registration, Form Post, third-party initiated login, logout certification profiles, and formal OIDF certification submission. Unsupported features must be rejected and omitted from Discovery metadata.

## Compatibility constraints

The normal deployment accepts only `private_key_jwt`. OIDF's published instructions for manually registered clients in the Basic/Implicit/Hybrid OP plans require two `client_secret_basic` clients and one `client_secret_post` client. The instructions also require the exact callback `https://www.certification.openid.net/test/a/<ALIAS>/callback`. An isolated conformance deployment supports those additional methods for registered suite clients. The local Basic OP plan omitted PKCE. The Worker therefore permits a no-PKCE code only when that conformance deployment's secret-client registration explicitly sets `allow_missing_pkce=1`; normal clients and deployments still require PKCE S256.

## Profile boundary

- A deployment selects `normal` by default. The conformance profile requires an explicit deployment boundary; HTTP parameters, headers, D1 runtime-policy updates, and Discovery requests cannot select it. Once deployed, operational values and suite-client registrations are managed in that deployment's D1 without another Worker deployment.
- The conformance Worker uses its own HTTPS issuer, D1 database, signing keys, client credentials, and test accounts. Production data and credentials are never copied into it.
- Each static client registration fixes one token endpoint authentication method. A client registered for `private_key_jwt` cannot fall back to a secret; a secret client cannot authenticate by a different method. Requests supplying more than one method are rejected.
- Only the conformance profile permits `client_secret_basic` and `client_secret_post` registrations. Secrets are generated with high entropy, stored as verifiers rather than plaintext, compared without timing-dependent short-circuiting, rotated or deleted after the run, and never logged. Apply rate limits to the token endpoint.
- A suite secret client may omit PKCE only when its registration sets `allow_missing_pkce=1` in the conformance deployment. A code issued with a challenge always requires its matching verifier, and a token request with a verifier for a code issued without a challenge is rejected to prevent PKCE downgrade.
- Discovery advertises only methods the selected deployment accepts. `normal` publishes `private_key_jwt`; conformance publishes its enabled methods. Changes to PKCE, signing, or other metadata are likewise tied to actual deployed behavior.
- Authorization-code binding to client ID and redirect URI, one-time consumption, signed ID Token validation, SSO and consent checks, and error handling remain the same shared implementation. No test-only bypass of identity or consent is allowed.

OIDC Core §15.1 requires OP support for RS256 ID Token signing. RS256 is a compatibility requirement for conformance, not a change to mikaki's ES256 issuance default. Both algorithms must be advertised only after working issuance and verification paths are tested.

OIDC Core leaves the method of authenticating the end user to the OP. The Basic OP profile does not require a password field. The Worker now uses a WebAuthn passkey ceremony, an explicit first-consent checkbox, and a one-time D1 login transaction to continue authorization. The local fixture provisions a generated passkey and Chromium's virtual authenticator; it does not provision an account password. Account recovery is a separate product flow and is not needed for the Basic OP test plan.

## Readiness map

| Area | Current evidence | Next gate |
| --- | --- | --- |
| Plan compatibility | The isolated Worker accepts fixed `client_secret_basic`/`client_secret_post` registrations and client-specific no-PKCE compatibility. The local OIDF `oidcc-server` module passes with passkey login. | Complete the full Basic OP plan and review warnings and manual-review modules. |
| Interactive authorization | `GET /authorize` starts a passkey ceremony for an interactive request without a suitable SSO session. Passkey assertion verification creates the SSO session and first `app_connection` after explicit consent. `prompt=none` remains non-interactive. | Add product passkey registration and account recovery before inviting public users; test more negative browser cases. |
| Static clients and subjects | Exact redirect registrations, client keys, sectors, and pairwise-subject tables exist in the initial D1 migration. | Provision at least two isolated test clients with distinct keys and the suite callback, then verify cross-client code rejection and stable pairwise `sub`. |
| OP endpoints | Discovery, JWKS, authorization, token, and UserInfo routes exist. A local workerd probe covers one ES256 code exchange and UserInfo, including replay and concurrent exchange. | Check Discovery against actual deployed signing keys and behavior; run RS256 end to end and negative protocol cases. |
| Hosted run | The local Colima OIDF suite ran Config OP and a complete Basic OP plan against an ephemeral HTTPS workerd fixture. `oidcc-server` passed through passkey login. The normal-profile issuer is deployed at `https://mikaki.tossa.app` with a dedicated D1, runtime policy, and ES256 signing key. | Test a separate public conformance deployment; the normal issuer has no public enrollment or registered clients yet. |

The local Svelte/JavaScript OP exercises a broader login flow, but it is a separate test adapter; it does not establish that the Rust Worker can complete the hosted flow.

## Implementation gates

1. Inspect the current OIDF Basic OP and Config OP plan configuration. Record the exact client authentication, PKCE, and callback requirements of the selected plan.
2. Verify the deployment-scoped conformance mode and per-client fixed authentication method against the hosted suite. Local workerd checks cover `client_secret_basic` and `client_secret_post`, mixed-method and normal-profile rejection, secret verifier matching, a per-client rate limit, and shared code exchange.
3. Exercise Worker passkey login and consent continuation so an unauthenticated suite browser can finish authorization without pre-seeding a cookie or grant.
4. Provision isolated static clients, exact callback URIs, client public keys or generated secrets, signing keys, and test accounts through a repeatable setup path. Never commit private keys or live test credentials.
5. Verify Discovery and JWKS against both profiles; test ES256 and RS256 token issuance and validation, authorization errors, `prompt`/`max_age`, issuer/audience/nonce/time claims, UserInfo, and negative cases.
6. Run isolated D1/workerd integration checks for cross-client code binding, mixed authentication, replay, expiration, concurrency, and signing-key rotation.
7. Deploy an isolated HTTPS instance, register the selected plan's clients, run all tests in that plan, and retain the suite version, plan variant, non-secret configuration, logs, results, and known exclusions. Formal certification submission remains a separate decision.

Passing local checks or a single RP flow does not complete the milestone. Hosted OIDF conformance needs a publicly reachable HTTPS issuer and a full plan run. Deployment and external test-plan creation are separate actions from implementation.

## Local OIDF run (2026-09-23)

The OIDF conformance suite version 5.2.4 ran in Colima against an ephemeral conformance-profile Worker fixture served over local HTTPS at `https://host.docker.internal:8792`. The fixture used a fresh local D1 database, generated signing key, three generated secret clients, and a self-signed certificate. Private keys and client secrets are kept only under ignored `local/generated/` and are not part of this record.

| Plan | Suite IDs | Result |
| --- | --- | --- |
| Config OP (`oidcc-config-certification-test-plan`) | plan `VXp5JDZw1RcYD`, module `vg8geZoUX1DiSQZ` | `oidcc-discovery-endpoint-verification` **PASSED**; no failure or warning events. |
| Config OP (`oidcc-config-certification-test-plan`) | plan `blffV5QoDprk5`, module `dQgXsCSbyvWhY79` | Final Worker build: **PASSED**. |
| Basic OP (`oidcc-basic-certification-test-plan`, discovery/static client) | plan `b88xZEFP2mumH`, module `QlAIsNTGcd6A3xH` | 35 modules were listed. Only `oidcc-server` was started; its authorization URL omitted `code_challenge` and `code_challenge_method`. The Worker redirected with `error=invalid_request`. The module was **INTERRUPTED** while waiting for browser completion; this is not a full plan result. |
| Basic OP (`oidcc-basic-certification-test-plan`, discovery/static client) | plan `dKF4WYjgOJXxi` | Final Worker build, all 35 modules finished: 21 **PASSED**, 8 **SKIPPED**, 4 **REVIEW**, 2 **WARNING**, 0 failed. |

The first Basic OP run exposed the missing PKCE compatibility rule. After that rule was added, plan `eq0ZepRTJctg2` reached `login_required`, exposing the missing interactive Worker flow. These runs were diagnostic and are not certification results.

The passkey-based full Basic OP run used discovery and static clients in plan `dKF4WYjgOJXxi`. Of its 35 modules, 21 were **PASSED**, 8 were **SKIPPED** because their optional features are not advertised, 4 finished **REVIEW** after required screenshots were uploaded, and 2 finished **WARNING**. There were no failed or interrupted modules. The warnings were for an unreturned voluntary `acr` value and the unavailable `name` claim; at the time mikaki advertised only `openid` as a scope and no profile claims. The `REVIEW` modules require human evaluation and must not be described as passed. The two redirect-URI review modules show a static error page without sending the browser to an unregistered callback. The earlier UserInfo POST-body warning was resolved by allowing that bearer-token transport only in the isolated conformance profile. Full suite logs, module IDs, and results are retained in ignored `local/generated/oidf-passkey-*.json`.

Subsequent focused rerun: the Worker now issues `acr=urn:mikaki:acr:passkey-uv` for its UV-required passkey ceremony and advertises that value in Discovery. `oidcc-ensure-request-with-acr-values-succeeds` finished **PASSED** in local plan `2UhRPZQIUM0s1`, module `9QI9AIvmYWDb1j6`. The full 35-module plan has not yet been rerun with this change; its recorded totals above remain the historical result. The `name` warning and eight optional-feature skips remain open.

The remaining `name` warning does not justify making a name mandatory during initial passkey registration. The normal profile currently discloses only a pairwise `sub`, and applications own their display names. [OIDC Core §5.5.1](https://openid.net/specs/openid-connect-core-1_0.html#IndividualClaimsRequests) allows an Essential Claim to be absent when it is unavailable or the end user does not authorize release. An optional name is being considered as a [Vault attribute shared with a dedicated UserInfo system principal](vault-claim-sharing.md); that requires Storage, key distribution, and RP-specific disclosure consent before the OP can return it. Do not add a conformance-only account-profile column, derive a name from an account ID, or return a placeholder merely to silence the warning. The warning remains documented until this product capability exists.

## Current status

Rust currently exposes Discovery, `GET /authorize`, passkey `GET /login` and `POST /login/finish`, `POST /token`, `GET /jwks`, and GET/POST `/userinfo`. The passkey ceremony verifies a one-time challenge and the browser origin, updates the credential counter, then creates SSO and the first app connection after explicit consent. The local fixture uses a generated test passkey; it contains no password login. Static redirect/sector/pairwise-subject and fixed client-auth registration tables exist in the initial migration, now applied to the normal-profile D1. ES256 and RS256 signing paths compile for Worker WASM. Local workerd probes verified RSA import/signing, private_key_jwt and isolated `client_secret_basic`/`client_secret_post` exchanges with and without PKCE, ES256 ID Token validation, UserInfo, replay revocation, cross-client code binding, and a concurrent code exchange with exactly one winner. Config OP passed locally; the Basic OP full plan has no failed modules but still includes manual reviews, warnings, and optional skips. The normal-profile public issuer responds to Discovery and JWKS. Production passkey registration and recovery, an isolated hosted conformance deployment, and formal certification remain.

## References

- [OIDF instructions for OpenID Provider conformance testing](https://openid.net/certification/connect_op_testing/)
- [OpenID Connect Core 1.0, §3.1.2.1 (end-user authentication method)](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest)
- [OIDF OpenID Connect Conformance Profiles](https://openid.net/wordpress-content/uploads/2015/03/OpenID-Connect-Conformance-Profiles.pdf)
- [OpenID Connect Core 1.0, §15.1](https://openid.net/specs/openid-connect-core-1_0.html#ServerMTI)
- [OAuth 2.0, §2.3.1 client password authentication](https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1)
- [OAuth 2.0 Security Best Current Practice, §2.5](https://www.rfc-editor.org/rfc/rfc9700#section-2.5)
- [OAuth 2.0 Security Best Current Practice, §4.8.2](https://www.rfc-editor.org/rfc/rfc9700#section-4.8.2)
