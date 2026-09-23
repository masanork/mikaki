# OIDC Core conformance target

2026-09-23 / implementation target; no OIDF test plan has been run.

## Milestone

The intended first conformance milestone is the OpenID Foundation **OpenID Connect Core: Basic OP Certification Profile** plus **Config OP** tests, using Authorization Code Flow only. The Basic OP plan is conditional on resolving the client-authentication and request-profile mismatches below. Passing a plan is a test result for that profile; it is not a claim of full OIDC Core coverage or formal certification.

Included:

- static confidential clients and exact redirect URI registration;
- `response_type=code`, `scope=openid`, query response mode, and PKCE S256;
- pairwise subject identifiers;
- ES256 as the product default and RS256 support required by the Core OP profile;
- `private_key_jwt` for normal clients; `client_secret_basic` and `client_secret_post` only for explicitly registered clients in the isolated conformance deployment;
- signed ID Tokens, Discovery, JWKS, token exchange, and GET/POST UserInfo;
- the supported `openid` scope and `sub` claim only.

Excluded from this milestone: Implicit/Hybrid flows, Dynamic Client Registration, Form Post, third-party initiated login, logout certification profiles, and formal OIDF certification submission. Unsupported features must be rejected and omitted from Discovery metadata.

## Compatibility constraints

The normal deployment accepts only `private_key_jwt`. OIDF's published instructions for manually registered clients in the Basic/Implicit/Hybrid OP plans require two `client_secret_basic` clients and one `client_secret_post` client. The instructions also require the exact callback `https://www.certification.openid.net/test/a/<ALIAS>/callback`. An isolated conformance deployment will support those two additional authentication methods for registered suite clients. PKCE S256 is currently mandatory in the Worker; inspect the actual plan requests before deciding whether the conformance deployment needs a client-specific compatibility rule for requests without PKCE. Any such rule must be confined to that deployment and recorded in the result. It must not change normal clients or the normal deployment.

## Profile boundary

- A deployment selects `normal` by default. The conformance profile requires an explicit deployment boundary; HTTP parameters, headers, D1 runtime-policy updates, and Discovery requests cannot select it. Once deployed, operational values and suite-client registrations are managed in that deployment's D1 without another Worker deployment.
- The conformance Worker uses its own HTTPS issuer, D1 database, signing keys, client credentials, and test accounts. Production data and credentials are never copied into it.
- Each static client registration fixes one token endpoint authentication method. A client registered for `private_key_jwt` cannot fall back to a secret; a secret client cannot authenticate by a different method. Requests supplying more than one method are rejected.
- Only the conformance profile permits `client_secret_basic` and `client_secret_post` registrations. Secrets are generated with high entropy, stored as verifiers rather than plaintext, compared without timing-dependent short-circuiting, rotated or deleted after the run, and never logged. Apply rate limits to the token endpoint.
- If a suite client must be allowed to omit PKCE, that registration alone may do so. A code issued with a challenge always requires its matching verifier, and a token request with a verifier for a code issued without a challenge is rejected to prevent PKCE downgrade.
- Discovery advertises only methods the selected deployment accepts. `normal` publishes `private_key_jwt`; conformance publishes its enabled methods. Changes to PKCE, signing, or other metadata are likewise tied to actual deployed behavior.
- Authorization-code binding to client ID and redirect URI, one-time consumption, signed ID Token validation, SSO and consent checks, and error handling remain the same shared implementation. No test-only bypass of identity or consent is allowed.

OIDC Core §15.1 requires OP support for RS256 ID Token signing. RS256 is a compatibility requirement for conformance, not a change to mikaki's ES256 issuance default. Both algorithms must be advertised only after working issuance and verification paths are tested.

## Readiness map

| Area | Current evidence | Next gate |
| --- | --- | --- |
| Plan compatibility | Published Basic OP manual-client instructions require secret-based clients. Support for them in an isolated conformance profile is now accepted but not implemented. The Worker requires PKCE S256, and whether the plan sends it has not been verified. | Inspect the live plan/configuration; implement secret authentication behind the profile and decide any PKCE compatibility rule from observed requests. |
| Interactive authorization | `GET /authorize` can issue a code only for an existing valid SSO cookie and active `app_connection`. It returns `login_required` or `consent_required` for interaction it cannot yet perform. | Complete Passkey login, first consent, and connection creation in the Worker path; exercise normal and negative authorization requests through a browser. |
| Static clients and subjects | Exact redirect registrations, client keys, sectors, and pairwise-subject tables exist in the initial D1 migration. | Provision at least two isolated test clients with distinct keys and the suite callback, then verify cross-client code rejection and stable pairwise `sub`. |
| OP endpoints | Discovery, JWKS, authorization, token, and UserInfo routes exist. A local workerd probe covers one ES256 code exchange and UserInfo, including replay and concurrent exchange. | Check Discovery against actual deployed signing keys and behavior; run RS256 end to end and negative protocol cases. |
| Hosted run | No public HTTPS issuer, deployed D1 migration, OIDF plan run, or retained OIDF result is recorded. | Deploy an isolated test instance and run the selected plan after the preceding gates. |

The local Svelte/JavaScript OP exercises a broader login flow, but it is a separate test adapter; it does not establish that the Rust Worker can complete the hosted flow.

## Implementation gates

1. Inspect the current OIDF Basic OP and Config OP plan configuration. Record the exact client authentication, PKCE, and callback requirements of the selected plan.
2. Add deployment-scoped conformance mode and per-client fixed authentication method. Implement `client_secret_basic` and `client_secret_post` with strict parsing, secret verification, mixed-method rejection, rate limits, and normal-profile rejection. Keep code exchange behind one authenticated-client type.
3. Complete the Worker login and consent continuation so an unauthenticated suite browser can finish authorization without pre-seeding a cookie or grant.
4. Provision isolated static clients, exact callback URIs, client public keys or generated secrets, signing keys, and test accounts through a repeatable setup path. Never commit private keys or live test credentials.
5. Verify Discovery and JWKS against both profiles; test ES256 and RS256 token issuance and validation, authorization errors, `prompt`/`max_age`, issuer/audience/nonce/time claims, UserInfo, and negative cases.
6. Run isolated D1/workerd integration checks for cross-client code binding, mixed authentication, replay, expiration, concurrency, and signing-key rotation.
7. Deploy an isolated HTTPS instance, register the selected plan's clients, run all tests in that plan, and retain the suite version, plan variant, non-secret configuration, logs, results, and known exclusions. Formal certification submission remains a separate decision.

Passing local checks or a single RP flow does not complete the milestone. Hosted OIDF conformance needs a publicly reachable HTTPS issuer and an actual plan run. Deployment and external test-plan creation are separate actions from implementation.

## Current status

Rust currently exposes Discovery, `GET /authorize`, `POST /token`, `GET /jwks`, and GET/POST `/userinfo`. `/authorize` only issues a code when a valid SSO cookie and pre-approved active app connection already exist; Passkey login UI, first-consent processing, and app-connection creation are still absent. Static redirect/sector/pairwise-subject tables exist in the initial migration, which is not deployed. ES256 and RS256 signing paths compile for Worker WASM. Local workerd probes verified RSA import/signing and a full isolated D1 authorization, private_key_jwt code exchange, ES256 ID Token validation, UserInfo, replay revocation, and a concurrent code exchange with exactly one winner. The production D1 migration is not deployed. Therefore the selected conformance milestone is not yet runnable.

## References

- [OIDF instructions for OpenID Provider conformance testing](https://openid.net/certification/connect_op_testing/)
- [OIDF OpenID Connect Conformance Profiles](https://openid.net/wordpress-content/uploads/2015/03/OpenID-Connect-Conformance-Profiles.pdf)
- [OpenID Connect Core 1.0, §15.1](https://openid.net/specs/openid-connect-core-1_0.html#ServerMTI)
- [OAuth 2.0, §2.3.1 client password authentication](https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1)
- [OAuth 2.0 Security Best Current Practice, §2.5](https://www.rfc-editor.org/rfc/rfc9700#section-2.5)
- [OAuth 2.0 Security Best Current Practice, §4.8.2](https://www.rfc-editor.org/rfc/rfc9700#section-4.8.2)
