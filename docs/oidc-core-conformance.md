# OIDC Core conformance target

2026-09-23 / implementation target; no OIDF test plan has been run.

## Milestone

The first conformance milestone is the OpenID Foundation **OpenID Connect Core: Basic OP Certification Profile** plus **Config OP** tests, using Authorization Code Flow only. Passing these plans is a test result for the selected profile; it is not a claim of full OIDC Core coverage or formal certification.

Included:

- static confidential clients and exact redirect URI registration;
- `response_type=code`, `scope=openid`, query response mode, and PKCE S256;
- pairwise subject identifiers;
- ES256 as the product default and RS256 support required by the Core OP profile;
- `private_key_jwt` client authentication, with no client secret stored by sakimori;
- signed ID Tokens, Discovery, JWKS, token exchange, and GET/POST UserInfo;
- the supported `openid` scope and `sub` claim only.

Excluded from this milestone: Implicit/Hybrid flows, Dynamic Client Registration, Form Post, third-party initiated login, logout certification profiles, and formal OIDF certification submission. Unsupported features must be rejected and omitted from Discovery metadata.

## Compatibility constraints

The product profile uses `private_key_jwt`. OIDF's published instructions for manually registered clients in the Basic/Implicit/Hybrid OP plans describe `client_secret_basic` and `client_secret_post` clients. Before claiming compatibility, select an OP test plan/configuration that can exercise `private_key_jwt` while preserving this product policy. Do not add weaker client authentication just to make a test plan configurable. If the available Basic OP certification plan cannot represent this policy, record that incompatibility and test the closest non-certification Core authorization-server plan instead.

OIDC Core §15.1 requires OP support for RS256 ID Token signing. RS256 is a compatibility requirement for conformance, not a change to sakimori's ES256 issuance default. Both algorithms must be advertised only after working issuance and verification paths are tested.

## Implementation gates

1. Add static client redirect URI registration and stable per-client pairwise subjects to the Rust Worker D1 schema.
2. Connect the SSO cookie, authorization request validation, prompt/max_age handling, consent decision, and one-time code creation to Rust typed state and one conditional D1 operation.
3. Implement Discovery with metadata matching only working endpoints, algorithms, scopes, claims, and response modes.
4. Complete the OIDC Core token and UserInfo requirements, including RS256, authorization errors, issuer/audience/nonce/time claims, and negative cases.
5. Add local integration coverage for concurrency, redirect validation, token/code replay, expiration boundaries, and key rotation; run against isolated D1/workerd.
6. Deploy an isolated HTTPS conformance instance, register test clients with the suite callback URI, then run the selected OIDF plans and retain plan version, configuration, logs, and results.

Passing local checks or a single RP flow does not complete the milestone. Hosted OIDF conformance needs a publicly reachable HTTPS issuer and an actual plan run. Deployment and external test-plan creation are separate actions from implementation.

## Current status

Rust currently exposes `POST /token`, `GET /jwks`, and GET/POST `/userinfo`. The initial Worker migration now defines exact static client redirect URIs, a client sector identifier, and stable pairwise-subject storage; no `/authorize` or Discovery endpoint consumes these tables yet. There is no authentication-to-code issuance path and only ES256 signing. The production D1 migration is not deployed. Therefore the selected conformance milestone is not yet runnable.

## References

- [OIDF instructions for OpenID Provider conformance testing](https://openid.net/certification/connect_op_testing/)
- [OIDF OpenID Connect Conformance Profiles](https://openid.net/wordpress-content/uploads/2015/03/OpenID-Connect-Conformance-Profiles.pdf)
- [OpenID Connect Core 1.0, §15.1](https://openid.net/specs/openid-connect-core-1_0.html#ServerMTI)
