# OIDC implementation readiness

This is the current integration baseline and release checklist. See [project status](status.md), [local implementation](../local/README.md), and [Core conformance](oidc-core-conformance.md) for evidence and remaining work.

## Fixed profile

| Area | Baseline |
| --- | --- |
| Identity | Shared account, app owned SubjectId; no email based merging. UUIDv4 identifiers stored as TEXT in initial D1; persistent pairwise UUIDv4 `sub` per account/sector. |
| Login | Static server side clients, Authorization Code + PKCE S256; `state` required, `nonce` optional. |
| Client authentication | ES256 `private_key_jwt` normally; registered test clients in isolated conformance deployment may use `client_secret_basic/post`. |
| Signing | ES256 normal issuance, explicit RS256 compatibility profile; EdDSA/PQC not initial defaults. |
| Access Token / UserInfo | 32 random byte opaque token, five minute default, no refresh; UserInfo returns `sub` only. |
| Sessions | SSO at most 30 days; app idle limit seven days within parent lifetime; validity lease at most five minutes. |
| Logout | RP Initiated and Back Channel target; revocation and durable outbox commit together. |
| Storage | One D1 database commits Mikaki auth/OIDC state; no distributed transaction with RP databases. |
| Policy | Typed [runtime policy](../config/runtime-policy.example.toml), active revision in D1; separate secrets and deployment settings. |

## Implementation boundary and evidence

`mikaki-webauthn` verifies protocol and cryptography; `mikaki-auth` owns ceremonies/accounts; `mikaki-oidc` owns authorization, client authentication, sessions, JOSE purposes and outbox; the Worker handles HTTP, D1, secrets, clock, randomness, and outbound requests. Dependency direction is Worker → OIDC → Auth → WebAuthn. Do not deserialize a bare HTTP AccountId as authentication proof.

The OIDC crate has validated authorization and token request types, strict form decoding, opaque code/digest handling, ES256 client assertion validation, and ID Token signing. The Worker connects `/authorize`, `/token`, `/jwks`, `/userinfo`, and `/session/check`. It bounds streamed request bodies, rejects duplicate/unknown token form fields, and rechecks current state in the final D1 batch. It supports ES256 and an RS256 compatibility path. Isolated workerd/D1 tests covered code/PKCE exchange, replay revocation, UserInfo, parallel exchange, passkey authentication and first consent. Production migration and invitation registration have been deployed. Local conformance and logout outbox work is recorded under [local](../local/README.md). Account recovery, complete RP callback/logout integration, operational drills, and public readiness remain open.

Discovery must advertise only deployed endpoints, claims, algorithms, and authentication methods. In the normal deployment, `token_endpoint_auth_methods_supported` is `private_key_jwt`; isolated conformance can add secret methods. Backchannel flags become true only after implementation. `request`/`request_uri`, dynamic registration, arbitrary claim requests, and encrypted UserInfo are outside the initial profile. Enforce `prompt` and `max_age` semantics and use defined errors. Distinguish invalid input, unauthenticated, forbidden, expired, replayed, conflict, limited, unavailable, and unknown outcome internally.

Cryptographic dependencies require native and Wasm tests, known vectors, algorithm restrictions, duplicate JSON handling, key rotation, bundle size/latency measurement, and audit. The 2026-09-23 JOSE probes measured ES256/RS256 verification in both targets and checked mutation, issuer, audience, expiry, and key substitution. Those measurements parse a JWK each call and are not cached key production latency. See [probe notes](../design/probes/README.md). Keep RSA private key handling behind a reviewed runtime/KMS boundary; the RustSec RSA timing advisory remains relevant to dependency selection.

## Release gates

1. Typed policy, separated secrets/deployment values, and reproducible native/Wasm cryptography evidence.
2. Production migrations and atomic auth/OIDC operations, including every failure point and primary D1 reads.
3. Code Flow, client authentication, Discovery/JWKS, UserInfo, token purpose and key rotation tests against standard RPs.
4. Browser callbacks and cookies in tossa and tsudoi, including first login, returning login, multiple tabs, cancellation, and lost responses.
5. Management, RP and Back Channel Logout, durable outbox, GC, monitoring, key compromise and DB restore drills.
6. Target OP conformance, load evidence, limitations, and operating procedures.

The first conformance target is Basic OP + Config OP in an isolated deployment, with its own issuer, D1, keys, and test accounts. Keep normal private_key_jwt configuration separate from Basic OP test client secrets. The Basic OP plan may omit PKCE; allow that only for its explicitly registered test client. RS256 alone is not a conformance result. Remaining external inputs include the production issuer/RP ID/origin, both apps' registered URLs, deployment account, and tested browser/authenticator set. Do not invent these values.
