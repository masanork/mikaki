# FAPI 2.0 readiness and DPoP receipt evidence

Reviewed 2026-09-30 against [FAPI 2.0 Security Profile Final](https://openid.net/specs/fapi-security-profile-2_0-final.html), [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html), [PAR RFC 9126](https://www.rfc-editor.org/rfc/rfc9126.html) and the local OIDF 5.3.1 suite. The [local Final AS conformance run](fapi2-conformance-2026-09-30.md) completed its selected plan with 45 PASSED, 4 REVIEW, 3 SKIPPED and no failures. Manual reviews and certification remain separate.

## Scope and effort

The first candidate is a separately configured **confidential-client FAPI 2.0 Security Profile Final AS and resource server**, using `private_key_jwt`, ES256, DPoP, PAR and Authorization Code/PKCE S256. This is a medium-sized protocol/storage change; product operation and certification add further work. Existing passkey login, consent, static client keys, assertion replay reservations, PKCE, code binding and issuer responses provide a useful base.

FAPI requires authenticated PAR and sender-constrained tokens. Its basic Security Profile does not require the Message Signing extension's JAR/JARM. OpenID is an option, and an AS is not required to add a refresh grant solely to start this profile; a FAPI client must support refresh behavior when offered. Keep the existing [public-client agent OAuth](agent-oauth.md) usable under its own contract rather than turning Codex/Grok into confidential clients. OID4VCI receipt and FAPI AS certification are distinct targets.

## Implementation fit/gap

| Area                             | Current repository evidence                                                                                                                                                                            | Required next change                                                                                                                                                                                |
| -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Client authentication            | `MIKAKI_DEPLOYMENT_PROFILE=fapi2` uses the strict Rust verifier at PAR and token endpoints: issuer-string `aud`, registered ES256 key and one-use `jti`. Normal/conformance modes retain their existing contracts. | Run the independent Final AS assertion modules and qualify client key onboarding/rotation. |
| Assertion timing                 | FAPI mode accepts optional `nbf`, permits 10 seconds of future `iat`/`nbf`, and rejects long lifetime. Local Worker tests exercise the PAR and token boundaries. | Check suite-specific clock-offset cases against the Final test plan. |
| PAR                              | FAPI mode requires authenticated POST `/par`, durable 300-second references, revision checks, and atomic consumption with code issue. The independent PAR switch remains available in normal mode. | Verify remaining RFC 9126 edge cases and exercise an independent FAPI client. |
| Authorization                    | PAR mode rejects direct requests and wrong-client references; the authenticated pushed request wins over extra front-channel fields. Login accepts a minimal `client_id`/`request_uri` reference, and two Worker instances cannot both complete one URI. | Finish deny/consent and pre-authentication URI reuse browser journeys. |
| Code binding                     | PAR records can bind a DPoP thumbprint from `dpop_jkt` or a valid PAR proof; code redemption checks the same key. PAR mode rejects a runtime code TTL above 60 seconds. | Require a key on all FAPI codes and qualify code/key rotation and absence cases. |
| Token/resource sender constraint | FAPI mode requires a DPoP proof at token issue, issues only DPoP tokens, challenges with D1-backed AS/RS nonces and rejects Bearer at UserInfo. Normal mode keeps optional DPoP. | Qualify every selected resource and external RS. The VCI fixture ledger remains process-local. |
| Metadata/algorithms              | FAPI mode advertises PAR, ES256 private-key client authentication and DPoP. Isolated secret clients remain limited to conformance mode. | Compare all metadata fields with the selected Final AS plan; Basic OP still advertises RS256 signing. |
| Operations                       | [Basic/Config OP](oidf-conformance-2026-09-29.md) and [FAPI Final AS](fapi2-conformance-2026-09-30.md) tests use local HTTPS and virtual passkeys. | Qualify real TLS/edge behavior, confidential client onboarding, key rotation/revocation, bounded storage cleanup, rate limits, outage behavior and independent client/RS plans. |

The selected suite plan is `fapi2-security-profile-final-test-plan`, with `fapi_profile=plain_fapi`, `authorization_request_type=simple`, `client_auth_type=private_key_jwt`, `sender_constrain=dpop`, and `openid=openid_connect`. The suite supplies `grant_management=disabled` by default. Its catalogue contains regional/conditional modules too; counting all catalogue entries is not a selected-profile pass count. The [run record](fapi2-conformance-2026-09-30.md) separates 4 manual REVIEW cases from 3 SKIPPED optional cases: OIDC `claims` selection, the RSA-key RS256 negative test, and refresh-token behavior. They become work only when a concrete client needs those capabilities; they are not prerequisites to resolving the four reviews or qualifying production TLS.

## Delivered shared Rust and D1 authority

The [shared verifier](../crates/oidc/src/dpop.rs), [Worker adapter](../crates/worker/src/dpop.rs), [migration 0020](../crates/worker/migrations/0020_dpop_token_binding.sql) and [Worker regressions](../local/conformance/dpop-worker.test.ts) implement optional DPoP for the confidential-client OP's authorization-code token endpoint and UserInfo. This is executable product code, locally tested, without deployment or a FAPI profile claim. Public agent OAuth and the synthetic VCI issuer use their own contracts.

Rust verifies bounded compact ES256 proofs, embedded public P-256 keys, signature, type, method, HTTPS target, `iat`, and resource `ath`/thumbprint before any replay write. Token issuance stores the RFC 7638 thumbprint with the opaque token hash in the same batch as code consumption; a trigger prevents rebinding. The response is `token_type=DPoP`. Bound tokens cannot use Bearer, including the isolated conformance form-body path; unbound tokens retain their Bearer contract.

D1 acceptance reserves `(jkt, SHA-256(jti))` with an unpredictable receipt. Cleanup, inclusive deadline checks, a conservative global 10,000-row ceiling and conflict handling execute atomically. The DB clock rechecks freshness; resource acceptance also rechecks token expiry/revocation and current account, parent session, client and consent eligibility within that batch. A token proof is accepted after client authentication and remains reserved if a subsequent invalid grant or write failure aborts issuance. Retry uses a fresh proof and client assertion. Issuance rechecks that exact proof receipt and its deadline after signing. DB errors do not fall back to Bearer or a memory cache.

The Rust assertion, nonce and DPoP tests pass, as do 15 Worker regression scenarios, including distinct Worker instances sharing D1 with one concurrent winner, replay after Worker reload, nonce rotation, PAR/code binding, a complete local FAPI profile route, revocation/consent invalidation, DB failure rollback and existing Bearer compatibility. CI includes this suite in `test:worker-contracts`.

Apply migrations [0020](../crates/worker/migrations/0020_dpop_token_binding.sql), [0021](../crates/worker/migrations/0021_dpop_nonce.sql) and [0022](../crates/worker/migrations/0022_par_authorization.sql) before deploying this Worker. Normal mode has PAR and nonce challenges off by default; `fapi2` requires both, DPoP token/RS proof and issuer-audience assertions. These tests use ephemeral local D1 and synthetic keys; no remote migration or deployment occurred. The full Final suite and independent counterparties remain gates. This OP persistence does not make the separate VCI fixture production-ready.

```sh
npm run build:policy
worker-build --release crates/worker
cargo test --locked -p mikaki-oidc
node --test local/conformance/dpop-worker.test.ts
node design/probes/workers-rs/token-exchange.ts
```

## Delivered DPoP slice

The [source](../design/probes/dpop/probe.ts), [scenarios](../design/probes/dpop/cases.ts), [HTTPS harness](../design/probes/dpop/network.ts) and [content-free report](../design/probes/dpop/results-2026-09-29.json) record **45 component/policy scenarios and 11 loopback HTTPS scenarios**, all passing. They use pinned OWF OAuth2/VCI 0.6.0 and the existing independent OID4VP verifier 0.12.0, with JOSE 6.2.12 signature callbacks. These are synthetic components and harness policies, not independent full applications.

The gate supports a selected GET/POST ES256/P-256 subset. It rejects malformed/duplicate/oversized proofs, symmetric/unsigned signatures, private JWK material, unsupported critical headers, wrong method/origin/path, proof type, missing/wrong nonce, `ath`, token and thumbprint. The authentication scheme is case insensitive; the token is case sensitive. Query/fragment are excluded from `htu` as required by DPoP. Time checks accept +10 seconds and reject +11/+61, with a 60-second age plus ten-second skew. This deliberately conservative window is a Final-compatible subset, not a requirement to accept exactly this window for every deployment.

Replay IDs are scoped to key thumbprints, bounded at 1,000 and retained through the full acceptance window. A reservation occurs **after** protocol/binding and signature verification, before returning success. OWF's optional uniqueness callback runs before its signature callback; this harness leaves that callback unset and reserves afterward so a forged signature cannot consume a legitimate ID. Concurrent duplicates have one winner; capacity fails closed and expired entries are reclaimed. A process-local map does not establish cross-isolate or restart safety.

The issuance wrapper requires DPoP for the existing **anonymous** pre-authorized membership fixture. It verifies proof before invoking the original code/token/nonce logic, records token thumbprints, returns `token_type=DPoP`, and rejects Bearer use externally. Its private adapter still invokes the original core's Bearer interface. The wallet adapter enforces advertised ES256 and DPoP token type and handles one initial nonce challenge with a fresh proof. DPoP proves sender-key possession; it is not confidential-client authentication or holder-key attestation.

The sender key and credential holder key are different disposable keys. Approved receipt preserves the original issuer artifact and holder-key envelope under the existing in-memory encryption, then presents only membership status to the independent verifier. Neither issuance nor presentation tokens create MCP/owner-storage authority.

The network fixture retains logical `https://issuer.mikaki.test` in Host, SNI and proof claims while routing TCP to an ephemeral loopback port. A fresh synthetic certificate is explicitly trusted; certificate and hostname checks stay enabled. The negative tests verify that an untrusted certificate, wrong hostname or foreign issuer fails before an HTTP request. Real HTTPS tests also cover cancellation, Bearer downgrade, missing proof, other sender, wrong `ath`, transport-proof/credential-proof confusion and replay. It is a fixture-to-harness network qualification, not a public issuer or wallet application.

```sh
npm ci --prefix design/probes --ignore-scripts
npm run test:dpop --prefix design/probes
npm run test:dpop-network --prefix design/probes
npm run probe:dpop --prefix design/probes
npm run check:node
```

The HTTPS tests need OpenSSL and loopback sockets. They generate ignored, private fixture TLS material and close their own servers. CI runs both suites. Reports suppress keys, credentials, nonce/state, tokens and exception text, and capture installed versions and dependency/source hashes. Historical OIDF records retain the lock hashes used at their original run; adding OAuth2 as an explicit dependency does not rewrite that history.

## Next work in order

1. Select a named full issuer/wallet and compatible Final flow. Qualify actual import/consent/presentation UI and original artifact/holder preservation. The present anonymous DPoP receipt succeeds locally but is not an authenticated FAPI flow or the complete OIDF issuance/wallet plan.
2. The OP replay/token binding, nonce rotation, multi-instance one-winner, grant revocation and fail-closed DB foundation is now implemented above. Qualify edge operations and sender-key rotation policy.
3. The strict verifier, mandatory PAR and DPoP token/UserInfo profile are now locally exercised, including simultaneous PAR completion. Test login/consent reload, key rollover and configuration failure paths; qualify production TLS/edge behavior.
4. Protect every selected resource endpoint. Resolve the [four Final AS manual reviews](fapi2-conformance-2026-09-30.md), then qualify a real independent FAPI client and resource server.
5. Finish intended-device PRF/holder recovery, transfer/deletion, real issuer trust/status and hosted activation for product credentials. Message Signing, HAIP, mdoc, encrypted/deferred issuance and regional profiles follow concrete counterparties/use cases.

FAPI protects the authorization/token/resource path. It does not establish a credential's issuer truth, recover a lost holder key, or replace the Vault's owner approval and encrypted storage boundaries.
