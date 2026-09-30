# Synthetic OID4VP presentation probe

**Locally verified:** 2026-09-29. This is the bounded component slice of [VG-07](vault-fit-gap.md#vg-07--minimal-credential-presentation-feasibility-probe), under [ADR 0012](adr/0012-vault-protocol-boundaries.md). It has no product endpoint, browser wallet, production credential, or deployment. [Source](../design/probes/oid4vp/probe.ts), [negative cases](../design/probes/oid4vp/cases.ts), and [content-free report](../design/probes/oid4vp/results-2026-09-29.json) are repeatable.

## Selected profile

| Choice | Tested contract |
| --- | --- |
| Protocol | [OpenID4VP 1.0 Final, 2025-07-09](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html), one DCQL credential query and one presentation |
| Credential | [SD-JWT RFC 9901](https://www.rfc-editor.org/rfc/rfc9901.html), flat claims from the [SD-JWT VC draft-19](https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-19.html) subset; `dc+sd-jwt`, ES256, SHA-256, `cnf.jwk`, required KB-JWT |
| Synthetic issuer/type | `https://issuer.mikaki.test` / `https://issuer.mikaki.test/membership/v1`; exact issuer identity and one public key pinned out of band |
| Request | Preregistered `mikaki-probe-verifier`, exact HTTPS response URI known out of band, `response_type=vp_token`, `response_mode=direct_post`; no colon/prefix in the client ID (Final section 5.9.2 fallback) |
| Disclosure | Only issuer-attested `membership_active=true`; the original credential also contains hidden synthetic name and member number |
| Independent verifier | [`@openeudi/openid4vp` 0.12.0](https://github.com/openeudi/openid4vp), locked in the isolated probe dependencies; trust checks enabled via `trustedIssuerJwks`, holder binding required |
| Issuer/wallet | Mikaki fixture harness using `jose` 6.2.12; separate SD-JWT construction from the verifier implementation, but shared JOSE primitives. This is not an independent full wallet application. |
| Status | Trusted in-memory service keyed by issuer-JWT SHA-256; require `good` on every presentation. Revoked, unknown, and outage reject. No Token Status List, CRL, OCSP, or external status interoperability claim. |
| Transport | Real Web `Request` and URL-encoded `direct_post` body serialization in process; reserved `.test` origins. No sockets, TLS handshake, cross-device QR, or Digital Credentials API exercise. |

The verifier request is a fixture object validated against one exact supported profile, not a general authorization-request parser. There is no HAIP, mdoc, X.509 trust chain, issuer discovery, `direct_post.jwt`, or standards certification claim. The independent library's out-of-band JWK path is expressly a harness trust option; a production trust profile needs separate selection.

## Artifact, holder key, and consent boundaries

The fixture issuer signs the original credential. Import checks the signature, issuer, expiry, credential type, disclosure anchoring, and holder public-key binding. The wallet preserves the exact issuer JWT, all disclosures, and their ordering inside an AES-GCM envelope. An editable annotation remains separate. Updating it cannot rewrite the issuer's proof or change an attested claim.

The holder uses a dedicated disposable ES256 key, distinct from WebAuthn login credentials and Vault/recipient keys. Its private JWK has a separate AES-GCM envelope and purpose-bound additional authenticated data. A random, nonextractable in-memory wrapping key unlocks these fixtures; this is not a Passkey PRF or recovery implementation. The issuer, holder, artifacts, and wrapping key are generated for each scenario and never written to the report. Process teardown discards them; JavaScript garbage collection is not guaranteed secure zeroization.

An explicit fixture approval call permits the one requested disclosure and key-binding proof. Unsupported verifier, response URI, mode, or broader DCQL fails before unlocking. Cancellation needs no unlock and returns `access_denied` with state and no `vp_token`. There is no actual owner consent UI or unattended agent presentation path. A future UI must bind approval to the exact authenticated request and selected credential.

## Verification and negative evidence

Twenty-eight scenarios pass on the environment recorded in the report. Independent-library cases check acceptance of the minimal presentation, nonce and audience, holder-key signature, missing binding, `sd_hash`, altered/unanchored disclosures, expiry, type, DCQL claim value, and an untrusted signing key. Policy and wallet cases separately check issuer URI, encrypted import/annotation preservation, cancellation, unsupported or excessive requests, envelope query ID and duplicate fields, response destination/method, session state/expiry, replay and concurrent one-winner consumption, status and outage, excessive disclosure, and KB-JWT type/freshness.

The independent library is stateless. The harness therefore owns request state, deadlines, and synchronous one-time consumption before asynchronous verification; a failed proof or cancelled request also requires a fresh session. Additional policy checks pin `iss`, require issuer time claims and current `kb+jwt` time/type, and reject extra disclosure. Passing a library parser alone is insufficient authorization. Credential status and expiry remain separate from a source-version freshness observation or an MCP grant deadline.

Exceptions and library diagnostics can contain private claim values. The generated report records only scenario identifiers, layers, pass/fail, versions, the fixture profile, and environment. It does not persist presentation strings, disclosures, holder keys, nonce/state, or exception text. The tests do not establish a security audit or broad standards conformance.

```sh
npm ci --prefix design/probes --ignore-scripts
npm run test:oid4vp --prefix design/probes
npm run probe:oid4vp --prefix design/probes
npm run check:node
```

CI runs the scenarios after installing the isolated probe dependencies. Reporting regenerates the dated JSON locally. The tested library has a deprecated transitive `@sd-jwt/decode` 0.19.0 dependency, whose package warning includes a security advisory reference; migration/review is a production adoption gate. The 2026-09-29 npm audit returned three moderate entries in the existing Wrangler → Miniflare → Undici 7.29.0 chain, already present in the baseline lockfile; no clean dependency-audit claim is made. The probe did not change or downgrade those tools.

## Decision and next gates

The subsequent [OIDF Suite 5.3.1 HTTPS adapter](oidf-conformance-2026-09-29.md) connects an external emulated wallet to the same independent verifier library in a separate synthetic PID/`redirect_uri` profile. Seven negative modules pass and two positive modules accept and await screenshot review. It does not change or qualify this preregistered membership wallet, status policy, actual wallet applications or HAIP.

This evidence supports keeping OID4VP as a credential-presentation candidate, with credentials preserved separately from editable Vault attributes and MCP copies. It does not yet select a production wallet library or complete VG-07's device and recovery qualification.

The subsequent [OID4VCI receipt probe](oid4vci-probe.md) now selects the Final Pre-Authorized Code flow with a separate transaction code, nonce endpoint and dedicated holder proof. Its receipt → exact encrypted import → presentation path passes against an independent issuer protocol library and this independent verifier library. The shared importer additionally rejects future issuer `iat`, duplicate disclosures and unsupported membership-fixture shapes. Issuance authority remains separate from owner storage updates; there is no product issuer or general credential importer.

Before product adoption, also qualify an independent full wallet/verifier over the chosen network/request-authentication profile, the intended browser/devices, a real issuer trust/status scheme, holder-key transfer/recovery/deletion, and exact owner approval. Neither `vp_token` nor issuance tokens become MCP or owner-storage access tokens.
