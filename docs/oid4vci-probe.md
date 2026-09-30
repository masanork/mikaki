# Synthetic OID4VCI receipt and presentation probe

**Locally verified:** 2026-09-29. This extends the [OID4VP membership component probe](oid4vp-probe.md) and [VG-07](vault-fit-gap.md#vg-07--minimal-credential-presentation-feasibility-probe). It implements one receipt profile in an isolated fixture harness; it is not a product wallet or deployed credential issuer. [Source](../design/probes/oid4vci/probe.ts), [scenarios](../design/probes/oid4vci/cases.ts), and [content-free report](../design/probes/oid4vci/results-2026-09-29.json) record the boundaries.

## Selected profile

The wire subset follows [OpenID4VCI 1.0 Final, 2025-09-16](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html). Its separate Nonce Endpoint, `proofs` object and array of credential response objects are explicit; draft-era singular `proof`/`credential` messages are rejected rather than silently upgraded.

| Choice | Contract exercised |
| --- | --- |
| Credential | The same `dc+sd-jwt` synthetic membership type as the presentation probe; SD-JWT RFC 9901 / SD-JWT VC draft-19 flat-claim subset, ES256, SHA-256, dedicated `cnf.jwk` holder binding |
| Issuer | Exact `https://issuer.mikaki.test`, an out-of-band pinned disposable issuer public JWK, one `membership_v1` configuration and `membership` scope |
| Flow | Pre-Authorized Code with a separately supplied six-digit numeric `tx_code`; anonymous token exchange, immediate one-credential response |
| Independent issuer component | [OWF `@openid4vc/openid4vci` 0.6.0](https://github.com/openwallet-foundation-labs/identity-common-ts/tree/main/packages/openid4vci), pinned in the isolated dependencies. It builds/validates metadata and offers, parses credential requests, verifies JWT-proof protocol claims and constructs nonce/credential responses. |
| Harness-owned authority | Code/transaction-code checks, code/token/nonce ledgers, exact configuration authorization, one-time issuance, JOSE signature verification callback and synthetic SD-JWT signing. The independent library is not a full external issuer application. |
| Discovery | Fixed credential issuer and OAuth AS metadata endpoints; exact HTTPS endpoint/issuer checks, supported format/key/proof algorithms and grant; redirects disabled before any disclosure |
| Token | Opaque bearer, 120 seconds, one approved configuration and one issuance, no refresh or authorization-details profile. This token supplies no MCP or owner-Vault authority. |
| Nonce | Unauthenticated POST to the separate nonce endpoint; unpredictable `c_nonce`, required `Cache-Control: no-store`, 60-second one-use fixture ledger |
| Proof | One `proofs.jwt` entry, `typ=openid4vci-proof+jwt`, ES256 with public JWK, issuer audience, fresh `iat` and issuer nonce. `iss` is omitted for anonymous pre-authorized exchange. No DID, X.509 or key attestation profile. |
| Response | HTTP 200 JSON with exactly one `credentials: [{ credential: <SD-JWT> }]`; no deferred, notification, batch or encrypted request/response profile |
| Transport | Web Request/Response serialization in process at reserved `.test` origins. No network/TLS, external application, QR, real wallet or device exercise. |

The library supports older drafts too. The Mikaki fixture enforces this narrower Final subset separately; library acceptance alone is insufficient for its authorization and receipt contract. Fixed issuer/key pins are a synthetic trust policy, not public issuer discovery or identity assurance.

## Receipt and storage

The explicit fixture approval gates discovery and token exchange. Cancellation performs no issuer request. The six-digit transaction code is generated separately from the offer and supplied out of band in the test; a real delivery/consent UI is not implemented. The fixture permits three incorrect transaction-code attempts before invalidating its 90-second pre-authorized code.

After validating discovery and a narrowly scoped issuance token, the receipt harness obtains a fresh nonce and generates a dedicated disposable holder key. The issuer verifies the signed proof and binds the issued artifact to the verified public key. Import verifies the pinned issuer signature/identity, credential type, expiry/time, exact holder binding and all three unique anchored fixture disclosures before creating a wallet object. Future issuer `iat` and duplicate disclosures reject. The prior import helper now explicitly enforces this flat membership fixture subset; it is not a generic SD-JWT importer.

The exact issuer artifact and private holder JWK are stored in separate purpose-bound AES-GCM envelopes under the existing in-memory wrapping-key fixture. Editing an annotation preserves the original proof. The receipt-to-presentation case then discloses only membership state and is accepted by the pinned independent OID4VP verifier library. Keys, original claims, offers, transaction codes, access tokens, proof JWTs and nonce values never enter the generated report.

Invalid/expired/replayed nonces fail closed. A failed proof consumes its nonce but not an otherwise valid issuance token, so the issuer endpoint can accept a newly signed proof with a fresh nonce. The bounded receipt function does not perform automatic retries. Issuance consumes the token before returning a credential; a lost response requires a new offer. Persistent recovery of a pending holder key and receipt, idempotent retry and deferred issuance are not qualified here.

## Evidence and repeatable commands

Forty-two scenarios pass, including receipt → encrypted original-artifact preservation → OID4VP presentation. Independent-library negative cases reject wrong proof nonce, audience, type and signature. Separate policy/wallet cases exercise cancellation, issuer/configuration/grant and metadata substitution, redirects, proof downgrade, unsupported encryption, token scope/refresh rejection, cached nonce, transaction-code limits, code/token/nonce expiry and reuse, one-winner concurrency, anonymous proof `iss`, proof time/private-key rejection, unapproved configurations, legacy/multiple/mixed requests, and invalid response type/shape/signature/holder/type/expiry/time/disclosures. The prior 28 presentation cases still pass: **70 combined cases**.

```sh
npm ci --prefix design/probes --ignore-scripts
npm run test:oid4vci --prefix design/probes
npm run test:oid4vp --prefix design/probes
npm run probe:oid4vci --prefix design/probes
npm run probe:oid4vp --prefix design/probes
npm run check:node
```

CI runs both suites after installing the isolated dependencies. Reports capture installed package versions, lockfile digest, environment and per-layer pass/fail; they suppress exception text and protocol secrets. The existing dependency-audit and deprecated presentation-decoder gates remain documented in the [OID4VP record](oid4vp-probe.md); this is not a clean security-audit or standards-certification claim.

## Remaining adoption gates

A subsequent [OIDF Suite 5.3.1 network run](oidf-conformance-2026-09-29.md) passes issuer **metadata only** through a local HTTPS adapter. It does not expose this fixture's token/nonce/credential endpoints or qualify network receipt. The suite issuance/wallet profiles require explicit client-authentication and sender-constraining choices that differ from this anonymous bearer subset; metadata success does not close that gap.

The subsequent [DPoP HTTPS receipt slice](fapi2-readiness.md#delivered-dpop-slice) now qualifies this synthetic issuer's token/nonce/credential path through a DPoP-required wrapper over loopback TLS with certificate and hostname checks. Its sender key is distinct from the credential holder key; receipt → encrypted import → presentation succeeds. This separate anonymous profile is not confidential-client authentication, full OIDF issuance qualification or an independent issuer/wallet application.

The evidence now covers both bounded credential receipt and presentation components. Next pin a named independent full issuer/wallet deployment and exercise the selected Final wire profile over TLS with synthetic data. Select real issuer trust/status and credential metadata policies before enabling broader imports. Choose a concrete relying-verifier use case before adding a production wallet or issuer service.

Product receipt also needs owner/account binding, exact consent UI, encrypted persistent credential records distinct from editable attributes, holder-key PRF envelopes and transfer/recovery/deletion, pending-receipt recovery, and intended-device evidence. Qualification of Authorization Code/PKCE, signed metadata, DPoP/attestations, encrypted request/response, deferred/notification flows, and other credential formats is conditional on that selected issuer. Issuance, presentation, and ongoing agent authorization remain separate authorities.
