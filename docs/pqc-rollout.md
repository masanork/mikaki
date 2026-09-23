# Phased adoption of ML-KEM and ML-DSA

**Status, 2026-09-23:** No post-quantum algorithm is enabled as a product feature. The [isolated probes](../design/probes/pqc/README.md) exercised ML-KEM-768 and ML-DSA-65 across native, Node Wasm, and Chromium; NIST ACVP sample vectors; interoperability with noble; and an HPKE-wrapped Vault data key with rejection of version mismatches. A FIDO registration/assertion capture page and verification CLI are ready for testing when hardware is available. Current Vault format, passkey enrollment, and OIDC signing have not changed.

| Boundary | Current product | Next unit of work | Activation gate |
| --- | --- | --- | --- |
| Vault | Owner-only PRF → HKDF → AES-GCM key wrapping, no active system recipient | Complete recipient directory, secret storage, grants, and browser/Worker envelope interoperability | Public-key authenticity and continuity, standard KEM/AEAD composition, rewrapping and recovery, independent vectors, browser performance, and old-version behavior on failure |
| FIDO authenticator | Product registration/verification uses ES256 (COSE `-7`) | Measure support in actual authenticator, browser, and OS; add isolated ML-DSA-65 (COSE `-49`) registration/assertion verification | Successful enrollment and reauthentication on supported hardware, tamper and mix-up rejection, coexistence with ES256 credentials, and a defined enrollment policy |
| OIDC/JOSE | Production client authentication uses ES256; ID Tokens use ES256/RS256 | Probe RFC 9964 ML-DSA JWK/JWS interoperability | Check RP libraries, JWKS and rotation, HTTP limits, conformance profile, and signing-key custody before explicit per-client enablement |

ML-KEM establishes a shared secret for key delivery; it is not a passkey signature algorithm. ML-DSA signs but does not by itself improve the Vault's long-term confidentiality. Vault bodies already use AES-256-GCM, and owner data keys are wrapped under passkey PRF-derived keys. ML-KEM is relevant to delivery of a data key to another device or system recipient. The [grant and disclosure design](vault-claim-sharing.md) and authentic recipient public keys must come first. Do not invent a format that directly treats an ML-KEM shared secret as an AES key.

## Sequence before product use

1. Complete the [UserInfo recipient-key lifecycle](vault-recipient-key-lifecycle.md). D1 holds public keys, IDs, generations, and lifecycle state; the dedicated claim Worker's Secrets Store binding holds private seeds. The directory, verification route, service binding, lifecycle CLI, and browser validator exist. Seed provisioning, calling the validator from the future envelope flow, and operational activation remain.
2. Only when the owner unlocks an attribute, create an additional recipient envelope for that revision's data key. Bind origin, attribute, revision, service, and key ID in HPKE info/AAD. Keep the owner envelope. Publish the envelope and grant in the same version; disable system sharing for an update whose key delivery fails.
3. Test revocation, rotation, attribute updates, wrong key/revision/attribute substitution, and key-service failures across Worker and browser before connecting UserInfo. Owner-only Vault use must not require a PQC key or ML-DSA-capable FIDO device.

The isolated HPKE probe validates part of step 2's cryptographic boundary. Directory and lifecycle code exists, but Secrets Store provisioning, operational activation, grants, and browser sharing are not connected to the product.

An assigned COSE number does not establish support in an available FIDO device, browser, or OS. An existing credential cannot be converted to PQC on the server. Enroll a new credential on verified hardware and run it alongside ES256 before migration. Do not advertise `-49` in `pubKeyCredParams` until verification works, or label an implicit fallback as PQC support.

At the time of the probe, Cloudflare Workers' WebCrypto compatibility table did not list ML-KEM or ML-DSA. Begin with isolated Rust/Wasm validation rather than assuming built-in support. The candidate RustCrypto `ml-kem 0.3.2` and `ml-dsa 0.1.1`, and the noble comparison implementation, state that they lack independent audit. Before product integration, extend known-answer coverage across parameters, review key/signature size bounds and dependencies, and measure resources in the actual Worker and browser.

The Vault HPKE probe implements draft-04 and decrypted one official [draft-05 vector](../design/probes/pqc/hpke-pq-draft05-vector.json) for ML-KEM-768/HKDF-SHA256/AES-128-GCM. The product AES-256-GCM envelope format and browser/Worker interoperability remain unverified. Keep product issuance separate from “implemented” and “accepted for reading,” and make each explicit in operational policy if adopted.

## References

- [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) and [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)
- [RFC 9964: ML-DSA in JOSE and COSE](https://www.rfc-editor.org/info/rfc9964/)
- [FIDO Server Requirements 2.3 Review Draft](https://fidoalliance.org/specs/fidoserver/fido-server-v2.3-rd-20260226.html) (review draft, not hardware evidence)
- [WebAuthn Level 3](https://www.w3.org/TR/webauthn/)
- [Cloudflare Workers WebCrypto](https://developers.cloudflare.com/workers/runtime-apis/web-crypto/)
- [RustCrypto ML-KEM](https://docs.rs/ml-kem/0.3.2/ml_kem/) and [ML-DSA](https://docs.rs/ml-dsa/0.1.1/ml_dsa/)
- [NIST ACVP samples](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files) and [noble-post-quantum](https://github.com/paulmillr/noble-post-quantum)
- [draft-ietf-hpke-pq-05](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-pq-05) (working draft; product format undecided)
