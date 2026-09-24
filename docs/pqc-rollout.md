# Phased adoption of ML-KEM and ML-DSA

**Status, 2026-09-24:** Production sharing remains disabled. The product browser sender and claim Worker receiver implement a candidate ML-KEM-768 HPKE envelope. An owner approval path stores an envelope and system Grant atomically and supports revocation when D1 policy permits. Node, Chromium, RustCrypto, SQLite, and local workerd tests exercise the pieces. A read-only production probe opened a synthetic product envelope with the live Secrets Store key and rejected owner/ciphertext substitutions. FIDO registration/assertion capture and verification tools are ready for hardware evaluation. Passkey enrollment and OIDC signing have not changed.

| Boundary | Current product | Next unit of work | Activation gate |
| --- | --- | --- | --- |
| Vault | Owner-only PRF → HKDF → AES-GCM wrapping; disabled system-sharing path and candidate ML-KEM envelope | Exercise the owner browser against production after public reachability is restored, review recovery and key failure behavior, then design RP-specific ClaimRelease | Public-key authenticity and continuity, standard KEM/AEAD composition, independent vectors, browser performance, and failure behavior |
| FIDO authenticator | Product registration/verification uses ES256 (COSE `-7`) | Measure support in actual authenticator, browser, and OS; add isolated ML-DSA-65 (COSE `-49`) registration/assertion verification | Successful enrollment and reauthentication on supported hardware, tamper and mix-up rejection, coexistence with ES256 credentials, and a defined enrollment policy |
| OIDC/JOSE | Production client authentication uses ES256; ID Tokens use ES256/RS256 | Probe RFC 9964 ML-DSA JWK/JWS interoperability | Check RP libraries, JWKS and rotation, HTTP limits, conformance profile, and signing-key custody before explicit per-client enablement |

ML-KEM establishes a shared secret for key delivery; it is not a passkey signature algorithm. ML-DSA signs but does not by itself improve the Vault's long-term confidentiality. Vault bodies already use AES-256-GCM, and owner data keys are wrapped under passkey PRF-derived keys. ML-KEM is relevant to delivery of a data key to another device or system recipient. The [grant and disclosure design](vault-claim-sharing.md) and authentic recipient public keys must come first. Do not invent a format that directly treats an ML-KEM shared secret as an AES key.

## Sequence before product use

1. Finish the [UserInfo recipient-key lifecycle](vault-recipient-key-lifecycle.md). D1 holds public keys and lifecycle state; the claim Worker's Secrets Store binding holds the private seed. Generation 1 is active; key identity and a synthetic product envelope were verified through the live binding. Define and exercise recovery before shared data depends on it.
2. The owner-only browser now creates an additional recipient envelope for a saved attribute's data key after PRF unlock. It binds origin, account, attribute, revision, service, key ID, and exact ciphertext in HPKE info/AAD. D1 stores the envelope, Grant, and audit atomically. The D1 policy starts disabled; attribute updates and policy disable revoke the Grant.
3. The claim Worker now checks decryptability before accepting a system Grant. A production synthetic probe verified correct and incorrect owner/ciphertext bindings. Test the full owner path, rotation, wrong key/revision/attribute substitution, and key-service failures across Worker and browser. Add RP-specific consent and ClaimRelease before UserInfo returns `name`. Owner-only Vault use must not require a PQC key or ML-DSA-capable FIDO device.

The system Grant only permits a future claim service to consider the attribute; it grants no RP access by itself.

An assigned COSE number does not establish support in an available FIDO device, browser, or OS. An existing credential cannot be converted to PQC on the server. Enroll a new credential on verified hardware and run it alongside ES256 before migration. Do not advertise `-49` in `pubKeyCredParams` until verification works, or label an implicit fallback as PQC support.

At the time of the probe, Cloudflare Workers' WebCrypto compatibility table did not list ML-KEM or ML-DSA. Begin with isolated Rust/Wasm validation rather than assuming built-in support. The candidate RustCrypto `ml-kem 0.3.2` and `ml-dsa 0.1.1`, and the noble comparison implementation, state that they lack independent audit. Before product integration, extend known-answer coverage across parameters, review key/signature size bounds and dependencies, and measure resources in the actual Worker and browser.

The product envelope currently names draft-04 and decrypted one official [draft-05 vector](../design/probes/pqc/hpke-pq-draft05-vector.json) for ML-KEM-768/HKDF-SHA256/AES-128-GCM. The product AES-256-GCM sender and independent RustCrypto receiver interoperate locally and with the live seed in a synthetic probe. Recovery, full owner flow, and final suite versioning remain gates before enabling writes.

## References

- [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) and [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)
- [RFC 9964: ML-DSA in JOSE and COSE](https://www.rfc-editor.org/info/rfc9964/)
- [FIDO Server Requirements 2.3 Review Draft](https://fidoalliance.org/specs/fidoserver/fido-server-v2.3-rd-20260226.html) (review draft, not hardware evidence)
- [WebAuthn Level 3](https://www.w3.org/TR/webauthn/)
- [Cloudflare Workers WebCrypto](https://developers.cloudflare.com/workers/runtime-apis/web-crypto/)
- [RustCrypto ML-KEM](https://docs.rs/ml-kem/0.3.2/ml_kem/) and [ML-DSA](https://docs.rs/ml-dsa/0.1.1/ml_dsa/)
- [NIST ACVP samples](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files) and [noble-post-quantum](https://github.com/paulmillr/noble-post-quantum)
- [draft-ietf-hpke-pq-05](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-pq-05) (working draft; product format undecided)
