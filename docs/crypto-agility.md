# Cryptographic agility

**Design condition, 2026-09-22.** Design for a possible PQC transition over the coming years without enabling unverified PQC or a custom hybrid in the initial product. Maintain a path for gradual addition, coexistence, and retirement. OIDC continues to use standard JWT/JOSE. See the [phased rollout](pqc-rollout.md) for current probes and activation gates.

## Initial signing and compatibility

The prior proposal to issue ordinary tokens primarily with RS256/RSA-3072 was withdrawn. ES256 (ECDSA P-256) became the leading JOSE default, with Ed25519 as a comparison candidate; actual library/native/Wasm/RP interoperability and performance inform the chosen profile. `private_key_jwt` client keys are registered separately from OP ID Token signing keys and never shared with WebAuthn credentials.

OIDC Core §15.1 requiring an OP to support RS256 does not require it as the ordinary issuance default. Implement and test RS256 for the relevant conformance/client profile without silent RSA fallback for an unsupported client. If Ed25519 is adopted, check the exact `alg=Ed25519` in RFC 9864 versus older `alg=EdDSA`, `crv=Ed25519` expectations in actual libraries and pin the registration profile; do not equate them unconditionally. Neither ES256 nor Ed25519 is post-quantum.

RSA and SHA-1 implementations may be needed for bounded backwards compatibility or conformance. Distinguish *implemented*, *accepted for verification*, and *default for new issuance*. Adding implementation code alone must not broaden production policy. RSA is a key family; RS256 uses SHA-256 and does not require SHA-1. A SHA-1 certificate identifier such as JOSE `x5t` does not authorize SHA-1 signatures. Each compatibility profile records the standard/test, allowed operation (identifier processing, verification, issuance), client/scope, and shutdown procedure. Use maintained cryptographic libraries, not new primitives.

## Boundaries prepared from the start

- Key records carry purpose, `kid`, generation, algorithm/parameters, public format version, private-key reference, and state. Do not force every key into RSA n/e or fixed EC-coordinate columns; validate format-specific content in types.
- Keep issuance profile separate from verifier allow lists, scoped per client and purpose. Reject unsupported algorithms; never select solely from untrusted token `alg`.
- Permit old/new profiles and public keys to coexist during migration without inventing a multi-signature JWT format or building an unused provider framework.
- Bound variable-length keys and signatures per algorithm, including possible multi-kilobyte PQC values. Reassess HTTP headers/bodies, JWKS, DB, and Wasm memory when adding one; do not make sizes unlimited.
- Version Vault ciphertext, wrapping scheme, and key generation, authenticating selection headers. Distinguish readable old formats from new-write format and design resumable re-encryption/rewrapping at the Vault stage.
- Deployment rollback cannot re-enable retired algorithms or revoked keys. Only implemented and tested profiles can become operationally selectable.

## Migration by boundary

For OIDC: verify a new algorithm in isolation, switch issuance per client, retain old keys while tokens/logout hints need them, then stop old issuance and verification. Derive neither `AccountId` nor `sub` from a signing key, so rotation does not change identity.

WebAuthn additionally depends on browser, authenticator, and standard support. A server cannot transform an old credential into a PQC credential. Register supported new credentials alongside old ones, then retire old ones with an explicit policy. Evaluate transfer of PRF-wrapped data keys separately from signature-algorithm migration.

MLS signatures/key agreement, DID keys, and TLS key exchange each have separate standard-suite and library migrations. Do not edit an active MLS state's algorithm field in place. A method such as `did:key` may change identifier when the key changes and needs a reconfirmation path.

PQC signatures alone do not give stored data long-term confidentiality. Assess harvest-now-decrypt-later risk separately for storage encryption, key transport, and wrapping. Later rotation cannot recall a leaked key or ciphertext already collected; rekey and re-encrypt where necessary instead of assuming rewrapping always suffices.

Acceptance tests reject unsupported or mismatched key types and cover old/new coexistence, per-client switch, retirement, partial failure, and rollback. Adding an algorithm requires known-answer vectors, interoperability, native/Wasm size/performance, input limits, and dependency review. Initial production PQC is not required.

References: [OIDC Core §15.1](https://openid.net/specs/openid-connect-core-1_0.html#ServerMTI), [RFC 7515 §4.1.7](https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.7), [RFC 9864](https://www.rfc-editor.org/rfc/rfc9864.html), [RFC 9964](https://www.rfc-editor.org/rfc/rfc9964.html), and [FIPS 203/204/205](https://csrc.nist.gov/publications/fips).
