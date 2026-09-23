# ADR 0008: Require full mandatory WebAuthn server conformance

**Status:** Accepted, 2026-09-22

## Decision

Passing all mandatory FIDO2 Server Conformance cases, without excluding an inconvenient required case, is the completion condition for the WebAuthn implementation. Formal certification submission is a separate decision. On 2026-09-22, the native and Wasm adapters each passed all 155 required cases in Tools 1.9.1. The 14 additional optional cases were outside that run. The [test record](../../local/conformance/results-2026-09-22.md) states the conditions.

Separate product defaults from verifier capability. The product still requests ES256, required user verification, discoverable credentials, and `none` attestation. The verifier accepts trusted, stored ceremony settings for UV required/preferred/discouraged, allowed algorithms, and account-bound versus discoverable assertions. It never changes policy based on a credential response.

For an account-bound assertion, bind the credential to both the stored user handle and allow list. Only there may a missing response `userHandle` be accepted; if present it must match. Discoverable assertions still require it. User presence is always required, and the result reports the actual UV flag.

In addition to ES256, support Ed25519, RS256, and compatibility-only RS1 verification in native and Wasm. Bind key format to algorithm and reject algorithms outside the server allow list. RSA is not a product default, and RS1 permission does not extend to token signing or key generation. Store public keys as algorithm-bearing COSE values. The unpublished local DB could be recreated, so no compatibility parser for its old SEC1 form was added.

## Implementation and validation

The implementation sequence was: shared policy/key handling; packed certificate, U2F, TPM, and required platform attestation; MDS signature, chain, revocation and validity checks; then full native/Wasm suite runs with independent regression tests. Certificate and TPM fields must be parsed structurally rather than found by byte search. HTTP retrieval and caching belong to adapters, with time and validation input passed into the core. Test roots must not become product trust anchors.

The core now supports `none`, packed self/full, U2F, and TPM 2.0 in the common verification path. It checks certificate chains, time, Basic Constraints, key usage, critical extensions, AAGUID, TPM public key, extraData, certified name, and DER-form TPM BMPString notices. Explicitly trusted X.509 v1 roots are supported and distinguished from intermediates. It rejects unsupported name and policy constraints rather than claiming a general Web PKI implementation.

MDS 3.1.1 processing verifies an ES256 BLOB against configured root SPKI, signed CRLs, required `iat`, BLOB number, optional `nextUpdate`, and status reports. The core has no network or durable state and contains no test root. Production scheduling, durable snapshot cache, and rollback protection for BLOB numbers remain operational work. Independent public fixtures produced with Python cryptography/OpenSSL exercise success and failure in native and Wasm CI. Optional formats and formal certification are not claimed.

## Dependency and audit boundary

The 2026-09-22 selected versions were `ed25519-dalek 3.0.0`, `sha1 0.11.0`, and `rsa 0.10.0-rc.18`. The RSA release candidate and target maintenance status require review before public release. The verifier uses RSA public-key verification only; it does not generate, load, store, or operate on RSA private keys.

`cargo audit` reported [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071.html), a private-key timing advisory with no fixed version recorded at the time. The narrow verification-only exception is documented in `.cargo/audit.toml`; it is not a clean audit. Introducing RSA signing, decryption, or key generation requires re-evaluating that exception, generally deferring private-key operations until the advisory is resolved. Other advisories are not excluded.

The design follows the [WebAuthn Level 3 Recommendation](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/) and [FIDO MDS 3.1.1 Proposed Standard](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html).
