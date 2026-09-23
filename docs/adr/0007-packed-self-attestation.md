# ADR 0007: Verify ES256 packed self-attestation

**Status:** Accepted, 2026-09-22

## Context and decision

Add ES256 packed self-attestation verification to the initial `none`-only verifier while keeping the compact core of [ADR 0006](0006-compact-portable-webauthn.md). The product's attestation request remains `none`, its signature default remains ES256, and user presence and verification remain required. Only the verifier's accepted input expands.

Follow the [WebAuthn packed-attestation procedure](https://www.w3.org/TR/webauthn/#sctn-packed-attestation): require matching ES256 credential COSE and `attStmt.alg`, then verify the DER signature over `authenticatorData || clientDataHash` using the credential public key. Reuse the existing P-256 dependency.

This decision does not add certificate or MDS trust verification. If `x5c` is present, even as an empty array or null, do not fall back to self-attestation. Initially accept only `alg` and `sig` in packed `attStmt`; reject ECDAA and unknown fields. Successful self-attestation proves possession of the credential private key, not authenticator provenance, model, or trust.

## Alternatives and impact

Remaining `none`-only would reject self-attestation despite the available signature primitive. Adding packed full and MDS at once would expand the boundary into certificates, trust stores, and network operations. Test scores alone do not justify converting attestations to `none` or relaxing UV.

Shared native/Wasm acceptance checks cover a valid signature, algorithm mismatch, DER shape, modified signature, missing fields, `x5c`, ECDAA, duplicate keys, and binding to raw client and authenticator data. Record official-suite results separately under [local conformance](../../local/conformance/README.md).
