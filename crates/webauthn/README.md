# mikaki-webauthn

This is the WebAuthn verification core shared by native Rust and Wasm. It follows the compact-core choice in [ADR 0006](../../docs/adr/0006-compact-portable-webauthn.md) and the conformance gate in [ADR 0008](../../docs/adr/0008-webauthn-conformance.md).

## Boundary and supported behavior

`register` and `authenticate` verify the challenge, origin, RP ID, and ceremony policy supplied by a trusted caller. They return result types that external Rust code cannot construct. The core has no HTTP, database, clock, randomness, OIDC, or Vault dependency. Build `Context` from saved transaction state and server configuration, never from the credential response.

- Credential signatures: ES256, Ed25519, RS256, and compatibility-only RS1. The default allow list contains only ES256. Stored public keys are base64url COSE.
- Attestation: `none`, packed self/full, FIDO U2F, and TPM 2.0. Certificate-backed formats require explicit trusted metadata.
- Assertions: user presence, required/preferred/discouraged user verification, identified and discoverable ceremonies, account/allow-list/user-handle binding, backup and counter checks, extension CBOR structure, and strict JSON/CBOR/COSE limits.
- Certificates: signatures and key/algorithm consistency; time, issuer/subject, CA, key usage, path length, duplicates, critical extensions, and format-specific fields. TPM public key, extraData, and certified name are parsed and matched structurally.
- MDS: ES256 BLOB signature, chain to a configured root SPKI, signed CRL validity and revocation, `iat`, BLOB number, optional `nextUpdate`, AAGUID/U2F identifiers, and status reports. HTTP retrieval and stateful updates are outside the core; see [MDS operation](../../docs/webauthn-mds-operation.md).

`Context.attestation` supplies verification time and authenticated metadata. `attestation_hint` is an unverified lookup hint; the core matches AAGUID or U2F certificate key identifier itself. Test roots are not embedded in the product core.

The caller must validate transaction purpose, browser binding, expiry, unconsumed state, and credential ownership. It must atomically commit challenge consumption and credential insertion/update after verification. The product defaults remain ES256, required UV, discoverable credentials, and an attestation request of `none`.

## Verification evidence

On 2026-09-22, both native and Wasm adapters passed all **155 mandatory** FIDO2 Server Conformance Tools 1.9.1 cases, with no case hidden by a before-all failure. Fourteen optional cases were not selected. There has been no formal certification submission. See the [run record](../../local/conformance/results-2026-09-22.md).

```sh
cargo test --locked -p mikaki-webauthn
wasm-pack test --node crates/webauthn --locked
```

The shared native/Wasm suite runs 24 tests and four compile-fail type-boundary checks. Independent Python cryptography/OpenSSL fixtures cover packed/U2F/TPM, certificate trust and tampering, and MDS signature, CRL, revocation, and expiry. Fixtures contain no saved private keys or official suite code. CI runs the regression tests; the official GUI suite uses a separate [local adapter](../../local/conformance/README.md).

## Limits and follow-up

This is not a general Web PKI validator. It rejects unsupported name or policy constraints and unhandled critical extensions. MDS validation is stateless: durable snapshots, BLOB-number high-water mark, scheduled updates, failure alerts, and firmware-specific status application are not implemented. Product MDS is not enabled. Cross-origin iframes, some optional algorithms and platform attestation formats are unsupported. Legacy tokenBinding is parsed structurally but TLS Token Binding is not provided.

Parser [fuzz targets](../../docs/webauthn-fuzzing.md), synthetic multi-browser checks, and scoped size/performance measurements now exist. Real authenticator interoperability and external security review remain separate gates. A conformance pass is not a security audit or proof of superiority over webauthn-rs.

For extension-specific request/result/storage guarantees, see [extensions](../../docs/webauthn-extensions.md). For stable internal reason codes and public-response mapping, see [errors](../../docs/webauthn-errors.md). `Context::validate()` runs at both registration and authentication entry points; see the [ceremony contract](../../docs/webauthn-ceremony-contract.md). The optional attestation policy accepts `none`/self, while `required_trusted` rejects them; see [attestation](../../docs/webauthn-attestation.md).
