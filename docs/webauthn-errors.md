# WebAuthn diagnostic errors and public responses

**WG-01, 2026-09-23.** This is the shared native/Wasm core and local OP error contract. It classifies rejection without changing which inputs are accepted.

`Invalid` is a payload-free enum. Stable `code()`, `stage()`, and `Display` reveal only a diagnostic code, never raw input, identifiers, keys, signatures, or certificates. The core has no logger, HTTP transport, clock, or correlation-ID generator. [`error.rs`](../crates/webauthn/src/error.rs) is the code authority; new categories must not change existing code meanings.

| Stage | Codes | Check |
| --- | --- | --- |
| `configuration` | `configuration` | Trusted setting shape, limits, algorithms, identified ceremony |
| `input` | `input`, `limit` | Encoding and size/depth bounds |
| `client_data` | `client_data_type`, `challenge`, `origin` | Type, challenge, origin/crossOrigin/topOrigin |
| `authenticator_data` | `rp_id`, `user_presence`, `user_verification`, `backup`, `counter` | RP hash and flags/counter |
| `credential` | `credential`, `user_handle`, `allow_list` | Saved credential and subject binding |
| `key` | `public_key`, `algorithm` | COSE key and allowed method |
| `signature` | `signature` | Cryptographic signature |
| `extensions` | `extensions` | Extension CBOR, keys, and trailing bytes, not individual semantics |
| `attestation` | `attestation`, `attestation_policy`, `trust`, `tpm` | Attestation format, acceptance, trust, TPM |
| `certificate` | `certificate`, `certificate_time`, `certificate_path` | Certificate profile, validity, path, anchor |
| `metadata` | `metadata`, `crl`, `crl_expired`, `revoked` | MDS, CRL scope/time, status |
| `ceremony` | `ceremony_purpose`, `browser`, `ceremony_expired`, `ceremony_consumed`, `ceremony_attempts` | Saved ceremony state |

The code reports the first failed check. `crl_expired` also covers before-`thisUpdate` and missing `nextUpdate`; `revoked` includes metadata `allowed=false`. Generic JSON/base64/CBOR errors may become `input` before a more specific check. Excessive extension nesting maps to `extensions`. A lower-level signature error can survive key/certificate verification, but all failed anchor candidates collapse to `certificate_path`; this is not a parser-internals or per-anchor diagnostic API. Metadata validation returning an entry and attestation later rejecting its status are different stages. WG-02 subsequently added trusted-context validation.

| Boundary | Behavior |
| --- | --- |
| Native Rust | Return `Result<_, Invalid>`; caller chooses public response and internal log |
| Internal Wasm/JS | Registration, assertion, attestation, and MDS functions throw a short JSON string such as `{"code":"challenge","stage":"client_data"}`; never forward it as HTTP |
| Local OP credential verification | Collapse detailed and credential-lookup failures to HTTP 400 `{"error":"invalid_credential"}` |
| Outer OP input/CSRF/ceremony checks | Keep their existing fixed error mappings; this change does not make every endpoint identical |
| Conformance adapter | Keep generic public errors; do not forward internal exceptions |
| Local OP internal log | Only `event=webauthn_rejected`, a fresh UUID `correlation`, `code`, and `stage` |

The [TypeScript normalizer](../local/webauthn-errors.ts) accepts only short strings and verifies code/stage pairing through Rust `diagnostic_stage`. Arbitrary exception text, unknown code, or mismatched stage becomes fixed `credential`; extra fields are discarded. Neither responses nor logs include challenge, user handle, credential ID, browser binding, token, or raw result. Correlation IDs are not derived from those values. Internal reasons are diagnostics on untrusted input, not proof of successful authentication. Equal response bodies do not imply constant processing time; log access and retention belong to the adapter.

Shared native/Wasm tests cover challenge, origin, RP ID, flags, counter, signature, limits, and independent certificate/TPM/MDS fixture reasons. Auth tests cover ceremony codes. JS tests check real Wasm exceptions and arbitrary-string removal; browser tests confirm modified challenge/origin produces the same public 400 with distinct fixed internal reasons. The official FIDO GUI suite was not rerun for WG-01; its earlier 155-pass result remains separate.
