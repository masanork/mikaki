# Attestation acceptance and verified evidence

**WG-03, 2026-09-23.** The shared core implements an explicit trusted-attestation requirement and returns evidence about what was checked. This does not make attestation mandatory for normal product enrollment.

## Request, trust input, and acceptance policy

The browser's `attestation` option requests a conveyance preference; it does not set the server's acceptance rule. `none` and self-attestation provide no authenticator-provenance evidence. The RP decides whether to accept them, as described in [WebAuthn Level 3 §§5.4.7, 6.5, 7.1](https://www.w3.org/TR/webauthn-3/).

`Context.attestation` supplies trusted validation material and server time. Merely providing it does not reject `none` or self. Select acceptance separately with `Context.attestation_policy`:

| Policy | None / packed self | Certificate-backed packed / FIDO U2F / TPM |
| --- | --- | --- |
| `optional` (default) | Accept after format-specific validation | Accept only after authenticated metadata match, certificate path, signature, and all other checks |
| `required_trusted` | Reject, even if a self-signature is valid | Accept only after the same complete trusted validation |

Never downgrade an invalid certificate-backed attestation to self or `none`. Missing/disabled trust material or anchor mismatch fails. Unknown formats fail under either policy. A required-policy rejection of valid `none`/self uses internal code `attestation_policy`; malformed signatures, certificates, or trust inputs retain their own stage reason.

This policy applies at registration, not to re-verification on each assertion. Normal local OP registration keeps ES256, required UV, discoverable credentials, browser request `none`, and server policy `optional`. A product that restricts authenticator provenance must save `required_trusted` at issuance and pair a suitable conveyance request with trust-data refresh, stored evidence, and reassessment procedures.

## Registration result

`VerifiedRegistration.attestation()` returns `AttestationEvidence`. External Rust code cannot construct or deserialize this type; only a registration passing verification and acceptance policy can return it. The JS boundary serializes it as a result field. Never trust matching JSON supplied over HTTP as a verified result.

| Field | Meaning |
| --- | --- |
| `format` | Validated `none`, `packed`, `fido-u2f`, or `tpm` |
| `kind` | `none`, `self`, or `trusted`; not a precise Basic/AttCA/AnonCA classification |
| `aaguid` | Canonical base64url of the 16 authenticatorData bytes; not provenance evidence for none/self, zero for U2F |
| `trust` | Null for none/self; present only after full certificate-backed verification |
| `trust.metadata_key` | Matched metadata ID: base64url AAGUID for packed/TPM, lowercase hex SHA-1 certificate key identifier for U2F |
| `trust.anchor_sha256` | Canonical base64url SHA-256 of the DER trust anchor on the path that actually succeeded (or directly trusted batch certificate) |
| `trust.verified_at` | Server-supplied Unix seconds used for validation, not a future validity guarantee |

The anchor fingerprint comes from the successful path, not the first configured anchor or an unverified hint. This evidence reports matching against supplied trust material. It does not prove official MDS provenance, a BLOB version, a particular physical device, or continuing safety. It excludes raw responses and certificate chains; do not log full registration results by default. The local OP does not impose a provenance restriction or persist this extra evidence. Future revocation/firmware reassessment needs further stored data and MDS operations.

Native/Wasm shared tests cover optional acceptance of none/self with trust input, their required-mode rejection, and independent packed/U2F/TPM fixtures under required mode. They check format, metadata ID, time, and actual anchor fingerprint, including a directly trusted batch certificate. Compile-fail tests block evidence construction/deserialization; JS tests cover the Wasm result and invalid/missing policy or trust. Normal browser tests use the default policy. The official FIDO GUI suite was not rerun for this WG-03 change.
