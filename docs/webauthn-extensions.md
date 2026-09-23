# WebAuthn extension support

**WG-04 snapshot, 2026-09-23.** Structural parsing, signed integrity, extension-specific meaning, browser output, and persisted evidence are distinct guarantees. Later owner-only Vault PRF work must be read through [current status](status.md), rather than inferred from the shared verifier's CBOR parsing.

## Shared core

When the ED flag is set in `authenticatorData`, trailing data must be a CBOR map with string extension identifiers. Reject duplicate or nonstring keys, size/depth violations, and extra trailing data. Without ED, reject extension-like trailing bytes. Unknown string keys with structurally valid values are accepted but not interpreted, returned as verified facts, or stored.

On assertion, the credential signature covers the entire authenticatorData including extensions. A valid signature does not establish the meaning or acceptance policy of an unknown extension. Registration integrity depends on attestation format; the product default `none` has no attestation signature and does not establish authenticator provenance. See [WebAuthn Level 3 §5.7.4](https://www.w3.org/TR/webauthn-3/#dictdef-authenticationextensionsauthenticatoroutputs) and [§9.5](https://www.w3.org/TR/webauthn-3/#sctn-authenticator-extension-processing).

| Extension or feature | Current shared-core / local-UI request | Result and guarantee |
| --- | --- | --- |
| `credProps` | Product registration UI requests `true` | Browser checks `getClientExtensionResults().credProps.rk===true` and does not send completion when false/missing. This is a client compatibility check, not signed identity or provenance evidence; it is not sent to or stored by the server. |
| Discoverable credential | Registration uses `residentKey=required`; assertion omits allow list | Core binds the stored credential to user handle. It never treats `credProps` self-report as account proof; actual later discoverable login is the practical check. |
| `credProtect` | Not requested | If present, only generic structure is checked. Its protection level is not verified or stored; required UV does not imply a credProtect setting. |
| `prf` / `hmac-secret` | The shared verifier does not request or interpret these values | CBOR acceptance alone does not implement PRF. Browser-side Vault key handling is a separate capability with its own secret and failure contract. |
| `largeBlob` / `credBlob` | Not requested | No read, write, semantic check, or storage guarantee. |
| `appid` / `appidExclude` | Not requested | No AppID override of RP ID hash; U2F attestation verification is not legacy AppID migration. |
| Unknown authenticator extension | No specific request | Check structure; assertion signs its bytes, but no individual meaning, persistence, or disclosure is guaranteed. |
| Other client extension output | Not requested | Not fed into core Registration/Assertion. `getClientExtensionResults()` as a whole is not signed data. |

`credProps` is a [client extension](https://www.w3.org/TR/webauthn-3/#sctn-authenticator-credential-properties-extension); browser checks cannot replace server validation of owner, challenge, origin, and signature. PRF is a [distinct extension](https://www.w3.org/TR/webauthn-3/#prf-extension).

Shared native/Wasm tests reject nonstring and duplicate keys, accept structurally valid unknown values, reject an assertion whose extension value changes after signing, and avoid claiming verified extension meaning. Browser tests ensure missing/false `rk` cannot commit an account or consume an invitation, followed by successful registration and discoverable reauthentication. The official GUI suite was not rerun specifically for WG-04; the earlier 155-pass record is not a new run.
