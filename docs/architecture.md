# Architecture

Mikaki separates authentication, application authorization, and encrypted personal data. The shared Mikaki account is the login identity for participating applications; each application still owns its local subject, session, roles, and business data. This separation is an [accepted decision](adr/0001-common-account.md).

```text
Browser + passkey
       |
       v
Mikaki Worker (OIDC endpoints, HTTP, D1)
       |                 |
       v                 v
OIDC and auth cores   Vault storage (separate capability)
       |
       v
Portable WebAuthn verifier

Relying party <— authorization code / tokens —> Mikaki
Relying party —> its own app session and authorization
```

## Accounts and applications

Mikaki binds credentials to its `AccountId` and verifies one-time, purpose-bound WebAuthn ceremonies. Applications use an OIDC issuer and pairwise `sub` to map an authenticated user to their own subject. An email address, display name, or client-supplied account identifier does not establish a cross-application identity link. An RP must validate the OIDC response and create its own session; the [RP guide](rp-integration.md) describes the current contract.

The initial product profile requires a discoverable credential and user verification. Its default signing algorithm is ES256, and its attestation request is `none`. The verifier also handles selected compatibility algorithms and attestation formats. Conformance capability and product acceptance policy are deliberately recorded separately in [WebAuthn details](webauthn-attestation.md) and [ADR 0008](adr/0008-webauthn-conformance.md).

Account creation requires an invitation. The initial administrator is created through a one-time bootstrap gate. Browser input cannot grant an administrator role. The deployed flow and its limitations are in [account enrollment](account-enrollment.md). There is no initial recovery path for loss of all credentials; account recovery and recovery of encrypted vault data are separate problems.

## OIDC and sessions

The normal deployment uses OIDC Authorization Code, PKCE S256, static managed clients, and ES256 `private_key_jwt`. A separate conformance profile supports additional client authentication methods only in an isolated deployment. The [OIDC conformance target](oidc-core-conformance.md) documents that boundary. The RP must verify issuer, audience, state, nonce, token signature, and the returned subject, then establish an application session according to [RP integration](rp-integration.md).

The OP session and an RP's application session have different owners and lifetimes. The managed [session check](rp-session-check.md) gives an RP a bounded lease on its previously issued session ID. It is an extension, not standard OIDC Session Management or token introspection. Logout delivery and expiry must be backed by durable state and failure handling, as described in [session lifecycle](session-lifecycle.md). Runtime values live in a versioned D1 policy; see [runtime configuration](runtime-configuration.md).

## Portable core and storage

The Rust workspace keeps WebAuthn parsing and cryptographic verification independent of HTTP, Workers, and D1. The auth core owns credential and ceremony rules. The OIDC core owns protocol state and validation. The Worker supplies transport, durable transactions, time, randomness, and signing. Browser Wasm is a separate adapter for browser and conformance use; it does not grant authorization. See the [development guide](contributing.md) for the source map.

The durable store must enforce challenge consumption at most once, including concurrent requests. Ceremony purpose, account binding, browser binding, and verification conditions are fixed when the ceremony begins. A Rust type named “consumed” does not replace a database transaction. The [OIDC store contract](oidc-store-contract.md) and [ceremony contract](webauthn-ceremony-contract.md) give the detailed intended invariants.

## PRF and vault boundary

Passkey authentication does not prove that a user can decrypt vault data. A WebAuthn PRF result and keys derived from it stay in the browser and must not be logged or sent to the server. Random data-encryption keys are wrapped under purpose-separated derived keys; separate passkeys must not be assumed to produce the same PRF output. A new authenticator needs an authorized rewrapping path. A PRF failure must be explicit for operations that need decryption, with no silent weak-key fallback. The [vault design](personal-vault.md) describes the proposed sync and recovery model.

Vault storage is outside the authentication core. Login permission, vault read/write permission, and RP claim disclosure are separate decisions. Removing a credential cannot retract plaintext or keys already obtained by a device. [Claim sharing](vault-claim-sharing.md) remains a proposal; [recipient-key management](vault-recipient-key-lifecycle.md) has local components but is not activated or connected to UserInfo.

## Future boundaries

Federated messaging, a conversation archive, and MCP access are outside the initial login scope. Federation must distinguish DID identity, device encryption keys, and server delivery. MCP access requires explicit, bounded delegation and does not follow automatically from message receipt or login. The [roadmap](roadmap.md) identifies their maturity and links to the corresponding proposals.
