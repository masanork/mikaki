# Architecture

Mikaki separates authentication, application authorization, and encrypted personal data. The shared Mikaki account is the login identity for participating applications; each application still owns its local subject, session, roles, and business data. This separation is an [accepted decision](adr/0001-common-account.md).

```text
Browser + passkey
       |
       v
Mikaki Worker (OIDC endpoints, HTTP, D1)
       |                 |
       v                 v
OIDC and auth cores   OP-owned D1 + encrypted Vault R2
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

Vault storage is outside the authentication core. Login permission, vault read/write permission, and RP claim disclosure are separate decisions. Removing a credential cannot retract plaintext or keys already obtained by a device. Merged PR #125 adds record-v2 disclosures, with local evidence for system grants, selected RP consent and conditional disclosure audits; its Claim Worker no longer accepts format-1 attribute reads. The follow-up `feat/issue-121-legacy-vault-retirement` branch removes the remaining legacy attribute UI/routes. Legacy consent/native authorization paths and historical schema/data remain separate #121 work. The route/UI retirement diff is under validation and is not in main or production. The recipient decrypts only the selected ciphertext using its own Secrets Store seed. Production sharing policy and real-owner qualification remain separate gates. [Recipient-key management](vault-recipient-key-lifecycle.md) describes activation and rotation.

[ADR 0012](adr/0012-vault-protocol-boundaries.md) also separates storage/synchronization, credential presentation, file operations, and AI access. MCP adapts domain operations; it does not own the Vault data model. OIDC profile release and proposed OpenID4VP credential presentation serve different relying-party needs. The [protocol review](vault-protocol-review.md) records current candidates and their adoption gates.

## Runtime ownership and plaintext

The Rust OP owns OIDC/WebAuthn authorization, owner ciphertext commits, D1 and R2. Its default handler serves public routes; named `AgentStore` and `ClaimStore` entrypoints supply bounded internal capabilities. Agent and UserInfo production configurations omit D1/R2 bindings. The [ownership ADR](adr/0015-service-data-ownership.md) records atomic batches and rollout order; these binding changes are locally verified and await deployment.

The browser holds PRF output, the nonextractable owner key, decrypted records and its local SQLite search index. Owner storage receives ciphertext and public identity/revision metadata. For an approved UserInfo disclosure, the recipient returns the allowed name to the OP, which constructs the plaintext UserInfo response for the RP. The UserInfo recipient temporarily holds only authorized profile plaintext and its recipient secret. The Agent domain authority can decrypt explicit selected snapshots with its own recipient key, and private drafts/results can contain delegated plaintext in its authorized storage. Revocation ends future access; it cannot retract copies already returned. Root/content keys are never delegated. See [source authorities](implementation-authorities.md), [bounded authentication retention](auth-resource-lifecycle.md) and [ciphertext collection](vault-garbage-collection.md).

The deployed issuer configuration is `https://auth.mikaki.org`; a checked-in configuration is not proof of a running version or policy. Current owner-key v2 record storage and browser conversation search exist. Additional credential enrollment/rewrapping, root rotation, record-selection sharing UI and live conversation ingestion still have open qualification or implementation work.

## Identity development boundary

The Identity/Wallet implementation merged in PR #105 on 2026-10-04 is separate from the encrypted owner Vault. Its OP normalizes card-derived name, address, birthdate, optional gender/expiry and provenance as plaintext D1 data for linking, explicit release consent and issuance. Raw card EFs, PINs, photos, personal number and its hash are excluded from persistent storage/logs. Linked attributes remain until owner deletion; unlinked intake transactions expire after 600 seconds, and abandoned transactions and expired nonces use bounded minute/intake cleanup. Issued credentials expire within five minutes; owner deletion stops further issuance but cannot erase an already delivered credential. See [Identity/Wallet data and retention details](identity-card-issuance.md). This is not the Vault ciphertext GC or the ordinary OIDC retention contract. PR #105 pre-merge CI passed; the subsequent [main CI run](https://github.com/masanork/mikaki/actions/runs/37190624338) failed in `identity-issuance` with `Response body already read`. Neither run establishes production deployment or activation.

Holder credentials and holder private keys occupy separate Wallet/native compartments; verifier-approved presentation can reveal selected plaintext. A linked attribute or custom issued credential does not establish government issuance or current possession of the original card. Native ordinary OIDC authentication likewise does not grant PRF decryption or Wallet presentation permission. The separate, disabled-by-default [legacy Native Vault OAuth preview](native-vault-oauth.md) uses owner consent and a DPoP-bound `openid vault.read` token for ciphertext access. This follow-up retires its attribute resource API; consent and token issuance remain for the next retirement slice. Installed-app/device qualification remains open; see [native client authority](tauri-client-auth.md).

Identity migrations `0036`–`0044` are part of the merged source; `0045`–`0046` add Vault GC and authentication resource lifecycle changes. The production migration ledger, feature flags and trust/attestation configuration have not been rechecked here. The incremental deployment and reset paths tracked by [#116](https://github.com/masanork/mikaki/issues/116) and [#121](https://github.com/masanork/mikaki/issues/121) must be reconciled before applying migrations or resetting production data. Identity release requires explicit consent and configured trust/attestation policies; the HAIP profile adds its own enable flag and issuer/wallet/key trust. Physical-card/ISO qualification and certification remain separate follow-up gates tracked by [#117](https://github.com/masanork/mikaki/issues/117)–[#120](https://github.com/masanork/mikaki/issues/120). No current production activation is claimed.

## Future boundaries

Federated messaging and live cross-application conversation ingestion remain future work. Encrypted thread records and browser-local search are implemented; existing typed-record and Agent APIs do not by themselves import real conversations. Federation must distinguish DID identity, device encryption keys, and server delivery. MCP access requires explicit, bounded delegation and does not follow automatically from message receipt or login. The [roadmap](roadmap.md) identifies their maturity and links to the corresponding proposals.
