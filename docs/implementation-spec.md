# Mikaki implementation specification

> Historical implementation plan, drafted 2026-09-22. It preserves acceptance gates and future design. For current implementation and deployment evidence, start with [project status](status.md) and the relevant runbook. Logical operation names here do not fix HTTP routes or public Rust signatures.

[ADR 0006](adr/0006-compact-portable-webauthn.md) prioritizes a small native/Wasm WebAuthn core. The contracts below distinguish mandatory acceptance properties from initial candidates that still need testing. Topic specifications and [ADRs](adr/README.md) retain their own scope.

## 1. Goals and stages

Mikaki shares passkey verification for tossa and tsudoi, uses client held keys to restore encrypted personal data, plans device end to end messaging between separate Cloudflare accounts, archives user selected conversations, and later delegates narrow local MCP reads. OIDC is required for the first production app connection. Initial scope excludes password login, SAML, SCIM, unrestricted federation, group chat, server full text search, custom ratchets, and a soft substitute for MLS.

| Stage | Scope and exit evidence |
| --- | --- |
| P0 | WebAuthn/auth/Worker core, browser PRF probe, and OIDC; complete login UX and protocol acceptance before production RP connection. |
| S1 | Independent real MLS/Wasm spike: two clients join, exchange, persist/restore, update, and remove. |
| P1 | Personal Vault, key wraps, and synchronization; restore on device B and preserve good data under conflict/failure. |
| P2 | Import only authorized tossa/tsudoi conversations; handle duplicate, edit, and delete semantics. |
| P3 | After S1, device MLS and limited federation; two separate Cloudflare accounts exchange one to one messages under fault tests. |
| P4 | Local MCP read access for an explicit target, expiry, and recipient with revocation tests. |
| Later | Containers, concurrent devices, and groups after distinct requirements/design reviews. |

Do not add empty crates or APIs for later phases. A failed S1 spike does not block authentication or Vault work. Record material protocol changes in an ADR.

## 2. Threat model and data boundaries

Protect credential ownership, login results, user keys and content, one time operations, and continuity of cryptographic state. Consider hostile clients/peers, tampered storage or keys, replay and concurrency, lost responses, restarts, and old restored state. Mikaki authenticates users but is not the default decryptor of Vault content or messages. Delivery keys authenticate servers, not users. API authorization and recipient key distribution are separate controls.

Server operational data includes credential/session/revocation state, OIDC subject mappings, and claims needed for approved UserInfo behavior. The initial UserInfo profile has only `sub`. Sensitive server readable fields may later use purpose scoped KEKs under KMS/HSM; a live authorized server can still read them. Locker/Vault bodies, titles, conversation content, and secret attachments are encrypted on the client; the server stores ciphertext and minimum synchronization metadata. No default server escrow, server decrypt fallback, or universal system key exists.

A user may explicitly share an individual data key with a purpose bound system principal, for example a claim service or malware scanner. Such a recipient can decrypt that item independently. Bind envelopes to recipient, key ID, purpose, data revision, suite, and generation; authorize and audit wrap/unwrap separately from API permission. Revoke future access first and rekey if future cryptographic separation is needed. Plaintext already delivered cannot be recalled. Never send PRF output, root keys, or secret plaintext through API bodies, URLs, logs, tokens, or analytics. Client side encryption does not defend an unlocked browser from malicious same origin code/XSS. Metadata, availability, and perfect rollback detection are outside the initial guarantee.

## 3. Crate and package boundaries

| Unit | Responsibility |
| --- | --- |
| `mikaki-webauthn` | Parse and cryptographically verify WebAuthn; produce verified facts, without DB/HTTP/business policy. |
| `mikaki-auth` | Ceremonies, credentials, AccountId, and atomic store operations; no Vault/MLS/Worker types. |
| `mikaki-oidc` | Client authentication, authorization, sessions, JOSE purposes, logout outbox; no D1/Workers/Vault types. |
| `mikaki-worker` | Composition root, HTTP, bindings, D1/R2, policy, time, randomness, and outbound IO. |
| `mikaki-browser-wasm` | Browser/local JSON/Wasm boundary; no server authorization commit. |
| `mikaki-vault` (P1) | Grants, ciphertext versions, synchronization operations; no decryption or Cloudflare types. |
| `mikaki-client` (S1/P1) | Device key protection and MLS/Vault state transitions; no server DB. |
| `mikaki-federation` (P3) | DID/delivery verification, deduplication, retry; no message plaintext or MLS secret state. |
| `packages/browser` | WebAuthn browser API, UI, IndexedDB, transport, and Wasm invocation. |

Dependency direction and verified type construction must prevent untrusted HTTP input from masquerading as a completed authentication. Add crates when a real boundary has implementation, not to reserve a name.

## 4. WebAuthn and account contract (P0)

Use discoverable passkeys under an explicit RP ID and allowlisted origins. Validate challenge, origin, RP ID hash, operation type, user presence and required verification, credential ID, user handle, signature, algorithm, flags, and extension outputs as specified in the [ceremony contract](webauthn-ceremony-contract.md). The initial credential algorithm is ES256. Reject ambiguous/duplicate malformed JSON, CBOR, and COSE inputs within size/depth limits. Verify on native and Wasm. A successful verifier returns typed facts; the auth layer atomically consumes a one time ceremony and updates registration/authentication state. At most one concurrent finish succeeds. A failed signature must not create or use a login session.

Logical operations are `BeginRegistration`, `FinishRegistration`, `BeginAuthentication`, `FinishAuthentication`, `ListCredentials`, and `DeleteCredential`. New registration requires approved invitation or recent owner proof. Credential management requires recent user verification; never delete the last active credential without a reviewed recovery path. A passkey's removal from the server does not erase it on the physical authenticator. Keep credential and account status in every final commit check.

The common account is separate from each app's subject and permissions. OIDC login can succeed without Vault/PRF. [OIDC login](oidc-login.md), [session lifecycle](session-lifecycle.md), and [identity and keys](oidc-identity-and-keys.md) define production RP integration. Browser transactions bind state/nonce/PKCE to that browser; no RP accepts an unverified account ID sent by the client.

## 5. PRF and personal Vault (P1)

PRF is an optional WebAuthn extension for Vault unlock, never a condition of ordinary login. Derive purpose separated wrapping material with a defined KDF, salt, context, and version. Keep root/data keys and plaintext on the device. A `Vault` records owner, format, and generation; `KeyWrap` binds owner credential, PRF input, salt/context version, key type/generation, nonce, and ciphertext; `KeyEnvelope` binds CK/DEK to scope, recipient/key ID, purpose, suite/version, generation, and wrap bytes. A `Grant` binds owner/app/delegate, collection, operation, expiry, and revocation revision. `ObjectHead` points to an immutable ciphertext version/digest; `Mutation` stores operation ID, request hash, result revision, and outcome.

Generate a random data key per appropriate object/snapshot scope and authenticate format, owner, object, revision, and purpose in AAD. Define test vectors before persisting data. Additional passkeys/devices need explicit key rewrapping and ownership proof; login recovery does not automatically recover Vault secrets. A missing object and a decrypt failure are distinct results. On failure, do not recreate a key or overwrite ciphertext.

For remote mutation, authenticate and authorize, validate expected revision and quota, write immutable ciphertext to R2, then conditionally commit D1 head, mutation receipt, and tombstone/change state. Return success after DB commit. A failed DB commit leaves an orphan for GC while preserving the old head. Identical operation IDs with identical content can return the original result; different content conflicts. Never use unconditional last write wins or assume an R2/D1 distributed transaction. Old offline clients cannot silently resurrect deleted data. See [Vault direction](personal-vault.md) and the implemented [owner only attribute slice](vault-claim-sharing.md).

## 6. Conversation archive, MLS, and federation (P2/S1/P3)

Archive only authorized conversations. Preserve source app, conversation/message IDs, sender namespace, time, edit/delete semantics, and provenance. Do not present imported data as cryptographically signed by its sender unless verified. Use separate long term archive keys from live messaging state.

The MLS candidate must pass actual OpenMLS/Wasm checks for Welcome join, send/receive, state export/import, update/removal, and crash recovery before product adoption. Bind device keys and KeyPackages to verified user/DID control and explicit generations; do not trust a self asserted sender. Persist cryptographic state at safe points so crashes, concurrent tabs, and lost send responses do not reuse nonces or fork epochs silently. Limit key packages and track consumption atomically. If the candidate fails, evaluate a maintained alternative rather than inventing a protocol.

Federation uses authenticated HTTPS between independently operated instances. Resolve a constrained DID method and verified delivery endpoint with SSRF protection and key continuity. Recipient servers durably store ciphertext before acknowledging receipt. Bind envelopes to sender, recipient, conversation, message ID, expiry, and authenticated transport; reject duplicates with different payloads, expired/blocked/unpermitted traffic, and quota overflow. Retry and reordering must not display duplicates or corrupt MLS state. See [federated messaging](federated-messaging.md).

## 7. MCP and operating limits

MCP begins with local or owner present list/search/read of selected archive content. Bind grant to recipient, operation, collection, expiry, and audit. The model cannot enlarge its own tool permissions through conversation text. An OIDC ID Token or access token does not unlock Vault keys. A remote unattended decrypting service requires an explicit separate recipient design and disclosure.

Initial design limits include: ceremony TTL 300 seconds and 32 byte challenge with at most five finish failures; WebAuthn body 64 KiB and JSON/CBOR depth eight; at most 10 credentials per account with last active credential protected; Vault ciphertext snapshot 1 MiB and initial 100 MiB per owner; message text 8 KiB UTF-8 and delivery envelope 256 KiB; at most 20 unused KeyPackages per device, initially valid seven days; delivery expiry seven days with duplicate records retained at least another 24 hours. Revisit these against actual protocol/library/deployment constraints. No unconditional sync overwrite or automatic tombstone deletion. [OIDC operations](oidc-operations.md) owns OIDC limits and recovery policy.

## 8. Acceptance and decision gates

- **A1–A3 WebAuthn:** reject tampered/wrong origin/RP/purpose/flags/credential assertions; one concurrent ceremony finish; failure and deletion races; malformed/fuzzed JSON/CBOR/COSE; native/Wasm agreement and unforgeable verified types.
- **O1 OIDC:** code, PKCE, state, nonce, ID Token validation, first consent, SSO, cancellation, Vault independence, and explicit reauthentication.
- **K1/V1/V2 Vault:** PRF vectors, alternate passkey wrap, wrong key/AAD/tamper rejection; device A→B restore; concurrent update and R2/D1 failures; lost responses, deletion/offline sync; distinguish missing from decrypt failure and enforce grant scope.
- **M1–M3 MLS:** real Wasm two party join/exchange/restore/update/remove; crash at package/send/receive boundaries, quota and tab conflicts; reject substituted DID/device/KeyPackage and recover explicitly from commit/epoch conflict.
- **F1/F2 federation:** separate Cloudflare accounts, offline exchange, duplicate/reorder/restart/lost response; no success before durable inbox; reject same ID/different body, expiry, block, SSRF, and quota overflow.
- **P1 MCP:** restrict list/search/read and revocation, including prompt injection from content.

G0 fixes RP/origin, browser/authenticator targets, parser/crypto dependencies, and D1 conditional commit tests. G1 fixes production OIDC issuer, client registration, pairwise mapping, cookies, sessions, policy loader, key/token/client authentication, and management boundaries. G2 fixes Vault key hierarchy, PRF/AEAD format, generations, device transfer, quota, and owner recipients. G3 fixes MLS adoption, DID methods, transport trust, MLS persistence and recovery. G4 fixes MCP authentication, selection UX, unlock lifetime, and audit. G5 fixes shared collection/blob units, system recipient key continuity, Grant/AuthZEN and envelope publication/revocation, recipient rekeying, malware scan design, signed revisions/rollback guarantees, and HPKE suite. A gate blocks only its named product capability; isolated probes can precede it.

Prior work in monban/iwato, doma, tayori, hako, and kakitsu informs WebAuthn testing, client encryption, MLS/DID delivery, Vault/MCP, and small Rust/Wasm wrappers. Do not inherit their incompatible API, server decrypt paths, non durable crypto state, or best effort persistence. Keep code and dependency growth reviewable; see [frontend and CI](frontend-and-ci.md), [architecture](architecture.md), and [roadmap](roadmap.md).
