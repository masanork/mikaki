# Candidate Vault owner-key contract

**Status:** new-format crypto, bounded lease and owner-key bootstrap API, locally tested 2026-10-03. The default Vault UI, native client and agent service do not use it yet. This is an implementation step toward U1/U2 in the [Vault product model](vault-product-model.md). The owner confirms there are no existing data assets requiring a legacy migration; new-format functionality is the rollout target.

## Responsibility and keys

An explicit owner-present WebAuthn PRF evaluation opens one encrypted 32-byte owner key. The browser imports it as a nonextractable AES-256-GCM `CryptoKey`. Fresh independently random 32-byte content keys protect each new record encryption; the owner key wraps those content keys. A record wrap binds a collection, so direct root-to-record wrapping suffices for this first bounded slice; separate collection keys can be introduced with a separately versioned contract if needed. No parent key is supplied to an agent or recipient.

The [`vault-owner-crypto.ts`](../crates/worker/ui/vault-owner-crypto.ts) implementation uses Web Crypto HKDF-SHA-256 and AES-256-GCM with 12-byte random nonces and 16-byte authentication tags. WebAuthn's [PRF extension](https://www.w3.org/TR/webauthn-3/#prf-extension) supplies a 32-byte output; the library receives that output from a credential-verifying adapter. The [Web Crypto API](https://www.w3.org/TR/webcrypto/) provides the key/import/derive/encrypt/decrypt primitives. The library does not itself verify WebAuthn assertions, enroll credentials or authorize server writes.

`createOwnerKey`, `openOwnerKey` and `rewrapOwnerKey` consume and zero their supplied PRF output arrays, including on failure. Internal raw owner/content keys and sealing working-plaintext copies are zeroed in `finally`. Retained keys are nonextractable handles, not raw byte arrays. Handle revocation/reference cleanup is not physical memory erasure and does not protect against compromised same-origin code. Opened plaintext is caller-owned and must be removed/cleared when no longer needed.

## Version 2 encoding

All base64url values are unpadded and canonical. Parsers reject unsupported versions, extra/missing envelope fields, non-string binary fields, invalid lengths and oversized inputs before base64 decoding. Owner/collection/record/kind identifiers are opaque ASCII `[A-Za-z0-9_-]`, 1–128 characters. Generations and revisions are positive safe integers. The origin is an exact canonical HTTPS origin with no path/credentials/query. An expected context is supplied by the owner-bound caller, not trusted from an attacker-controlled record.

| Owner key envelope field | Meaning |
| --- | --- |
| `format_version` | Integer `2`; distinct from the unchanged version-1 attribute envelope. |
| `kind` | Literal `owner-key`. |
| `credential_id` | Canonical base64url of the selected credential ID, 1–512 bytes. |
| `prf_input` | Random 32-byte input, stable for this credential's wrapping of this owner-key generation. |
| `salt` | Random 32-byte HKDF salt for this wrap. |
| `nonce` | Random 12-byte AES-GCM wrapping nonce. |
| `wrapped_key` | Encrypted 32-byte owner key with 16-byte tag, exactly 48 bytes. |

For KDF info and AAD, encode each string as UTF-8 with an unsigned big-endian 16-bit byte-length prefix, concatenated without separators. Owner context fields are, in order, version string `2`, origin, owner ID, Vault ID and decimal key generation. Owner wrapping additionally binds the canonical credential ID and PRF input strings.

- HKDF info: `mikaki-vault-owner-kek`, owner context, credential ID, PRF input.
- Owner wrap AAD: `mikaki-vault-owner-wrap`, owner context, credential ID, PRF input.
- Record content AAD: `mikaki-vault-record-content`, version string `2`, origin, owner ID, Vault ID, collection ID, record ID, kind, decimal revision. Parent-key generation is deliberately excluded from this stable content identity.
- Record content-key wrap AAD: `mikaki-vault-record-key`, the full owner context (including decimal parent generation), collection ID, record ID, kind and decimal content revision.

The record has exactly `format_version: 2`, `ciphertext` and `key_envelope`. Each binary field begins with byte `0x02`, followed by its own 12-byte nonce and AES-GCM ciphertext/tag. The content-key envelope is exactly 61 bytes; the body is at least 29 bytes, including an empty plaintext/tag, and at most 24 KiB. This deliberately retains a bounded small-record limit; it does not provide the general thread, attachment or SQLite-snapshot blob transport. Each seal receives a fresh content key and independent nonces, including when sealing identical content at an identical revision. Expected-revision uniqueness and exact-retry storage rules remain the server's responsibility.

Context and sealing input are snapshotted before asynchronous encryption. Wrong owner/origin/Vault/generation/collection/record/kind/revision, mismatched content-key envelopes and ciphertext/wrap tampering fail authentication. Generation remains bound in the content-key envelope. Domain separation is encoded explicitly; root wraps and record bodies cannot substitute for each other.

`rewrapOwnerRecord` verifies the original body before wrapping its existing content key under a different parent handle at the immediately next generation. Owner/origin/Vault/item identity must stay unchanged; ciphertext and content revision remain identical. `sealOwnerRecord` with a fresh content key/new revision is the separate operation for renewing content keys. A different content-encryption suite requires a new supported format and resealing, not changing a label. Parent rewrapping cannot revoke old copied keys/wrappers/plaintext. This v2 adjustment happens before adoption; there are no deployed v2 data assets to migrate.

## Owner lease candidate

[`OwnerKeySession`](../crates/worker/ui/vault-owner-session.ts) requires an already observed owner identity in the existing [`VaultScope`](../crates/worker/ui/vault-lifecycle.ts). It binds the exact owner account, authenticated credential and session tag, and requires the selected root envelope to match that session credential. Opening calls a supplied PRF evaluator once; repeated opens and ordinary record reads/seals use the existing in-memory handle. The evaluator must verify the returned credential and current owner-present ceremony; the lease also rejects a mismatched credential result.

This candidate inherits the existing 15-minute idle/one-hour absolute deadline, wall-clock rollback detection and scope aborts. Manual lock, pagehide, logout/external lock, expiry, session replacement and disposal drop the root reference. A generation token rejects late PRF, decryption and sealing completions. Concurrent unlocks are rejected. A rejected late decryption clears its working plaintext rather than releasing it to a caller.

Suspension masks availability and invalidates pending operation generations, while retaining an already opened handle within the existing scope lease. Resume verifies the server session before making that same handle available, without another PRF ceremony. The visibility guard also refuses operations while the document is hidden. The candidate does not attach its own page event listeners or render/mask values: the eventual Vault controller must call suspend/resume/dispose and clear UI/Worker state at the established lifecycle boundaries. It must ensure authority again before a remote write or disclosure; a sealed result is not authorization to commit it.

No PRF output, owner handle, raw parent key or plaintext is persisted to local/session storage, IndexedDB, URLs, Service Worker caches or an API by these modules. The bootstrap API below stores only encrypted wrappers and routing/version metadata. Offline custody remains separate. The owner lease currently uses `VaultScope`'s start/deadlines; it does not extend an existing display lease simply because a key was opened later.

## New Vault bootstrap API

`GET /vault/owner-key` reads the authenticated owner's head and only the wrapper for that session's active credential. No root returns `404 owner_key_missing`; an existing root without that credential's wrapper returns `409 credential_not_wrapped`, which must not trigger a new root. Other owners see their own namespace. OAuth/agent tokens alone cannot read this endpoint; it uses the existing validated owner SSO cookie. All responses use `no-store`; successful responses carry a revision ETag and owner/origin/Vault/generation/suite plus the encrypted envelope.

`PUT /vault/owner-key` creates generation/revision 1 only. Require same-origin, active owner/credential, JSON content type, `If-None-Match: *` and an `X-Operation-ID`. Its strict bounded payload has `format_version: 2`, `suite: PRF-HKDF-SHA256-AES256GCM-v2`, `vault_id`, `key_generation: 1` and `owner_envelope`. Reject unknown suites/versions, extra fields, invalid canonical encodings and a wrapper naming a different credential. The origin/owner are server-derived. The service validates structure, not decryptability; it receives no PRF output or raw parent key.

The head and credential wrap commit in one D1 batch, with live SSO/account epoch/credential rechecked in the insert predicate. A conflicting initial create cannot overwrite the head. The stored operation ID and exact-body request hash make identical retries return the same head; changed bytes under that operation ID are rejected. Failed wrapper insertion rolls back the head. Heads and credential wrappers are separate tables, with explicit format/suite, key generation and registry revision; those dimensions must not be conflated with content revision.

[`openOwnerVault`](../crates/worker/ui/vault-owner-store.ts) reads an existing supported head or initializes a new random Vault ID through one PRF evaluator call. `OwnerKeySession.initialize` installs the newly created nonextractable handle. The store returns it only after confirming the exact encrypted head/context; a lost successful response is reconciled by GET without generating another root or another PRF evaluation. An unconfirmed/conflicting creation disposes the candidate lease. No old attributes are imported. This helper is not yet invoked by the default production panels.

There is no root overwrite/delete/reset or generation-activation endpoint in this slice. A future rotation controller needs staging, per-record wrapper CAS and completeness verification before activating the new head, retaining old-generation custody while needed and disposing obsolete leases. The crypto rewrap primitive does not by itself implement that distributed transition. No unsupported suite is silently downgraded.

The future controller must also invalidate this fixed-context lease when it observes a root generation/registry authority change. A local handle cannot discover an unobserved remote revocation; no push notification or registry polling contract is implemented here.

## Additional credentials, loss and legacy data

`rewrapOwnerKey` requires fresh source and target PRF outputs and a different target credential. It decrypts the source wrapper into temporary bytes and encrypts the same owner key for the target, without rewriting record ciphertext. The target wrap must be opened and checked against retained records before the eventual registry commit. Both credentials must be registered to the owner under the future server contract; the crypto helper cannot establish that fact. Adding a wrapper leaves the original wrapper usable until the registry changes it.

Credential removal does not recall a previously copied owner key or plaintext. Rotating the parent key requires a new generation and verified record-key rewrapping; content can remain unchanged. Changing the generation header alone makes record envelopes unreadable. Loss of all valid owner-key wrappers makes those encrypted records inaccessible. Account/SSO recovery does not recover the owner key, and no unqualified fallback is supplied here.

Existing version-1 functions/tests remain intact, but a legacy importer is not a launch dependency because there are no existing data assets. New Vaults start in the new format. No old record is silently relabeled/rewritten and no legacy PRF input changes. If an import becomes useful later, it needs its own explicit source/revision/verification contract. Rotation/format agility is supported by separate parent wrappers, stable content identity, explicit generations/suites and fail-closed parsing, rather than a speculative legacy migration framework.

## Evidence and remaining adoption work

[`vault-owner-key.test.ts`](../local/conformance/vault-owner-key.test.ts) checks independent Node HKDF/AES-GCM deterministic fixtures, nonextractability/PRF cleanup, all bound identity fields, malformed encodings and size limits, fresh encryptions, additional-credential wrapping, one evaluator call for ten records, cancel/absent PRF, pending/late completions, suspend/resume, idle/absolute/session/pagehide and unchanged legacy readability.

[`vault-owner-key-browser.test.ts`](../local/conformance/vault-owner-key-browser.test.ts) exercises the actual bundled modules with browser WebCrypto and synthetic PRF results. Chromium, Firefox and Playwright WebKit pass locally; CI runs Chromium through `npm run test:vault-transfer`. Empty localStorage/sessionStorage/IndexedDB/CacheStorage are checked. This test does not issue actual WebAuthn ceremonies or qualify intended-device PRF/recovery behavior.

[`vault-owner-key-store.test.ts`](../local/conformance/vault-owner-key-store.test.ts) exercises the actual API in workerd: owner/credential scope, malformed and oversized input, origin/preconditions, immutable concurrent bootstrap, exact retry/conflict, injected second-statement rollback, root retrieval and record decryption with the recovered key. The client helper recovers a simulated lost successful response with one synthetic PRF evaluation, then opens the same Vault in a fresh lease. The crypto tests also verify unchanged ciphertext after parent rotation and resealing for content-key renewal.

Before default UI activation: implement version-2 record storage/authorization/CAS; connect the existing controller and panels to one lease; preserve exact selected disclosure/proposal/transfer authority; test actual Passkeys, repeated save/reopen/conflicts/retries and hidden/expired/replaced sessions. Additional wrapper registration, loss/recovery and staged rotation activation remain separate explicit custody work. Then build the first bounded authoritative thread archive and connect the qualified SQLite projection. The new API/helper does not yet change today's default panel prompts.
