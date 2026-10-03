# Personal Vault, credentials, conversation archive, and agent access

This records planned direction and decisions still needed before implementation; it does not claim the complete features exist. The [implementation specification](implementation-spec.md) defines the technical contracts, while [Vault claim sharing](vault-claim-sharing.md) identifies the small implemented owner only attribute path.

The [protocol review](vault-protocol-review.md) and [ADR 0012](adr/0012-vault-protocol-boundaries.md) separate owner ciphertext storage, profile release, credential presentation, file synchronization, and AI adapters. Remote MCP is one access adapter; it is not the canonical Vault protocol.

The [2026-10-03 usage-model proposal](vault-product-model.md) prioritizes encrypted human/human and human/AI threads, followed by linked application/approval history. It separates thread/message/workflow semantics, attributes, records, attachments and underlying blobs, and specifies a unified owner-key unlock target. Its interactive preview is fictional; the current per-attribute encryption and individual unlock contracts have not changed.

## Boundaries

Passkey authentication, Vault storage/unlock, conversation import, federated messaging, and MCP delegation have separate responsibilities. A shared Mikaki login can serve tossa and tsudoi without creating or unlocking a Vault. App identities, memberships, and collections remain app specific. Another operator's Mikaki instance is a separate infrastructure and identity boundary. Binding an app to a Vault owner requires authenticated consent, not matching email or an app assertion.

The user should encrypt and restore personal data across devices, selectively archive app conversations, and later delegate narrow AI read access. The server stores ciphertext and wrapped keys, manages grants/versions, and enforces operation permissions. The normal Vault root remains client controlled; a separately authorized system recipient can decrypt only specifically shared attributes, with that disclosure clearly stated. See [claim sharing](vault-claim-sharing.md).

## Keys and synchronization

A local first continuity slice now supports same-account passkey addition and saved-name transfer to a different PRF credential at a new encrypted revision. The single owner envelope is replaced; real-device and backup-recovery gates remain. See [passkey transfer](vault-passkey-transfer.md).

A first typed attribute, `owner_note`, now has a bounded versioned plaintext schema and explicit self-asserted provenance. The owner editor encrypts updates and supports consented plaintext JSON import/export. It leaves raw UTF-8 `name` and agent grant scope unchanged. See [typed attributes and local evidence](vault-typed-attributes.md).

Use a hierarchy in which a Vault root key protects collection/data keys; WebAuthn PRF can unwrap an owner key on a device. PRF is not required for ordinary OIDC login. Define PRF input, KDF, AEAD suite, versioned AAD, envelope format, key generations, recovery, and test vectors before permanent data. An additional passkey or device needs an explicit rewrap/transfer path; possession of the same AccountId is insufficient. Loss of every usable key may make old ciphertext irrecoverable unless a recovery scheme was previously established.

Keep encrypted object versions immutable in blob storage and metadata/head/revision in D1. Conditional updates and operation IDs prevent silent overwrites and make retries idempotent. A failed D1 commit leaves an unreferenced blob for GC while preserving the old head. A deletion creates a tombstone; an old offline device must not resurrect it. Distinguish missing data from decryption failure, and never regenerate or overwrite a key on decryption failure. D1/R2 do not form one distributed transaction. Revisions alone do not prove protection against a malicious store replaying an old valid ciphertext; define any rollback guarantee explicitly.

Grants bind owner, app/delegate, collection, operation, expiry, and revocation version. Authentication and OIDC tokens do not grant Vault operations or unlock a key. Separate app namespaces and key scopes. Metadata such as size, timestamps, and access patterns remains visible to the service.

## Archive and MCP

A local stdio adapter exercises bounded list/search/read against owner-prepared plaintext exports. The Vault UI can now explicitly unlock/export its saved name or encrypt a separate snapshot for a dedicated agent Worker. Local browser/workerd tests cover remote bearer access, grants, audit, revocation, recipient stop, and approved private drafts. Original Vault keys remain owner-controlled; production activation, OAuth onboarding, and conversation import remain gates. See [agent integration](agent-integration.md) for the implemented contract.

Import only consented conversations, retaining source app, conversation/message IDs, sender identifier namespace, time, body, and format version. Deduplicate by source tuple, not display name. Specify edit/delete import, retention after leaving an app, and suppression of unwanted reimport. Label provenance separately from cryptographic author verification. An archive is a personal copy, not the shared chat's source of truth. Live messaging forward secrecy does not erase deliberately archived plaintext.

Start MCP with list/search/read for selected conversations. Search snippets and counts obey the same scope. A local adapter or an unlocked browser bridge is the initial candidate because a remote unattended MCP server cannot derive PRF keys from an OAuth token. A permanently remote AI service would need selected plaintext or data keys and becomes a decrypting recipient, requiring a distinct design and consent. Show both the MCP client and downstream AI service to the user. Revocation stops future reads; it cannot recall already delivered plaintext, summaries, or embeddings. Log delegate, operation, target, time, and outcome, not bodies or keys. Treat imported text as untrusted; enforce tool permissions outside model reasoning.

Before implementation, settle origin/RP ID, app consent, data formats and quotas, device recovery, conflict/delete/retry/backup behavior, archive provenance and retention, and MCP execution, unlock lifetime, scope, expiry, and audit. Initial Vault acceptance requires device A to save encrypted data and a fresh device B to restore it through an authorized unlock, without losing good data under conflict, network failure, or decrypt failure.

## Attributes, credentials, and writes

Keep editable self-entered attributes separate from issuer-signed credentials. Preserve credential proofs and holder-key references when importing a credential; local annotations must not alter the signed payload. OIDC UserInfo remains the candidate for ordinary connected-RP profile release. OpenID4VP/VCI are wallet presentation/issuance candidates with separate issuer/verifier trust and device-key gates, not replacements for the owner storage API. File trees have their own [FileNode investigation](storage-api.md).

A locally implemented owner-note change now binds the agent proposal to the exact value, schema, destination, base revision and expiry. After review, the owner device encrypts a fresh revision; the proposal service verifies those approved bytes using an explicitly disclosed new-revision key, and Rust atomically consumes approval and commits owner storage. Exact retries and fresh-page recovery are qualified locally. See the [approved commit contract and remaining gates](vault-approved-commit.md). Current private drafts remain outside the encrypted Vault. Unattended writes, encrypted synchronization extensions and imported credentials need their own acceptance evidence; a read grant or credential presentation cannot authorize them.

References: [R2 Workers API](https://developers.cloudflare.com/r2/api/workers/workers-api-reference/), [IndexedDB](https://developer.mozilla.org/en-US/docs/Web/API/IndexedDB_API), [WebAuthn PRF](https://www.w3.org/TR/webauthn/#prf-extension), [HPKE RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html), [MCP authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization), and [MCP security guidance](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices). Recheck applicable MCP versions when implementing.
