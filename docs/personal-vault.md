# Personal Vault, conversation archive, and MCP

This records planned direction and decisions still needed before implementation; it does not claim the complete features exist. The [implementation specification](implementation-spec.md) defines the technical contracts, while [Vault claim sharing](vault-claim-sharing.md) identifies the small implemented owner only attribute path.

## Boundaries

Passkey authentication, Vault storage/unlock, conversation import, federated messaging, and MCP delegation have separate responsibilities. A shared Mikaki login can serve tossa and tsudoi without creating or unlocking a Vault. App identities, memberships, and collections remain app specific. Another operator's Mikaki instance is a separate infrastructure and identity boundary. Binding an app to a Vault owner requires authenticated consent, not matching email or an app assertion.

The user should encrypt and restore personal data across devices, selectively archive app conversations, and later delegate narrow AI read access. The server stores ciphertext and wrapped keys, manages grants/versions, and enforces operation permissions. The normal Vault root remains client controlled; a separately authorized system recipient can decrypt only specifically shared attributes, with that disclosure clearly stated. See [claim sharing](vault-claim-sharing.md).

## Keys and synchronization

Use a hierarchy in which a Vault root key protects collection/data keys; WebAuthn PRF can unwrap an owner key on a device. PRF is not required for ordinary OIDC login. Define PRF input, KDF, AEAD suite, versioned AAD, envelope format, key generations, recovery, and test vectors before permanent data. An additional passkey or device needs an explicit rewrap/transfer path; possession of the same AccountId is insufficient. Loss of every usable key may make old ciphertext irrecoverable unless a recovery scheme was previously established.

Keep encrypted object versions immutable in blob storage and metadata/head/revision in D1. Conditional updates and operation IDs prevent silent overwrites and make retries idempotent. A failed D1 commit leaves an unreferenced blob for GC while preserving the old head. A deletion creates a tombstone; an old offline device must not resurrect it. Distinguish missing data from decryption failure, and never regenerate or overwrite a key on decryption failure. D1/R2 do not form one distributed transaction. Revisions alone do not prove protection against a malicious store replaying an old valid ciphertext; define any rollback guarantee explicitly.

Grants bind owner, app/delegate, collection, operation, expiry, and revocation version. Authentication and OIDC tokens do not grant Vault operations or unlock a key. Separate app namespaces and key scopes. Metadata such as size, timestamps, and access patterns remains visible to the service.

## Archive and MCP

Import only consented conversations, retaining source app, conversation/message IDs, sender identifier namespace, time, body, and format version. Deduplicate by source tuple, not display name. Specify edit/delete import, retention after leaving an app, and suppression of unwanted reimport. Label provenance separately from cryptographic author verification. An archive is a personal copy, not the shared chat's source of truth. Live messaging forward secrecy does not erase deliberately archived plaintext.

Start MCP with list/search/read for selected conversations. Search snippets and counts obey the same scope. A local adapter or an unlocked browser bridge is the initial candidate because a remote unattended MCP server cannot derive PRF keys from an OAuth token. A permanently remote AI service would need selected plaintext or data keys and becomes a decrypting recipient, requiring a distinct design and consent. Show both the MCP client and downstream AI service to the user. Revocation stops future reads; it cannot recall already delivered plaintext, summaries, or embeddings. Log delegate, operation, target, time, and outcome, not bodies or keys. Treat imported text as untrusted; enforce tool permissions outside model reasoning.

Before implementation, settle origin/RP ID, app consent, data formats and quotas, device recovery, conflict/delete/retry/backup behavior, archive provenance and retention, and MCP execution, unlock lifetime, scope, expiry, and audit. Initial Vault acceptance requires device A to save encrypted data and a fresh device B to restore it through an authorized unlock, without losing good data under conflict, network failure, or decrypt failure.

References: [R2 Workers API](https://developers.cloudflare.com/r2/api/workers/workers-api-reference/), [IndexedDB](https://developer.mozilla.org/en-US/docs/Web/API/IndexedDB_API), [WebAuthn PRF](https://www.w3.org/TR/webauthn/#prf-extension), [HPKE RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html), [MCP authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization), and [MCP security guidance](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices). Recheck applicable MCP versions when implementing.
