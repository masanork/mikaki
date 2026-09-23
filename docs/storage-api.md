# File storage API design

This is a proposal, not an adopted or implemented FileNode API. A common S3 compatible blob backend may serve FileNode and Vault storage, while their data models, encryption, synchronization, and authorization remain distinct. See [Vault](personal-vault.md), [claim sharing](vault-claim-sharing.md), and [implementation specification](implementation-spec.md).

## Architecture and model

The Worker determines an authenticated actor and enforces AuthZEN decisions. Storage core handles immutable blobs, FileNode operations, revisions, changes, and quotas. A transactional metadata DB is authoritative for the tree and public blob references; an S3 adapter handles internal object operations. Never trust an actor claimed in a request body or expose bucket/key/credentials through the public API. Vault ciphertext remains opaque and client encrypted; ordinary FileNode content is a named file that the proposed initial server can process.

Use the JMAP File Storage FileNode model as the interoperability reference: immutable node ID, parent ID, file/directory type, optional blob ID, name, size, media type, and timestamps. Derive paths from parent and name; rename/move preserves node ID. A blob ID is a logical content reference, not an S3 key. Start with files/directories, unique sibling names, no cycles, and reject deletion of a nonempty directory. Symlinks, recursive delete, trash, server content search, and deduplication remain later choices. Whether to expose JMAP wire protocol or an adapter requires a gate decision; the recommended direction is a basic FileNode draft v14 subset with declared capabilities.

Proposed methods cover `FileNode/get`, `query`, `changes`, `queryChanges`, `set`, `copy`, and blob GET/PUT. Begin with full replacement PUT, not PATCH or client multipart. Require expected JMAP state for metadata changes and revision/ETag conditions for content. Accept operation IDs: identical request retries return the committed result, while a reused ID with different content is rejected. An opaque state cursor tracks creates, updates, deletes, and visibility loss; an expired cursor requires a full resync of currently visible nodes.

## Authorization

The Worker is the PEP and an AuthZEN 1.0 compatible PDP makes decisions on subject, action, resource, and context. Resource IDs include account/tenant and node IDs. The proposed action vocabulary separates metadata read, child listing, child creation, rename, delete, content read, and content write. A move needs source and old/new parent permissions; a copy needs source read and destination creation. Authorization must cover each result of get/query/changes and avoid existence leaks. A listed directory may disclose direct child metadata under the recommended profile; content still requires separate per file permission. Do not keep a second FileNode ACL or long lived allow cache. Timeout, malformed response, or PDP outage fails closed. Batch evaluation, pagination, and change cursor meaning need performance tests. Vault Grant remains a Vault domain record that the PDP can consult; it is not copied into a FileNode ACL.

## Blob commit and security

1. Validate actor, authorization, size, expected revision, and operation ID.
2. Put a new blob under a random immutable internal key; verify length and digest.
3. Atomically commit metadata head, blob reference, size/type, revision, change record, and idempotency result.
4. Collect the old blob only after it is unreferenced and past a grace period.

A failed DB commit preserves the old head and leaves an orphan for GC. Never assume a transaction spans S3 and DB. S3 compatibility does not guarantee identical conditional writes, versioning, multipart, or consistency across providers; qualify each adapter. R2 is the first Worker candidate. The proposal uses TLS and provider storage encryption for ordinary server readable FileNode content, while Vault keeps client encryption. This does not hide ordinary files from an authorized Worker or provider read path. A future external KMS envelope profile would separate object store credentials from a KEK, but a Worker with KMS unwrap rights could still decrypt during compromise. Do not use PRF derived Vault keys as FileNode server keys or a single Worker Secret as a universal app encryption key.

Downloads must not execute uploaded HTML at the Mikaki origin. Audit actor/action/resource/decision/operation/outcome without content or credentials. Proposed names: 1–255 UTF-8 bytes, normalized NFC, case sensitive among siblings, rejecting slash, controls, dot and dot-dot; detect client filesystem collisions explicitly. Set quotas for logical current blob size and node count, monitor orphan/historical physical storage separately. Direct presigned access, sharing, large multipart, trash, and symlinks need later security and UX decisions.

## Decision gates

Set users/use cases and JMAP wire choice; S3 provider, metadata DB, upload/quota/backup limits; ordinary file encryption and metadata disclosure; PDP deployment and authentication, subject/resource/action profile and Vault Grant integration; partial query visibility and revocation cursors; HTTP binding, ETags, errors, and portable names. The 100 MiB single request figure in the original proposal is a candidate to verify against the chosen Worker plan/provider, not a guaranteed current platform limit. Fix the draft version and capabilities before claiming interoperability.

References: [JMAP FileNode draft 14](https://datatracker.ietf.org/doc/html/draft-ietf-jmap-filenode-14), [RFC 9404](https://datatracker.ietf.org/doc/html/rfc9404), [RFC 9670](https://datatracker.ietf.org/doc/html/rfc9670), [AuthZEN specifications](https://openid.net/wg/authzen/specifications/), [Workers limits](https://developers.cloudflare.com/workers/platform/limits/), and [R2 upload methods](https://developers.cloudflare.com/r2/objects/upload-objects/).
