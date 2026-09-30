# ADR 0012: Separate Vault storage, credential presentation, files, and AI adapters

**Status:** Accepted responsibility boundary, 2026-09-28. Specific new protocol profiles remain proposals with adoption gates.

## Context

The local agent slice exposes selected decrypted snapshots through remote MCP and allows human-approved private drafts. That is useful AI-client evidence, but it is not evidence that MCP should own Vault storage, synchronization, profile schemas, or credential proofs. The earlier FileNode proposal also requires an explicit choice between its fine-grained rights and JMAP's published draft semantics.

## Decision

1. Keep owner ciphertext storage, revisions, retries, encryption, and recovery independent of AI transport. The existing owner HTTP attribute API remains the implementation baseline.
2. Keep MCP as an optional local/remote adapter to bounded domain operations. Remote snapshots are separately disclosed recipient copies; current draft execution is outside the owner Vault. New adapters must reuse the same authoritative domain transitions for the same capability.
3. Use OIDC UserInfo as the current candidate for ordinary connected-RP profile release. Evaluate OpenID4VP for issuer-backed credential presentation and OpenID4VCI for credential receipt; neither is generic Vault read/write. Do not promote self-entered attributes to verified identity evidence.
4. Continue the JMAP/FileNode comparison for file objects. Pin a version and reconcile inheritance, discovery, changes, and blob authorization before advertising its standard capability. Document vendor extensions or an independent API when semantics differ.
5. Keep OAuth delegation, live grants/consent, PDP evaluation, and cryptographic recipient authority distinct. A token or presentation alone never unlocks an owner PRF key.

## Consequences and gates

The current implementation is retained. No new standard-conformance or deployment claim follows from this ADR. Device recovery precedes general Vault writes; independent wallet/verifier and file-client probes precede their protocol adoption. A future Vault write proposal must be approved and encrypted through the owner storage path, rather than implemented as another MCP-only state machine.

The dated [protocol review](../vault-protocol-review.md) contains the primary specifications, alternatives, write/delegation contracts, and sequenced acceptance cases. It is the current decision map; older topic documents retain their detailed contracts and implementation evidence.
