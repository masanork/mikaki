# Selected v2 record disclosure adapters

**Status:** draft foundation, 2026-10-03. This module prepares explicitly selected copies from an already open owner-Vault lease. It does not mount new preview controls, create a remote grant, enable a UserInfo release, approve a proposal or change production policy. Default format-1 storage and envelope bytes remain unchanged. Service adapters, consent UI and independent integration review remain gates.

## Source identity and scope

[`vault-record-source.ts`](../crates/worker/ui/vault-record-source.ts) requires an explicit storage discriminator. A format-1 attribute and a same-named format-2 record are different sources. The v2 immutable source includes origin, owner, Vault, collection, record ID, kind, positive content revision and SHA-256 of the actual stored ciphertext bytes. The parent key generation and current owner-key registry revision are a separate authority object. Neither is substituted for content revision or added to the existing record content AAD.

This slice accepts only `personal/name` with kind `name`, or `personal/owner_note` with kind `owner_note`. Names use validated UTF-8 with the existing 256-character bound. Notes retain the exact canonical typed-note document and its self-asserted provenance. Archive kinds and other collections are rejected. No free-text label establishes source identity or issuer verification.

[`OwnerRecordDisclosure`](../crates/worker/ui/vault-owner-disclosure.ts) reads only the selected saved records through `OwnerRecordStore` and `OwnerKeySession.open`. A local export can select one or both supported records; a remote snapshot contains exactly one. Preparation reuses the current lease, clears temporary plaintext byte arrays, rejects unknown/malformed/deleted sources, and verifies the exact selected heads and current owner authority after asynchronous work. Lock, suspension, replaced sessions and stale controller generations reject late results. It neither exposes a root/content key nor retains its own plaintext cache.

A final source check is a point-in-time observation, not a subscription or a transaction spanning both records. An already returned plaintext export is an independent copy: subsequent revocation, record deletion or locking cannot erase it. JavaScript strings and recipient-retained copies have no guaranteed physical erasure.

## Local exports

New exports and local grants use explicit version 2 and collection `vault-records`; format-1 exports remain supported unchanged. Each document has `source_info.kind = vault-record`, the complete source and authority tuple, self-asserted provenance, and its reported preparation-check time. The whole export digest is bound into the local grant. The grant separately names its exact selected document IDs and source tuples. Owner/target/version/authority substitution is rejected before disclosure.

The stdio adapter continues to check bounded files, delegate, expiry (at most 24 hours), selected operations, current grant file and audit success. It rechecks the unchanged grant after audit I/O. Its result explicitly says `source_check = not-checked`: it never contacts the live Vault. Deleting or editing a server record cannot revoke an exported file or an already copied plaintext value.

## Independent encrypted snapshots

[`agent-record-crypto.ts`](../crates/worker/ui/agent-record-crypto.ts) uses an explicit version-2 envelope and `mikaki-agent-record-snapshot` domain. The RSA-OAEP-SHA-256 label and AES-256-GCM AAD authenticate the exact owner, grant, recipient key, resource, expiry, complete source tuple and separate live authority fences. It generates an independent random transport key. Owner/root and record content keys are never inputs or outputs of this adapter.

The existing format-1 `mikaki-agent-snapshot` and approved-attribute-proof encodings are unchanged. A v1 envelope cannot be substituted as v2, including when the attribute/record names and revisions happen to match. No fallback or trial decryption is used. The receiver still needs its own authoritative source/grant checks; authenticating a browser-supplied snapshot does not prove an issuer supplied its plaintext.

## Evidence and remaining gates

The [Node and actual stdio suite](../local/conformance/vault-owner-disclosure.test.ts) covers exact source parsing, v1/v2 isolation, selected-only name/note exports, one ceremony reused across preparations, independent cryptographic opening, source/authority/purpose substitutions, malformed schema and UTF-8, deletion and changed-head races, replaced root/session, suspension, late decrypted-byte clearing, audit failure, expiry and live local-grant revocation. It is wired into `test:vault-transfer`, and can run alone with `npm run test:vault-disclosure`.

This first chunk does not qualify remote HTTP grants, per-record UserInfo sharing, approved v2 owner-note commits, or user-facing v2 consent controls. Those require their respective atomicity, source-live, revocation-during-decrypt/audit and browser gates before they are enabled. Default v1 activation and physical-device PRF/recovery gates are unchanged.
