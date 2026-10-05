# Historical format-1 approved proposal to encrypted owner commit

**Retired:** this page describes the former owner-note attribute proposal/approval UI and its v1 attribute commit path. Those proposal/capability routes and AgentPanel controls are removed from the fresh baseline. Current OwnerWorkspace supports direct record-v2 writes; that is not the removed Agent proposal approval UI. Generic Agent private drafts and v2 OAuth grants are separate, and owner-side proposal/release UI remains follow-up work.

**Historical status, 2026-09-28:** the first VG-04 slice connects the typed owner-note proposal to one verified encrypted commit. Migration `0017`, the owner UI and service extension are local implementations, not a deployment. Real-device PRF and collection recovery remain [VG-01 gates](vault-passkey-transfer.md).

## Responsibility and exact-value verification

The owner approves the exact normalized note, target and base revision under the [proposal contract](vault-attribute-proposals.md). Approval remains separate from saving. The dashboard's save action reads the current note, requires the same revision, opens its envelope using owner-present PRF and validates the saved schema. Unknown/malformed saved data is protected by the client; the generic encrypted storage API cannot validate it. Never-stored and tombstoned notes use the current owner credential with explicit revision checks.

The client encrypts the approved canonical bytes with a fresh data key at `base_revision + 1` and a fresh format-1 owner envelope. It then reopens that candidate locally and compares the exact bytes. Unsaved edits in the ordinary note editor are not included. This also verifies owner readability; the service cannot prove the PRF envelope's contents without an owner secret.

A hash of the approval alone would not prove what an opaque ciphertext contains. The client therefore encrypts **only the newly generated revision's data key** to the existing proposal-service recipient. This is an explicit decrypting-recipient disclosure, stated in the UI. It does not disclose the existing note, its data key, PRF output or owner wrapping key. The service already holds the proposed plaintext and verifies that the candidate decrypts to exactly those approved canonical bytes.

The proof reuses the existing RSA-OAEP-SHA-256/AES-256-GCM service envelope with the distinct authenticated label `mikaki-approved-attribute-proof`. Its binding fixes owner, grant, recipient, resource, proposal expiry and candidate revision (`base + 1`). Its encrypted payload contains proposal ID, approval hash, SHA-256 of the exact candidate JSON string, and the candidate data key. A snapshot-purpose envelope cannot serve as this proof. The service decrypts the candidate using the owner-origin/attribute/revision AES-GCM context and checks its schema and bytes. This is a trusted-recipient verification profile, not zero-knowledge proof, a credential presentation, or a new standard claim.

The owner OP sets the trusted origin header on its private service binding; a public client cannot select that service header. Preparation authenticates the live owner, grant, capability, recipient and unchanged target. It records an immutable operation ID, exact encrypted candidate string/digest and origin in `agent_attribute_commit`. Key/proof material is not stored in that table. A different value, owner envelope, operation ID or serialized candidate under the same proposal is rejected. Identical preparation retries preserve the candidate and create one audit event.

The candidate must equal the JSON encoding of the strict format-1 object in `format_version`, `ciphertext`, `owner_envelope` order. Extra whitespace, duplicate fields, alternate ordering/escapes and unknown fields are rejected before preparation. This narrow encoding profile keeps TypeScript verification and Rust storage parsing aligned; it is not general RFC 8785 canonicalization.

## Atomic owner storage transition

`POST /vault/agents/attribute-prepare` is owner-only; its body contains `proposal_id`, `request_hash`, `operation_id`, exact `candidate` JSON string and encrypted `proof`. It does not write the owner Vault. No preparation/commit tool is exposed to MCP or public agent fetch.

`POST /vault/attributes/owner_note/approved` uses the existing format-1 ciphertext/envelope body, conditional headers, operation ID and two additional headers: `X-Attribute-Proposal` and `X-Proposal-Hash`. The Rust storage authority checks the exact prepared body digest/origin and a same-account active owner-envelope credential. It then performs one D1 batch:

1. Recheck the live owner/session/account/credential, source grant/recipient/capability, absolute database-clock deadlines, approved hash and unchanged base; consume the proposal as terminal `committed` and clear its plaintext. The transition's audit is part of this transaction.
2. Write the conditional owner head after the new ciphertext has uploaded to R2, and insert the existing mutation/retry ledger.
3. Bind the prepared operation to the resulting revision. A final CHECK guard requires the matching mutation, committed proposal and result; failure rolls **every D1 change** back together.

The terminal state is not externally visible between batch statements. Target-update invalidation skips this committed proposal and invalidates other pending/approved proposals for the old revision. Current grant-source/account/credential/recipient invalidation cannot revive it. Ordinary PUT and private-draft execution do not consume a proposal or satisfy this route's operation identity. The mutation digest uses a distinct approved-operation method containing the proposal ID and approval hash, preventing cross-route/header replay.

R2 upload failure happens before consumption and leaves the approved proposal usable for the exact retry. A later D1/audit/result failure may leave an unreferenced new blob, but preserves the old head and approval; the existing bounded R2 garbage collector handles such blobs. This does not make R2/D1 one distributed transaction. Revision conflict, expired/revoked capability, wrong owner/target/credential, changed approved bytes and changed operation are rejected without a partial owner write.

## Lost responses and page recovery

The browser retains the exact ciphertext, operation ID and preparation request until its response is acknowledged. It retries the same preparation after a lost preparation response, and the same Rust commit after a lost commit response. It never regenerates a candidate under an already prepared proposal.

After a page reload before commit, the authenticated owner status contains the immutable prepared ciphertext and operation ID. The client rechecks/opens the saved note and verifies the prepared candidate with PRF against the still-approved payload before committing. After a committed result, the dashboard shows its revision; the ordinary note can be reloaded and opened independently. Reloading/forgetting local retry state does not undo a committed operation.

An identical committed retry is a **historical acknowledgment**, even if a newer owner edit, expired grant or retired recipient exists. It requires a live session for the same owner and the same operation/body/approval identity, returns the original revision, and cannot reapply it. The mutation ledger's existing 90-day cleanup bounds this acknowledgment. Proposal/result metadata and prepared encrypted candidate follow the agent service's 30-day retention; the historical mutation acknowledgment remains independent after that metadata is removed. Physical cleanup depends on successful jobs.

Successful commit clears service-held proposal plaintext. Rejection, invalidation and hourly expiry cleanup retain their prior behavior. Temporary byte arrays are cleared where practical; JavaScript strings, recipient memory, backups, downloads or deliberately retained copies have no guaranteed erasure. There is no claim that disclosing a key can later recall an already delivered value. Recipient rotation must disable the old recipient record/revoke grants, as in the existing agent key contract.

The grant still shares `name` only. Note proposal capabilities become stale when the note revision changes; no note read grant or updated snapshot is created automatically. Owner adoption retains the note's self-asserted assurance. Proposer labels and the commit audit are separate from issuer proof.

## Local verification and remaining gates

On 2026-09-28, all 17 combined commit/proposal/agent/note/crypto/transfer/storage/share/release integration and regression tests passed. The release Worker/UI build, strict Node/agent/UI type checks, Rust Clippy with warnings denied, formatting, bilingual messages, product-source checks and local documentation links also passed. The final candidate-encoding refinement additionally reran the two commit-suite tests, including correctly encrypted proofs over noncanonical candidates.

`npm run test:attribute-commit` checks a populated `0016` to `0017` migration, paired real workerd Workers/D1/R2, independently generated Node crypto candidates and Chromium owner save/recovery. Negative cases cover wrong approved value/purpose/body/operation/owner/target, absent approval, prepare/commit audit failures, actual injected R2.put rejection, failure after head/ledger updates, concurrent identical commits, stale target, expiry fixture, credential-stop irreversibility, foreign owner-envelope credential and recipient retirement. Browser cases cover missing PRF, exact lost-response retries, a fresh-page reopen, prepared-candidate recovery and protection of an unknown saved schema. Tombstones require a newly consented positive revision and can be explicitly recreated.

Browser PRF is mocked. Intended-device behavior, real remote Codex/Grok OAuth flows, service provisioning/rotation/recovery, production migrations, deployment and operational release gates remain unqualified. This delivery implements one typed note write path, not general Vault recovery, arbitrary attribute writes, credentials or file synchronization.
