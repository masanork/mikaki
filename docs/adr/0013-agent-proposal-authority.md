# ADR 0013: One agent proposal authority, separate from encrypted Vault commits

**Status:** accepted for the bounded local agent service, 2026-09-28. The first VG-04 encrypted commit has local qualification; production activation and real-device/recovery gates remain open.

## Context and authority map

[ADR 0009](0009-rust-oidc-and-worker-stack.md) keeps security protocol transitions in Rust and prefers Rust product state ownership. The existing separate agent recipient Worker already owns snapshot and private-draft transitions in TypeScript. Moving just a second proposal adapter to Rust would create two agent transition authorities and an additional platform/crypto boundary before the approved encrypted write contract is proven.

| Capability | Authority | Does not authorize |
| --- | --- | --- |
| Owner ciphertext GET/PUT/DELETE and key transfer | Rust OP `vault_attributes.rs`, conditional D1 batch and R2 lifecycle | Plaintext schema validity or agent approval |
| System Grant | Rust owner sharing operations and recipient/Grant ledger | Any RP or agent access merely because a Grant exists |
| RP ClaimRelease | Separate RP-specific release ledger and live connection checks | Agent access or ordinary `openid` release of Vault data |
| Agent snapshot and private draft | Agent `store.ts` with live source/account/credential/recipient checks | Owner ciphertext writes |
| Typed attribute proposal and decision | Agent `attribute-proposals.ts` plus conditional D1 operations/triggers | Current note reads, private-draft execution, encryption or Vault commits |

## Decision

1. Record a narrow exception to ADR 0009 for the isolated agent-recipient domain: `store.ts` and `attribute-proposals.ts` own its validated inputs and durable transitions. HTTP/MCP tool handlers remain authentication/serialization adapters and call those same operations. There is no second Rust or UI implementation of the agent state machine. OIDC, sessions, owner storage, and system/RP authorization remain Rust-owned.
2. Reuse the versioned note validator from VG-02. Record owner, grant and grant revision, destination, target/base revision, exact normalized value, absolute expiry and a payload hash. The service identifies the proposer by grant/delegate/provider; display labels are not authenticated provider/bot identities.
3. Require a separate explicit owner-issued target/revision capability. Old grants and the existing private-draft scope do not silently acquire note rights. The capability is immutable, expires no later than the grant or one hour, and is reissued only on a new grant. Target revisions include tombstones; zero means never stored.
4. Keep attribute proposals in a distinct ledger. Approval records one final decision about the exact hash and base revision. It cannot be used by `mikaki_execute`, which continues to create private drafts only. The original VG-03 slice exposes no attribute execute/commit route; VG-04 adds a separate owner-only Rust commit route.
5. Durable mutations and content-free audit commit atomically. Identical retries return the existing result; changed payload, owner, target, base, grant revision, expiry, or decision do not replace it. Wrong owners, expired/revoked grants and stale targets cannot approve it. Revocation and target edits invalidate pending/approved proposals and clear their plaintext; expiry is enforced on calls and hourly cleanup clears expired plaintext.
6. VG-04 binds this approval to exactly one owner-device-encrypted conditional commit in the Rust owner-storage authority. The service first verifies and freezes the new candidate using its explicitly disclosed one-revision data key. Rust owns the terminal `committed` transition together with the head, retry ledger and result in one guarded D1 batch. The browser does not issue an ordinary PUT and independently mark a proposal complete. See the [commit contract and fault/recovery evidence](../vault-approved-commit.md).

## Consequences and limits

This makes a bounded TypeScript product exception explicit; it does not replace the Rust direction for the rest of Mikaki. A future migration must retire this authority after exercising the same contracts against its replacement, rather than leaving two implementations active. D1 conditional statements/triggers enforce durable concurrency and rollback; language types do not.

Proposal plaintext is disclosed to the agent service, separate from encrypted owner data. The UI states this before capability issuance. Approval means owner adoption of an untrusted suggested value, not issuer verification. Future source/credential provenance profiles need their own schema. Local browser tests use mocked PRF, and synthetic SDK/HTTP clients are not real remote Codex/Grok or OAuth evidence.

See the [proposal contract](../vault-attribute-proposals.md), [fit/gap sequence](../vault-fit-gap.md), and [Cloudflare D1 transaction reference](https://developers.cloudflare.com/d1/worker-api/d1-database/).
