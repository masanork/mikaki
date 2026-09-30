# Typed attribute proposal and decision contract

**Status, 2026-09-28:** the VG-03 slice implements one authority for `owner_note` proposals and owner decisions through HTTP, MCP and the owner dashboard. Migration `0016` and these features have not been deployed. Approval itself does not change owner ciphertext. The first [VG-04 encrypted commit](vault-approved-commit.md) now connects a separate owner save action to that approval. [ADR 0013](adr/0013-agent-proposal-authority.md) records the state-owner decision and authority map.

## Explicit capability

The owner first shares a saved-name snapshot with a grant that includes `propose`. This existing scope alone still authorizes private drafts only. A separate checkbox/action on the selected connection issues a capability for the displayed `owner_note` base revision. This operation discloses no current note value. It permits an agent to send proposed note plaintext to this service for review.

`POST /vault/agents/attribute-capability` takes `grant_id`, `attribute_id: "owner_note"` and a safe nonnegative integer `base_revision`. It uses the live owner session, same-origin guard, active account/credential/recipient, exact grant revision, and current note revision. It is immutable for that grant and expires at the earlier of grant expiry or issuance plus one hour. Identical issuance retries preserve the original deadline and create no extra audit event. A new base or renewed capability needs a new connection/grant and consent. Revision zero means never stored; a deleted head retains its positive revision.

## Proposal

Both `mikaki_propose_attribute` on the remote MCP service and `POST /attribute-proposals` on that same agent origin accept:

```json
{
  "proposal_id": "<43-character base64url operation ID>",
  "attribute_id": "owner_note",
  "base_revision": 0,
  "value": {
    "type": "mikaki.owner-note",
    "version": 1,
    "title": "Suggested title",
    "text": "Suggested text",
    "provenance": {"kind": "self-asserted"}
  },
  "expires_at": 1790000000
}
```

The example deadline is illustrative; callers must supply a future UNIX-seconds value no later than capability expiry or one hour from proposal creation. Input fields are strict. Note type/version, provenance, Unicode and byte limits use the [same owner-note validator](vault-typed-attributes.md). The service normalizes the value to that deterministic encoding before computing its hash; HTTP JSON property order is not a signed canonical request format. HTTP/MCP requests are bounded to 32 KiB. The ordinary owner bridge retains its existing 48 KiB limit.

The request hash binds format version 1, live owner/grant/grant revision, fixed destination `owner-vault`, attribute ID, base revision, canonical note payload and absolute expiry. Each operation ID is immutable. The proposer is the grant's delegate/provider disclosure label, not an independently authenticated AI identity. Returned receipts include proposal ID, hash, state, target/base, deadline, destination and `untrusted_content: true`; they exclude the current note value. The HTTP adapter uses the same text-content result envelope as the MCP call, with JSON receipt inside `content[0].text`.

The bearer is the existing resource-bound agent credential. A browser Origin, when supplied, must match the agent origin; owner bridge routes cannot be called on public agent fetch. This extension is not an OAuth onboarding implementation. No current note read permission is granted and the name snapshot remains unchanged. Unsupported targets, unknown note versions, misleading verified provenance, stale base revisions and absent/expired capabilities fail.

At most 20 pending/approved attribute proposals exist per grant. A concurrent identical request yields the same receipt and one proposal/audit row. Changing the value/deadline/base under the same ID fails. Retrying a rejected proposal reports its rejected state; it does not restore plaintext or revive it. Expired/revoked/stale requests cannot be used for replay.

## Review and decision

The owner dashboard shows the proposer labels, owner-note destination and base revision, deadline, exact title and text, and the untrusted/self-asserted assurance. It keeps these rows separate from private drafts. `POST /vault/agents/attribute-decide` accepts proposal ID, request hash and Boolean `approve`.

Only a live session for the proposal's owner may decide it. Approval requires the exact stored hash, live grant revision/capability and unchanged base; rejection clears the plaintext. Decisions are final: an identical retry is acknowledged without another event, while the opposite decision fails. Revoking the connection is available to invalidate an already approved proposal. Audit failure rolls the decision back.

Grant invalidation caused by revocation, name-source update, account/credential stop or recipient disable cascades to these proposals. A note creation/update/delete invalidates pending/approved proposals tied to an older base and clears plaintext. Invalid/rejected records cannot become pending or approved again. Expiry denies future use immediately; hourly scheduled cleanup clears expired pending/approved plaintext. Physical erasure therefore depends on a successful cleanup run, and service/D1 backups or already received copies are outside recall guarantees. Proposal metadata is retained for 30 days, then removed by cleanup; existing audit retention is also 30 days.

## VG-04 commit boundary

The first [approved encrypted commit](vault-approved-commit.md) now adds a separate owner-only prepare/save path. The owner device verifies readability and encrypts a fresh candidate; the proposal service receives only its newly generated one-revision key under a distinct envelope purpose and verifies the exact approved bytes. The Rust owner-storage authority consumes the approval, writes the head, records the result and audits atomically. Failed D1 transitions roll back; historical retries cannot reapply a change.

`mikaki_execute` remains private-draft-only and cannot accept this ledger. The ordinary owner editor's PUT is also independent. The new terminal state is `committed`; its plaintext is cleared and its result revision is shown to the owner. Committed receipts remain visible in owner status within metadata retention even after expiry. The proposal suite below still qualifies approval separately; the commit suite qualifies the new storage transition and failure/recovery cases.

## Local qualification

On 2026-09-28 the proposal suite and six existing agent/note regression tests passed locally, alongside the release OP build, strict Node/agent/Worker UI checks, Japanese/English messages, formatting and documentation/diff checks. CI has been configured to run the suite; this is not a hosted CI or deployment result.

`npm run test:attribute-proposals` uses real paired workerd Workers and D1 migrations, a synthetic official MCP SDK client, HTTP calls and Chromium owner review. It covers absent/explicit capability, wrong owner/base/scope, identical HTTP/MCP receipts, altered payload/hash, unsupported schemas/deadlines, audit rollback, exact owner approval without a Vault write, concurrent identical proposals, final rejection, first-note creation invalidation, revocation, expired-fixture cleanup and credential-stop irreversibility. Browser PRF is mocked; no production or real external-agent interoperability is claimed. Existing snapshot/private-draft and note tests remain separate regression cases.
