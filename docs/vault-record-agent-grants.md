# Selected v2 agent grants

**Status:** draft API implementation, 2026-10-03. Migration `0033` extends the isolated agent service to one explicitly selected v2 name or owner-note record. The owner-v2 preview does not yet mount these controls. No production migration, recipient provisioning or sharing-policy activation is included. The unchanged ordinary UI and its default status endpoint remain format 1.

## Source and copy authority

A new request explicitly supplies `storage_version: 2`, the complete [record source](vault-selected-record-disclosure.md), separate key-generation/current-registry fences, exactly one matching document ID, and a version-2 encrypted snapshot. The service verifies the OP-provided owner/origin and recipient binding before storing the request. The snapshot uses an independent transport key, not the owner root or content key. Browser-supplied plaintext is self-asserted; source metadata does not establish authenticated issuer authorship.

The supported targets are only `personal/name/name` and `personal/owner_note/owner_note`. Name validation preserves the existing 256 UTF-16-unit limit and lossless UTF-8, including a leading BOM. Notes preserve the strict canonical typed-note schema. Existing format-1 requests retain their wire ordering and request hashes; a new v2 grant never reuses the authority of a same-named v1 grant.

One shared live-source predicate is used in creation, active reads, audit, owner status and OAuth. V2 source identity pins origin, owner, Vault, collection, record, kind, content revision and stored ciphertext digest; the separate authority pins root generation and registry revision. The active nondeleted record and supported owner root must still match. Existing account epoch, credential, recipient/resource, expiry, selected operations and access-token checks remain required.

Migration `0033` makes source identity/selection immutable, scopes v1 source invalidation to v1 grants, and irreversibly clears a v2 snapshot after its source or root changes. Account/credential/recipient revocation continues to apply to both families. Source changes cannot be undone by changing the head back. Exact old creation retries acknowledge their request but cannot reactivate access.

## Disclosure, OAuth and owner inspection

Read, list and search decrypt only the selected snapshot. Audit must succeed and the same grant/source/token must still be active after audit I/O before a result is returned. V2 results explicitly use `source_info.kind = vault-record` and `access.source_check = record-matched`. These are point-in-time checks; already delivered plaintext cannot be recalled.

The default `/vault/agents/status` returns only legacy grants and their corresponding audit/proposal/draft rows. The explicit owner-only `/vault/agents/record-status` returns only v2 rows. It has the same authenticated OP bridge as the legacy endpoint and is never dispatched by the public agent entrypoint. Revoke-all intentionally stops both families.

V2 OAuth requests require exact version-2 authorization details with complete source and authority tuples. Scope-only and legacy detailed requests cannot select v2 grants. Owner consent, code redemption and active token access all retain exact grant/revision/resource and narrowed-scope checks. V2 UI for reviewing this detail remains a separate gate.

Private draft proposals remain selected-document-bound and cannot modify the Vault. A v2 read grant cannot enter the legacy attribute-capability/proposal/approved-commit state machine; its dedicated [owner-note write capability](vault-record-approved-commit.md) is a separate explicit service authority, with UI qualification still pending.

## Evidence and limits

The [in-process Worker/MCP/OAuth tests](../local/conformance/agent-record-grants.test.ts) execute the bundled service over a disposable native SQLite adapter. Thirteen cases cover populated-v1 migration and request hashes, name/note selection, full tuple and authority substitution, source/deletion/registry invalidation, post-decrypt and post-audit revocation, account/session/credential/recipient fences, exact OAuth consent/redemption, private-draft replay, status isolation and multibyte/BOM names. Three [migration-only tests](../scripts/test_agent_record_sql.test.ts) cover null/mixed/multiple sources, fractional revisions, immutable identity and non-restoration. Independent review reran all 16 cases successfully after correcting the SQL null guard and name-validation mismatch.

The [paired workerd suite](../local/conformance/agent-worker.test.ts) locally passes v2 grant creation/read, owner status through the OP bridge, v1/v2 source isolation, exact OAuth, legacy write denial and source invalidation during final audit. Both v1 and v2 private drafts require exact owner approval and converge on one draft under concurrent execution/retry. These disposable D1/workerd tests exposed the runtime's 100-level SQL expression-depth limit; grouping the unchanged OAuth authorization predicates keeps nested execution statements within it. Synthetic OAuth redirects are inspected without following them to public DNS. All three paired-suite tests and the 16 focused native/migration cases pass locally after this correction.

The paired suite remains included in `test:agent-integration`; exact-head CI must also pass. Native SQLite alone is not evidence of D1/workerd atomicity, service binding, browser consent or real OAuth-client qualification. These local synthetic runtime results do not qualify an actual OAuth client or production behavior. V2 browser consent and owner sharing UI remain separate gates; no deployment is implied.
