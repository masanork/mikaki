# Agent integration and remaining work

Evidence reviewed on 2026-09-28/29. This document distinguishes a local experiment from a production agent authorization service. Existing login and Vault release gates still apply.

Current source status (2026-10-05, follow-up branch `feat/issue-121-agent-v1-retirement`): the remote Agent Worker accepts and discloses only storage-version-2 selected records. Legacy v1 grants remain stored only for revocation and retention; they cannot authorize calls. Scope-only OAuth remains supported for existing clients, but owner consent can select only an active v2 grant with its live record source and authority. If OAuth authorization details are supplied, they must exactly match that record. The dated notes below describe earlier local behavior; the v1 attribute tool and routes described there have since been removed from the current source.

The subsequent [Vault protocol review](vault-protocol-review.md) places MCP at the AI adapter boundary. Storage/revisions, credential presentation, FileNode synchronization, and OAuth delegation have separate contracts. The current generic `mikaki_execute` creates a private draft outside Vault; it is not a generic encrypted Vault write API. Future adapters must reuse authoritative domain operations rather than establish transport-specific grant or revision state machines. Local owner-selected `owner_note` exports are implemented alongside saved-name exports; remote v2 snapshot grants can select one `name` or `owner_note` record.

## Connect a selected v2 record to local Codex

In the Owner workspace, open **Local v2 export** after saving a name or owner note. Select one saved record, enter `codex-local` as the delegate label and `OpenAI` as the service label, and choose one hour or one day. Prepare the export, review the exact plaintext, source revision and expiry, then confirm the selected copy before downloading the bundle and grant separately. Closing the panel, locking the workspace or observing a source revision change discards its prepared download state.

Keep both files in an owner-controlled directory. Use the paths from your downloads in this command, and keep the final delegate argument equal to the grant's label:

```sh
codex mcp add mikaki -- node /ABS/mikaki/local/agent-mcp.ts \
  /ABS/owner-files/mikaki-v2-grant-ID.json \
  /ABS/owner-files/mikaki-v2-bundle-ID.json \
  /ABS/owner-files/audit.jsonl codex-local
```

Restart Codex after adding the server. Ask it to list the selected records, search a known phrase, or read `name` or `owner_note`, matching the exported record. These are local plaintext copies: `source_check=not-checked` means the adapter does not contact the live Vault. A later Vault edit does not update a downloaded copy. Set `revoked` to `true` in the grant JSON to deny subsequent tool calls, including in a running adapter. Previously delivered text and independent access to the files remain outside this control. Revoking a remote grant in the dashboard does not change these local files. Local export creates no remote grant or proposal capability. A Codex read can transmit the selected text to its AI provider. The service/delegate labels identify the owner's intended recipient; they do not authenticate the local client.

The optional synthetic qualification uses temporary configuration and no production record or grant:

```sh
npm run probe:codex-v2-local-records -- name
npm run probe:codex-v2-local-records -- owner_note
```

The probe checks exactly one successful Codex `list`, `search` and `read` call. Separately, its MCP SDK preflight verifies the v2 source/authority and denies a read on the same running SDK client after grant revocation. Codex source/authority validation is reported only when its completed tool results expose that metadata. This probe does not qualify revocation on a persistent Codex connection. Its output contains only qualification results, operation names and counts; it does not save Codex JSONL or record text. Intended-device Passkey/PRF checks, owner-selected real data disclosure and hosted Agent activation remain separate work.

Fresh qualification on 2026-10-08 with Codex CLI 0.161.0 passed for synthetic v2 `name` and `owner_note`: one successful list/search/read call each, exact three allowed audit entries, and source/authority verified in all completed Codex results. The separate SDK preflight also denied read after revocation on its existing client. This does not establish an owner-device ceremony or a persistent Codex connection revocation check.

## Priorities and acceptance gates

| Priority                   | Concrete outcome                                                       | Remaining acceptance evidence                                                                                                                                                                                                                                                                                                                                                                                               |
| -------------------------- | ---------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| P0: production RP          | Finish narashi's registered login, session check, and logout.          | Owner completes a real passkey login and callback; RP establishes the correct subject/session; logout invalidates it; exercise outage, callback race, and key rotation. Registration is recorded in the [deployment guide](cloudflare-deployment.md); issue [#4](https://github.com/masanork/mikaki/issues/4) predates that registration.                                                                                   |
| P0: intended devices       | Reliable first login and SSO reuse.                                    | Safari/iOS, Chrome/Android, and desktop cancellation/retry and expiry checks. See [#5](https://github.com/masanork/mikaki/issues/5).                                                                                                                                                                                                                                                                                        |
| P0: logout operations      | Revocation survives delivery failure.                                  | OP logout/outbox/signing and local conformance exist; verify the production version, receiver, retry, duplicate delivery, and lease bound. See [local conformance](oidc-logout-conformance.md) and [#6](https://github.com/masanork/mikaki/issues/6).                                                                                                                                                                       |
| P1: Vault continuity       | Recover data on another authorized device.                             | PRF rewrap/transfer, fresh-device restore, same-account replacement, conflicts, lost responses, and key-loss behavior. Login recovery alone does not recover Vault keys.                                                                                                                                                                                                                                                    |
| P1: limited local AI reads | Give a local MCP client selected plaintext, for at most one day.       | Vault selection/PRF export and stdio tests pass locally. Codex CLI completed a synthetic MCP read; Grok Build CLI completed initialization/tool discovery. Real-device approval remains a product release check.                                                                                                                                                                                                            |
| P2: remote delegation      | Let a cloud agent read a selected copy without the owner's SSO cookie. | A separate Worker, explicit decrypting recipient, resource-bound bearer credential, dashboard, and invalidation tests are implemented locally. Preregistered public-client OAuth now has local SDK/browser qualification; bounded Rust owner login/return and installed Codex discovery/request qualification are also implemented. Production provisioning/review and complete real-client token/MCP qualification remain. |
| P3: agent actions          | Let an agent propose an effect and a human authorize execution.        | A private-draft proposal/approval/execution path passes local tests. Sending, publishing, arbitrary execution, and Vault mutations are outside this capability.                                                                                                                                                                                                                                                             |

The open issues include historical descriptions; their status alone is not evidence of missing implementation. This change does not close issues, post messages, or deploy a service.

## Implemented local read adapter

[`local/agent-mcp.ts`](../local/agent-mcp.ts) uses the official MCP TypeScript SDK and stdio. It exposes only `mikaki_list`, `mikaki_search`, and `mikaki_read`. The owner prepares a plaintext export and a separate grant; tools never accept a filesystem path or mutate the grant. There is no automatic conversation import, browser bridge, Vault decryption, OIDC authentication, or external network call.

The grant selects document IDs and operations, an owner/collection, delegate label, downstream service label, start time, expiry, and export SHA-256. It permits at most 24 hours. The adapter snapshots the bounded export at startup and checks its digest against the grant. Changed content needs a new export/grant and process restart. Every call reloads the grant, checks scope, writes audit, and rechecks the grant and time immediately before returning. Removing/malforming the grant, setting `revoked=true`, a scope change during the call, or audit failure prevents disclosure. An in-flight response already authorized for return cannot be recalled.

List/search expose only selected document metadata; search uses literal case-insensitive text matching and returns no body snippets. Pages contain at most ten items. Exports are limited to 1 MiB, 100 documents, and 16 KiB of text per document. IDs are opaque tokens, not paths. Titles/source labels and text are untrusted content; source labels do not verify authorship. Audit contains time, grant, delegate, service, operation, outcome, and a selected read target; it excludes bodies, queries, and rejected target IDs. An `allowed` record means the call passed its initial authorization and audit step; a subsequent `denied` record can still prevent disclosure.

### Prepare a harmless example

Run from the repository root with the project's Node version and `npm ci`. This writes only synthetic example content into ignored `local/generated/`. For real data, the owner must select and export exactly what they intend to disclose; keep the bundle, grant, and audit under owner control.

```sh
node --input-type=module <<'JS'
import { mkdirSync, writeFileSync } from 'node:fs';
import { makeSyntheticRecord } from './scripts/probe-codex-v2-local-records.ts';
mkdirSync('local/generated/agent-example', { recursive: true, mode: 0o700 });
const now = Math.floor(Date.now() / 1000);
const fixture = makeSyntheticRecord('owner_note', now);
const bundle = fixture.bundleBytes;
const grant = { ...fixture.grant, delegate: 'codex-local', service: 'OpenAI' };
writeFileSync('local/generated/agent-example/export.json', bundle, { mode: 0o600 });
writeFileSync('local/generated/agent-example/grant.json', JSON.stringify(grant), { mode: 0o600 });
JS
```

Inspect both files before connecting. Set `revoked` to `true` in the grant to stop subsequent tool reads, including in the same running process. To stop delivery to a cloud provider, also remove copies outside your control where supported; local revocation cannot erase previously delivered content.

### Connect a local client

Substitute absolute paths and the Node executable used by this project:

```sh
codex mcp add mikaki -- node /ABS/mikaki/local/agent-mcp.ts \
  /ABS/mikaki/local/generated/agent-example/grant.json \
  /ABS/mikaki/local/generated/agent-example/export.json \
  /ABS/mikaki/local/generated/agent-example/audit.jsonl codex-local
```

Codex supports local stdio and remote HTTP MCP servers; see [official OpenAI documentation](https://learn.chatgpt.com/docs/extend/mcp?surface=cli). Grok Build's documented equivalent starts with `grok mcp add mikaki -- node ...`; prepare a separate grant with matching delegate/service labels first. See [Grok Build MCP](https://docs.x.ai/build/features/mcp-servers). The optional `node scripts/probe-agent-clients.ts` probe uses synthetic data: Codex CLI 0.157.1 completed an MCP read and Grok Build 1.0.41 completed a 2025-11-25 handshake and discovered all three tools on 2026-09-28. The probe uses temporary configuration rather than registering a permanent connection. The Grok probe verifies protocol connectivity, not a Grok model-generated read.

These labels are owner configuration, **not authenticated client identity**. The stdio pipe/process is the local trust boundary. An agent with independent filesystem/command access can read the export, modify the grant, change the clock, or alter the audit outside this adapter. Use OS isolation and owner-controlled configuration if those actions must be prevented. Audit is a local operational log, not tamper-evident evidence. Do not copy live Vault keys, SSO cookies, or a broad export into a shared bot computer.

## Grok Bot and remote agents

[Grok Bot's official computer documentation](https://docs.x.ai/grok-bot/computer-and-apps) states that all Bots in an account share a cloud computer, browser sessions, files, and command-line credentials. Bot display names do not form an isolation boundary. Grok Build MCP and the [xAI API remote MCP tool](https://docs.x.ai/developers/tools/remote-mcp) are separately documented capabilities; they are not proof that Grok Bot can register this local server as a connector. Treat that integration as unverified. The intended target is the Grok Bot persistent cloud-computer product launched in August 2026. Its Marketplace/hosted plugin route, Cursor connector backend and actual registration/callback requirements are tracked in [Grok Bot qualification](grok-bot-integration.md); Grok Build and grok.com Business connectors are separate clients.

The following summarizes the current remote Agent path. Grant creation is limited to one selected v2 `name` or `owner_note` record and binds its complete source and key authority. OAuth consent is shown in the mounted OwnerWorkspace return flow and can select only an existing active grant; it cannot create a grant. Scope-only OAuth remains compatible with clients that omit authorization details, while a supplied RAR detail must exactly match the chosen record. The UI displays each option's record identity and authority and resets consent when the selection changes.

The separate [`crates/agent-worker`](../crates/agent-worker/README.md) resource server offers stateless Streamable HTTP MCP and protected-resource metadata. `mag_` credentials are 32 random bytes; only their SHA-256 hashes are stored. Each call checks the resource URI, recipient state, account epoch, credential state, live record source/authority, grant revision/expiry, and operation against fresh primary D1 state. OAuth uses S256 PKCE, exact callbacks/resource and owner-approved narrowed tokens. Mikaki OIDC/UserInfo tokens are never accepted. The record proposal/approval path binds a canonical candidate to an exact selected record; the owner-side encrypted commit verifies it before writing. Separately, generic `mikaki_propose`/`mikaki_execute` creates only a private draft and cannot write Vault data. Revocation clears encrypted snapshots; previously returned plaintext and derived summaries cannot be recalled. Production provisioning, real remote-client qualification, abuse controls and recovery review remain open.

## Local verification and remaining deployment gates

Run `npm run test:agents` for stdio and `npm run test:agent-integration` after building the OP Worker. The latter exercises real local workerd/D1/R2 and a Chromium owner flow with mocked PRF output and real encryption. It covers saved/unsaved values, consent, origin and owner isolation, export binding, read-only scope, expiry, audit-write rollback, denied access, exact approval, concurrent execution/retries, source/credential/account invalidation, multi-grant emergency stop, and irreversible recipient stop. The local-note browser test also passes downloaded files through the actual stdio server and official SDK client, including note-only access without name unlock, separate note/login credentials, title bounds, live-head changes during preparation, unsupported schemas, safe rendering and subsequent grant revocation. It does not replace intended-device passkey tests or a production bot connection.

## Saved-note local read flow, 2026-09-29

This historical section records the pre-reset UI and credential model. Its controls and unlock behavior are not instructions for the current Owner workspace; use [the v2 local Codex flow](#connect-a-selected-v2-record-to-local-codex) above.

In Vault's **Share with an AI agent** section, select **Share my saved owner note through local MCP**; name selection is optional. Select the connection/provider label and one, four or 24 hours, approve disclosure, then prepare the export. This requires an active owner session and a saved note, but not unlocking or saving the name. The note's own envelope chooses the required PRF credential, even when it differs from the session's login credential. Review the displayed saved title/text, revision, self-asserted provenance, recipient and deadline before downloading both files. The existing local adapter connection instructions above apply unchanged.

The browser fetches the current encrypted note with no cache, requires its body revision and ETag to match the displayed saved revision, decrypts and validates the exact version-1 note, and rechecks that saved head after the PRF prompt. A changed/missing head, canceled/unusable PRF, wrong key or incompatible schema prevents preparation. The owner session/account and selection are checked again before retaining the export. Local editor edits are never used. Selection, recipient, lifetime or observed saved-revision changes clear the prepared download; no file is downloaded automatically.

The format-1 document ID is `owner_note`. Its text is the exact canonical note JSON, preserving the full title and `self-asserted` provenance; its bounded list title is the localized Owner note label. The source label is `vault:owner_note:REVISION:self-asserted`. These are untrusted owner assertions, not authenticated issuer claims. Name and note can be selected together; only selected IDs appear in the bundle and grant. Local grants always contain only `list`, `search`, `read`, even if remote private-draft actions are selected. No owner key, PRF output, ciphertext envelope or SSO cookie is exported, and no remote grant or proposal is created.

After download, this is an immutable selected copy: changing/deleting a Vault record does not remotely alter the export or revoke its local grant. Edit `revoked=true` in the downloaded grant or remove that grant to stop future adapter reads; expiry is checked on each call. The remote dashboard's revoke actions control remote grants, not these downloaded files. Previously delivered plaintext and independent filesystem access remain outside the adapter's control. Updated content requires new explicit preparation and replacing the export/grant before restarting the local adapter.

Production configuration, key provisioning, database migration, named service-binding isolation, and remote-client examples are in the [agent Worker runbook](../crates/agent-worker/README.md). Production deployment, a real Grok Bot connector trial, account-level provider isolation, WAF/rate limits, backup/recovery review, and full OAuth onboarding remain gates. No deployment or real user data disclosure was performed for these tests.

Receiving a message, mentioning a bot, or authenticating a person does not authorize disclosure or delegation. These features need independent state transitions and acceptance tests before activation.

## Historical typed attribute proposal extension, 2026-09-28 (retired)

This dated experiment exposed a legacy `mikaki_propose_attribute` tool and related attribute routes. The current service has removed that tool and its v1 authorization path. The v2 selected-record proposal, owner approval and encrypted-commit flow remains: approval binds an exact candidate, and the owner-side commit verifies it before writing the encrypted record. The separate generic `mikaki_propose`/`mikaki_execute` flow creates only a private draft and never writes Vault ciphertext. Historical rows are retained for revocation, payload redaction and expiry cleanup. The old qualification and ownership rationale remain in the [archived contract](vault-attribute-proposals.md) and [domain ownership decision](adr/0013-agent-proposal-authority.md).

## VG-05 OAuth qualification, 2026-09-28/29

The [preregistered public-client profile](agent-oauth.md) now connects metadata discovery, S256 PKCE, owner-session-bound review of an existing shared grant, one-winner code exchange and narrowed tokens. Individual token/client/grant invalidation is rechecked for domain writes and disclosure. Local official SDK/workerd/Chromium evidence includes reads, private drafts and a separately enabled typed note proposal. [ADR 0014](adr/0014-agent-oauth-authority.md) explicitly records the isolated AS authority exception. Installed Codex discovery and a preregistered PKCE request are additionally qualified, and owner login/return is implemented locally. Isolated Codex CLI/App Server additionally passed token persistence, reads, scope narrowing and revocation on 2026-09-29. The deployed endpoint, actual Grok Bot plugin registration requirements, abuse controls and production activation remain gates.

## Source version and copy freshness, 2026-09-29

The owner dashboard now reads each selected source family's existing ciphertext endpoint with the browser fetch cache mode `no-store`, checks the exact positive ETag/body revision, and confirms the same owner session after those reads. It does not decrypt data for this check or add a metadata authority. Each attribute is a separate observation, with the browser's confirmation time. This is not a content-update timestamp, a real-time synchronization claim, or protection against a malicious store.

The UI shows the last confirmed saved version and the version already loaded in this page. Copies are labeled with their source revision and compared with the confirmed saved head: same at check time, a newer observed version, a differing/lower version requiring review, deletion, missing source, or unconfirmed. A failed storage/session/format check retains the previous observation as history but stops claiming an equal/current source. An older in-flight check cannot replace a newer check or another owner's state. A failed account confirmation also hides remote grant state; Refresh remains available for retry.

Remote access rows show the persisted source revision, server-recorded grant creation time, expiry, and browser confirmation time for the last fetched grant status. Expiry rendering advances while the page remains open. This is a bounded view of retained remote grants, not proof that previously delivered data was recalled.

Local previews now label both name and note revisions. Starting a plaintext download records only content-free metadata in this page: the copy's source revisions, their preparation confirmation times, download-start time and grant expiry. At most 20 export records are retained; reloading or changing the owner clears them. Repeated download of the same prepared bundle uses the same record. It is not a durable download-completion receipt or a filesystem inventory, and does not retain extra plaintext, owner keys or bearer credentials.

A confirmed source mismatch/deletion or failed source confirmation clears a still-prepared download for the affected item. Already downloaded files/grants remain independent copies; the local MCP adapter still verifies its digest, expiry and revocation rather than checking live Vault heads. The structured MCP extension below now carries source/access metadata. Credential-specific issuer validity/status semantics remain separate work; OID4VP/VCI are not implemented by this display.

Local helper/browser/workerd tests cover version agreement, later edits and deletion, independent note/name observations, missing/malformed ETags, unavailable storage/session, retry after failure, history metadata, saved-note local MCP exports and Passkey transfer regressions. `npm run test:agent-integration` includes the observation contract test. No production deployment or intended-device PRF proof is implied.

## Structured MCP results, 2026-09-29

All three local read tools and all six remote tools now declare MCP `outputSchema` and return successful values in `structuredContent`. The identical validated JSON is also serialized in the existing text block, following the [MCP structured-content contract](https://modelcontextprotocol.io/specification/2025-11-25/server/tools#structured-content). Existing document/receipt fields remain available. Remote list/search responses now explicitly include `next_offset: null`; local pagination retains its bounded offset. The single shared [output definition and serializer](../crates/agent-worker/tool-results.ts) validates values before either representation is returned, and the installed MCP SDK validates declared output schemas as well.

Every successful result has `result_version: 1` and `untrusted_content: true`. Proposed/executed receipts keep their existing IDs, hashes, target/base revision, destination and state semantics. Schema additions do not create a new proposal authority, approve a value, widen scopes, or change the retry hashes. Execution receipts remain stable for identical retries; time-varying access metadata is confined to read results.

Read/list/search results add the following fields:

| Field                             | Meaning                                                                                                                                                                                                                       |
| --------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `source_info.kind`                | `vault-record` for a v2 selected record; `unspecified` for a generic local export without structured provenance.                                                                                                              |
| `source_info.source`, `authority` | The exact v2 record identity and key authority observed for that grant. The free-text `source` label is never parsed to infer these fields.                                                                                   |
| `source_info.provenance`          | `self-asserted` for the selected saved record; this is not verified issuer authorship.                                                                                                                                        |
| `source_info.confirmed_at`        | Reported source-version confirmation time in Unix seconds, or null. It is not the content-update time. For remote reads it matches the final live-check time; for local files it is the owner export's recorded confirmation. |
| `access.mode`                     | `local-export` or `remote-snapshot`.                                                                                                                                                                                          |
| `access.source_check`             | Local `not-checked` means no live Vault read. Remote `record-matched` means the v2 record source and authority matched the grant during this call. Neither is a live subscription.                                            |
| `access.checked_at`               | Unix seconds of the final access check after audit I/O.                                                                                                                                                                       |
| `access.grant_expires_at`         | Unix seconds of the underlying grant deadline. OAuth token expiry may be earlier and is governed by its separate token response; this is not a promise of continued access until that deadline.                               |

New browser-prepared local documents include optional `source_info`, bound into the existing whole-export SHA-256 digest. The adapter validates the metadata shape and its Vault collection/document-ID binding, without treating owner-supplied timestamps/provenance as issuer proof. Saved note title/text/provenance remain the canonical note JSON in `text`. Old exports without this field still work and produce explicit unspecified provenance; even a label resembling `vault:name:999` cannot establish a saved version. An older strict adapter may reject new exports containing the optional field: use the current adapter for newly prepared files. No owner keys or credentials are added to exports or result metadata.

Remote source metadata comes from the active grant's authoritative `source_revision` and the final live account/credential/head/token checks, independently of the encrypted snapshot's untrusted display label. Local expiry/revocation/digest/selection and remote scope/audit/revision checks remain required before either text or structured disclosure. Errors return `isError: true` with the existing generic message and no successful structured document/receipt. No hidden document metadata is returned on denial or in unmatched search results.

Local qualification covers declared schemas and successful structured SDK calls over both stdio and streamable HTTP, text/structure equality, bounded pagination, metadata digest/target binding, unspecified legacy provenance, unknown trust states, separate saved-note credentials, audit failure, scope/revocation/expiry and proposal/execute receipt replay. Browser downloads round-trip through the actual stdio adapter. The current Codex/Grok product qualification records predate this output extension; these SDK results do not claim a new real-client or production deployment test. Issuer trust, holder keys, OID4VP and OID4VCI remain VG-07 work.
