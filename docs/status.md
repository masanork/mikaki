# Project status

**Reviewed 2026-10-13 JST.** Mikaki has deployed Passkey/OIDC and encrypted
Owner Vault foundations, and production Work preparation/review/copy-consent
screens. Productive repository copying and AI execution remain disabled.
This page separates deployed code, enabled capabilities, scoped local evidence
and the remaining user/operational acceptance work.

## Recorded deployment and evidence

The verified product/deployment baseline for this review is
`d549fa3072107eb343cb17dfee0f3b122efad0cf` ([PR #198](https://github.com/masanork/mikaki/pull/198)).
[Main run 38326750131](https://github.com/masanork/mikaki/actions/runs/38326750131)
completed all 20 jobs successfully, including OP/Claims/Docs promotion and the
source/version-matched production smoke. At that run, OP version
`650990b8-757a-4cba-bd39-626050b12c96`, Claims version
`17a08823-d079-4b69-bfef-e727001dbd7b` and Docs version
`2ac81e23-33cf-4eb3-9ba5-01129ec2fdd7` were promoted at 100% traffic.
This is retained deployment evidence, not continuous monitoring or a physical-device result.
Main `67dcba7` subsequently updates metrics only.

The [2026-10-05 cutover record](production-reset-2026-10-05.md) remains the
record of the fresh Owner Vault baseline, old-data deletion and retired
resources. Later Work adoption added its separate schema/checkpoint without
resetting the existing Owner account, Passkey or Vault keys.

| Capability | Current evidence | Remaining acceptance or activation |
| --- | --- | --- |
| Passkeys, OIDC and Docs RP | Product login/client/session/logout code and bilingual Docs are deployed. Reviewed enrollment uses one invitation email. Local Rust Worker/browser journeys exercise enrollment, callback, lease and logout. | Fresh owner-device Docs callback/UserInfo and logout E2E, browser automatic-Passkey/cancellation behavior: #4/#5/#6. |
| Logout delivery | Durable outbox and Queue delivery are deployed. After PR #173, the three retained production events all reached delivered/HTTP 200. | Mixed/sustained load, fanout, latency, capacity and owner E2E remain under #106/#109/#6; delivery of three events is not capacity qualification. |
| Owner Vault and key access | Encrypted names/notes/thread archives, local SQLite search, display/session locks, retention/GC and additional-Passkey wrappers are in deployed source. | Intended-device PRF and reopening under #112; all-wrapper-loss recovery and staged key-generation rotation under #114. Account recovery alone cannot decrypt the Vault. |
| Selected sharing and AI proposals | Separate name UserInfo approvals, selected name/OwnerNote Agent grants, proposal capability/review and exact approved saves are connected to the Owner UI. Synthetic v2 name/note local Codex reads are qualified. | Production sharing policy and hosted Agent remain disabled. Real-owner use, persistent-client revocation and conversation excerpts remain under #113. |
| Conversation integration | JSON thread archive import, encrypted storage and browser-local full-text search are implemented. | A named real-source adapter and stable edit/delete/reimport semantics remain under #115. Live messaging is separate future work. |
| Work preparation | Production schema/checkpoint, authenticated source/review, composition and separate copy consent are enabled. PR #198 exports the current Native disclosure record; PR #197 prepares sealed code-only host inputs from it. | Actual provider copy/readback/credential closure #200; concrete authenticated AI run #201; candidate review/exact owner adoption #202. `WORK_COPY_EXECUTION_ENABLED=false`. Track the first complete journey in #199. |
| Identity Wallet | Linked-document issuer/Wallet implementation and schema are in deployed source. Pinned local selected-Issuer qualification reached 84/84 PASS on main snapshot `50dc17c`; later signed-metadata cases gave two SKIPs and cross-client PAR cases two REVIEWs. | Profiles remain disabled pending keys/trust/bindings and #116 activation. Physical cards/devices #117, external wallets #118, remaining suite/human review/certification #119 and ISO transports #120 are open. Local selected cases do not qualify the latest production profile or full HAIP. |
| Portable WebAuthn | Recorded native/Wasm FIDO2 Server Conformance Tools 1.9.2 run passed 167 cases with MDS 3.0 compatibility. | Formal certification, MDS 3.1.1 and intended-device coverage remain separate. See [certification readiness](webauthn-certification-readiness.md). |
| Capacity and storage | Ingress/retention, bounded GC and service ownership are deployed; selected local RP/Agent/UserInfo measurements exist. | Representative mixed/sustained remote load, cost and alerts #106; storage contracts #107; measured adoption decisions for DO #108, audit delivery #110 and PostgreSQL #111. |
| Build and release | Required native, Worker/browser, Android, dependency and Work lanes passed before the source-attested promotion above. | Production backup/restore, recovery fencing, monitoring and device/standards acceptance remain independent. Native coverage is not whole-product coverage. |
| Other profiles | Local FAPI/DPoP, recipient HPKE/ML-KEM and Helpdesk fixtures retain their scoped evidence. | No full FAPI certification, productive PQC sharing or production Helpdesk registration is claimed. |

Evidence owners: [client operations](rp-client-operations.md),
[Queue delivery](logout-delivery-queue.md) and
[#109 production delivery](https://github.com/masanork/mikaki/issues/109#issuecomment-6074975302),
[Owner keys](vault-owner-key-contract.md), [selected record grants](vault-record-agent-grants.md),
[code source and copy preparation](work-code-source-registration.md),
[Work integration](work-delegation-implementation.md),
[Identity](identity-card-issuance.md) and
[#119 selected-Issuer evidence](https://github.com/masanork/mikaki/issues/119#issuecomment-6115002752),
[signed-metadata SKIPs](https://github.com/masanork/mikaki/issues/119#issuecomment-6125870830) and
[cross-client PAR REVIEWs](https://github.com/masanork/mikaki/issues/119#issuecomment-6126644830).

## Current delivery order

1. Keep this status and each Issue's completed implementation, remaining acceptance,
   evidence and next action distinct. A merged slice does not close a larger acceptance Issue.
2. Complete [Work's first one-source/one-run/one-candidate/one-adoption journey](https://github.com/masanork/mikaki/issues/199):
   productive copy #200, authenticated concrete execution #201, exact owner adoption #202.
3. Keep intended-device acceptance in the deferred session requested in #112.
   Reuse a fresh-account Docs login → Vault unlock/reopen → logout journey for
   #4/#5/#6/#112, and include additional-Passkey checks from #114 where supported.
4. Measure #106 before deciding on backend/distribution changes #108/#110/#111.
   Retain #107's operation atomicity and revocation contracts in any candidate.

Vault recovery, real conversation ingestion and Identity activation retain their
own Issue acceptance conditions; the Work trial does not silently complete them.
The [roadmap](roadmap.md) records dependencies and the
[Work delivery backlog](work-delegation-implementation.md#product-delivery-backlog)
records the bounded implementation increments.

## Release blockers

Before use by real users, complete the intended-device/RP acceptance, invitation
and administrator operations, an explicit Vault key-loss recovery policy,
production recovery/monitoring, and the relevant security/conformance gates.
Retain another trusted administrator before depending on the service for other
users, as required by [account enrollment](account-enrollment.md); the single
recorded administrator does not establish administration continuity. Additional-Passkey wrappers do not supply all-key-loss
recovery. Sharing policy, hosted Agent, productive Work copy and Identity activation
must each retain their separate reviewed configuration and qualification.
See [release and recovery](release-and-recovery.md),
[product quality](product-quality.md) and [deployment](cloudflare-deployment.md).

## Historical local and deployment evidence

The dated entries below preserve earlier builds and pre-cutover observations.
Their then-pending deployment/feature statements are historical; the current
capability table and linked Issue evidence above take precedence.
The 2026-10-05 cutover record supersedes their production resource inventory;
retired format-1 transfers and old client registrations are not current features.

The [deployment record](cloudflare-deployment.md) records narashi's production client registration and migrations through `0013` on 2026-09-27; the owner passkey/callback flow remains unverified. The [logout conformance record](oidc-logout-conformance.md) records implemented OP logout, outbox, delivery, and local suite results; production delivery was then unverified. The later PR #173 observation above establishes delivery of three events, while owner E2E and capacity acceptance remain open.

A local stdio MCP adapter passes scope, expiry, revocation, audit-failure, and SDK-client integration tests. Vault selection/PRF export and a separate bearer-authenticated remote MCP Worker now pass local browser and workerd tests, including exact owner approval of private drafts and irreversible source/account/credential/recipient invalidation. Codex CLI completed a synthetic MCP read; Grok Build CLI completed handshake/tool discovery. Browser tests use mocked PRF output and real encryption. These are local results, not deployed agent access or real-device proof. Preregistered public-client OAuth now has the local qualification below; complete real remote client qualification and conversation import remain open. See [agent integration and remaining work](agent-integration.md).

The first VG-01 continuity slice adds same-account passkey registration and saved-name transfer to a fresh encrypted revision. Local crypto, workerd, and browser tests cover target ownership/activity, audit rollback, revision/delete conflicts, exact retries after a lost response, absent target PRF, and fresh-browser reopening. Real-device restore and backup/all-key-loss recovery remain open; migration `0015` and the feature have not been deployed. See [the transfer contract](vault-passkey-transfer.md).

On 2026-09-29, the same transfer authority gained a separate saved-note UI. Local crypto/workerd/browser tests cover typed-content preservation, separate login/source/target credentials, missing/cancelled PRF, exact lost-response retries, new-key reopening, conflicts, unsupported versions and unchanged name data. Note reload discards local retry state and checks the authoritative head. Downloaded local MCP copies remain independent; prepared downloads are cleared on observed revision changes. This does not qualify intended-device PRF or all-key-loss recovery. See [saved-note transfer](vault-passkey-transfer.md#saved-note-ui-2026-09-29).

The first VG-02 slice adds an encrypted, typed owner note with schema version 1 and self-asserted provenance. Local Node HTTP/browser tests exercise validation, import/export, conditional edits, exact retries, tombstones and protection of unknown versions while preserving legacy `name`. PRF is mocked in the browser; no production deployment or automatic agent sharing is implied. See [typed owner attributes](vault-typed-attributes.md).

On 2026-09-29, saved notes gained explicit local MCP export selection, a saved-content/recipient/deadline preview, fresh note-envelope PRF and saved-head/schema checks. Browser downloads pass through the actual stdio server and official SDK client with read-only scope, unselected-target rejection and local grant revocation. Preparation failures, separate login/note credentials, combined name/note selection and clearing prepared downloads on observed changes are covered. Remote note sharing, intended-device PRF and deployment remain unqualified. See [the local-note flow](agent-integration.md#saved-note-local-read-flow-2026-09-29).

The first VG-03 slice adds a separate target/revision capability and one typed note proposal/decision authority for HTTP and MCP, plus owner dashboard review. Local paired workerd/SDK/browser qualification covers exact retries, concurrent creation, wrong owner/base/hash, audit rollback, invalidation and expiry cleanup. Migration `0016` is local only. Approval records a decision without changing the Vault; a separate VG-04 owner save action now performs the verified encrypted commit. See [the proposal contract](vault-attribute-proposals.md) and [ADR 0013](adr/0013-agent-proposal-authority.md).

The first VG-04 slice connects approved typed-note proposals to an owner-device-encrypted, exact-value-verified commit. Rust atomically consumes approval and records the owner head, mutation result and audit. Local migration/workerd/Chromium tests include injected R2 and late D1 failures, exact retries, stale/expired/revoked cases, page recovery, unknown-schema protection and tombstone recreation. Migration `0017` and the feature have not been deployed; intended-device PRF and remote OAuth gates remain. See [approved commit](vault-approved-commit.md).

VG-05 adds bounded Rust owner login/return and isolated Codex CLI/App Server 0.157.1 qualification (2026-09-29): OAuth token persistence, new-process reads, scope narrowing and revocation, alongside preregistered discovery/request qualification and preregistered public-client OAuth discovery, S256 PKCE, exact callback/resource binding, owner-session-bound selection of an existing shared grant, narrowed access tokens and individual revocation. Local official SDK/workerd/Chromium tests cover code concurrency, scope isolation, audit rollback, expiry and token/client/grant invalidation, including private drafts and separate note proposals. Migrations `0018`–`0019` and these endpoints have not been deployed. Grok Bot now has locally tested standalone plugin preparation and redacted OAuth request inspection. An existing Chrome session resolved dashboard access; the personal plugin page's Add action opened the public marketplace, and no private repo/team-marketplace controls were observed. Custom-plugin distribution for this account remains unresolved. Deployed Codex endpoint and actual Grok Bot plugin registration/callback requirements and remote flows, abuse controls and operational activation remain open. See the [OAuth profile](agent-oauth.md), [Grok Bot qualification](grok-bot-integration.md) and [ADR 0014](adr/0014-agent-oauth-authority.md).

On 2026-09-29, owner-facing source-version/freshness displays were added for saved names/notes and their AI copies. The UI distinguishes separately confirmed saved heads from page-loaded/copy revisions, shows confirmation rather than invented update times, records bounded page-local download-start metadata and displays remote grant source/creation/expiry information. Failed checks become unconfirmed, with account-bound retry and no live-file synchronization claim. See [freshness behavior and local qualification](agent-integration.md#source-version-and-copy-freshness-2026-09-29).

On 2026-09-29, all local and remote MCP tools gained declared output schemas and matching validated structured/text results. Read responses carry explicit source revisions/provenance and access-check mode/time; local files report that Vault freshness was not checked. Legacy exports remain accepted with unspecified provenance, while new export metadata is digest/target-bound. Local SDK/workerd/browser qualification preserves scope, audit, revocation and exact proposal/draft retry behavior. See [the output contract](agent-integration.md#structured-mcp-results-2026-09-29). No new production or real Codex/Grok qualification is claimed.

## Product UI evidence, 2026-09-29

Vault, invitation management, registration completion, and logout now share the login brand, responsive layout, control hierarchy, and same-origin stylesheet. Profile operations are serialized and uncertain mutations retain their exact encrypted operation for retry; reload explicitly discards profile edits/retry state and rechecks saved data. Name/note reload, manual lock, and transfer confirm draft disposal; initial deletions require confirmation. Browser unload warnings protect full-page navigation where supported, with no draft persistence. Automatic/security locks never wait for confirmation. Local Chromium regression checks cover both languages, mobile layout, keyboard navigation, style delivery under CSP, loading recovery, and lost-response retry. A local Vault display lease now locks after 15 minutes idle or one hour absolute, masks hidden tabs, verifies the same SSO session on return, and disposes every panel on lock or pagehide. Login/logout notifications lock other tabs. Local Worker/Chromium lifecycle tests exercise deadlines, late responses, session replacement, and cross-tab logout; intended-device qualification remains open. See [session lifecycle](session-lifecycle.md), [screens](product-ui-preview.md), and [quality gates](product-quality.md). The screenshots use synthetic data and mocked PRF; they are not a deployment, intended-device, or accessibility certification.

## Pre-merge test evidence, 2026-09-29

Product Worker contract and browser gates now run in PR verification as well as the attested main build. A local HTTPS journey connects actual Rust OP enrollment, virtual Passkey/PRF, saved-name reopening, a reference RP code exchange, replay invalidation and logout denial. Four native OIDC boundary tests cover registered-key signatures, claims, expiry/skew and authenticated PKCE exchange. The recorded native baseline is 86.9% lines / 83.1% regions; the separate recorded Node/V8 TypeScript baseline is 52.6% lines and excludes Svelte/browser execution. Instrumented browser failures retain traces/screenshots and bounded diagnostics. These are local/configuration results, not a completed remote CI run or actual narashi/physical-device qualification. See [test quality and reproducible evidence](test-quality.md).

## Release and recovery rehearsal, 2026-09-30

This section records the pre-cutover state on that date. The
[2026-10-05 cutover](production-reset-2026-10-05.md) supersedes its then-pending
production upload, version/readiness and attestation-mapping claims. Production
backup/restore qualification remains separate from the completed fresh reset.

The local release verifier now binds both Worker archives, their exact regular members, the source revision/cleanliness and ordered migration hashes. It rejects substituted bytes, unexpected/duplicate/linked members, migration gaps and tracked/untracked source edits. The attested-build configuration creates/verifies and separately attests this inventory. A disposable SQLite/filesystem exercise upgrades the recorded `0001`–`0013` baseline to every checked-in migration, preserves an encrypted name head/audit/closed bootstrap, rolls back a failed migration, restores a real backup and reopens matching ciphertext. It also rejects missing/corrupt objects and demonstrates historical restoration of revoked SSO/credential state. The secret-free report explicitly marks production recovery unavailable. Local tests and locally built archive checks pass; remote CI/attestation, Cloudflare restore, external recovery fencing, R2/key retention, runtime-byte mapping, intended devices and RP invalidation remain open. See [the runbook](release-and-recovery.md).

The OP can now expose its Cloudflare version ID and embedded source commit through `/version`; the manual production smoke can require a reviewed version and clean commit and retain comparison evidence. Local checker and Worker tests cover this path. It has not been deployed or checked at the production issuer, and the attested archive digest is still not linked to a Cloudflare-uploaded version.
The OP's bearer-protected `/ready` now checks policy validity, the build's latest D1 migration, private/public signing-key agreement, essential bindings and the internal Claim Worker schema path without returning configuration details. Version-aware smoke requires a 204 readiness response with a separately provisioned monitoring secret. Local multi-Worker tests pass normal setup and reject missing credentials, policy/key or Claim schema. This has not been exercised on the production issuer and does not prove R2 object access, recipient key material, writes or alerting.

An offline preparer now rechecks both release archives and the clean source, stages only their approved members, and uses Wrangler dry runs with production configs to inventory the final local upload inputs. A verifier rejects changed source, migrations, configs, staged members or bundle files before upload. Both Workers' prepared bundles passed a local dirty-source rehearsal, including `--no-bundle` dry runs; it did not upload or activate a Cloudflare version. Remote upload-byte/version and binding records remain to be established.
The reusable attested build is configured to perform the same preparation and verification in a clean checkout, attest `upload-manifest.json`, and distribute the prepared bundle bytes. This workflow change has local evidence only; a new remote run and attestation have not yet been observed.

## Resource and storage boundaries after the 2026-10-05 reset

[Ingress budgets and bounded retention](auth-resource-lifecycle.md),
[OP-owned storage capabilities](adr/0015-service-data-ownership.md) and
[Owner-record candidate GC](vault-garbage-collection.md) are deployed in the
fresh baseline. The minute auth/logout and ten-minute Vault schedules match
configuration. Their actual Worker contract regressions passed main CI. PR #130
corrected a production D1 limit in auth backlog telemetry using six independent
prepared statements in one batch, without changing retention or cleanup. Two
minute-cron `auth_gc` successes on the deployed source reported all six backlog
kinds with zero expired rows; no failure was captured in that window. The
independently reviewed acceptance evidence for #99–#101 and #103 is complete.
Load and operational alert qualification remain separate under #106.
Agent runtime integration remains local because no hosted Agent was activated.

The selected v2 sharing/approval paths and legacy denials retain their product
regressions. Docs replaces the retired Demo RP. Owner-browser login, Vault PRF
and Docs callback/logout E2E are still to be confirmed against the new
source/version; virtual-authenticator tests do not replace those observations.
