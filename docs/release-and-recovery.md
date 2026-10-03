# Release and recovery rehearsal

Reviewed on 2026-10-01. This runbook separates verified local checks from production activation. It does not authorize a deployment or historical database restore. [Product quality](product-quality.md) retains the device, RP, operations and provenance gates.

## Release inputs

The attested build generates `artifacts/release-manifest.json` after archiving both Workers. It records the clean Git source commit, SHA-256 and size of each archive and its four regular members, and the complete ordered migration set with SQL hashes. The manifest itself receives a build-provenance attestation. CI also prepares both production-configured Wrangler upload bundles, rechecks them, and attests their `upload-manifest.json` of archive/configuration/bundle hashes. The archive members are `index.js`, `index_bg.wasm`, `package.json` and `worker/shim.mjs`; runtime secrets remain outside these archives.

`npm run release:verify` reads the archives without extracting them, checks the exact member set/types, and compares the byte inventory and local migrations with the manifest and current clean checkout. Unexpected, duplicate or linked archive members, modified bytes, migration gaps, dirty/untracked inputs and a different source commit fail verification. Each input/output is bounded to 64 MiB and tar operations time out after 30 seconds. This is integrity checking; an attacker who replaces both the manifest and artifacts can satisfy it. Verify trusted attestations first.

The attested workflow already prepares the upload directory. After downloading and verifying it in a clean checkout, run `npm run release:verify-upload -- <promotion-directory>` immediately before upload; it rechecks source, migration/archive inputs, staged members, production configs and every bundle file. `npm run release:prepare-upload` can reproduce a fresh directory locally from verified archives. It extracts each approved member, asks the pinned Wrangler to bundle each production-configured Worker with `--dry-run --outdir`, and records archive, configuration, source and resulting bundle digests in `upload-manifest.json`. The preparer makes no Cloudflare upload. `--allow-dirty` is a local exercise mode only and marks `promotion_ready: false`.

The prepared `op/bundle/shim.js` and `userinfo/bundle/shim.js` are the entrypoints for a reviewed `wrangler versions upload <entry> --no-bundle --config <production-config>` operation. The OP upload must preserve both `OP_PRIVATE_JWK` and `MIKAKI_READY_TOKEN` using the reviewed `--secrets-file`; verify both Workers' binding inventories and version IDs before activation. Use a non-activating version upload first, then qualify and activate the exact IDs. [Wrangler documents](https://developers.cloudflare.com/workers/wrangler/commands/workers/) `versions upload` as uploading without immediate deployment, and `--no-bundle` as skipping its internal build. The local dry run checks that both generated bundles can be read with `--no-bundle`; no version was uploaded here. Record the hashes of the actual upload inputs and the Cloudflare-returned version IDs together. The preparer alone cannot attest the remote bytes or settings.

In a clean checkout of the independently selected release commit, download the matching `attested-worker-<commit>` artifact into `artifacts/`. Set `release_commit` to that independently reviewed commit, then verify all five provenance subjects:

```sh
gh attestation verify artifacts/release-manifest.json -R masanork/mikaki \
  --signer-workflow masanork/mikaki/.github/workflows/supply-chain-build.yml \
  --source-digest "$release_commit" --deny-self-hosted-runners
gh attestation verify artifacts/login-assets.json -R masanork/mikaki \
  --signer-workflow masanork/mikaki/.github/workflows/supply-chain-build.yml \
  --source-digest "$release_commit" --deny-self-hosted-runners
gh attestation verify artifacts/mikaki-worker.tar.gz -R masanork/mikaki \
  --signer-workflow masanork/mikaki/.github/workflows/supply-chain-build.yml \
  --source-digest "$release_commit" --deny-self-hosted-runners
gh attestation verify artifacts/mikaki-userinfo-claim-worker.tar.gz -R masanork/mikaki \
  --signer-workflow masanork/mikaki/.github/workflows/supply-chain-build.yml \
  --source-digest "$release_commit" --deny-self-hosted-runners
gh attestation verify artifacts/promotion-*/upload-manifest.json -R masanork/mikaki \
  --signer-workflow masanork/mikaki/.github/workflows/supply-chain-build.yml \
  --source-digest "$release_commit" --deny-self-hosted-runners
npm run release:verify
promotion_dir=artifacts/promotion-REPLACE_WITH_DOWNLOADED_DIR
npm run release:verify-upload -- "$promotion_dir"
```

Also verify the archive SBOM/CBOM attestations in [supply-chain evidence](supply-chain.md). The source-digest and runner constraints are documented by the [GitHub CLI](https://cli.github.com/manual/gh_attestation_verify). Local `create --allow-dirty` / `verify --allow-dirty` commands are available for development inspection only; their manifest explicitly records `clean: false` and is unsuitable for promotion. Do not regenerate a downloaded manifest to make an unsuccessful verification pass.

## Activation record

Before activation, prepare one restricted operations record containing:

| Evidence | Required record |
| --- | --- |
| Build | Reviewed commit, verified archive/manifest digests, attestation identity and CI run |
| Environment | Exact account, Worker names, issuer, D1 IDs and R2 buckets; no secret values |
| Schema | Before/after migration lists and hashes; current backup bookmark and its usable restore window |
| Configuration | Active runtime-policy generation/revisions, registered RP revision, disabled/enabled optional features |
| Secrets and bindings | Required secret names and binding presence; independently escrowed key versions and retirement rules |
| Deployment | Actual Cloudflare version IDs, route activation time and previous compatible version |
| Qualification | Timestamped owner-device save/reopen/transfer, complete RP callback, session check and logout denial/delivery |
| Rollback | Compatible code version, schema compatibility decision, preserved authority and post-rollback smoke evidence |

Follow the environment-specific [deployment procedure](cloudflare-deployment.md). A successful `/health` proves only that its handler runs. Discovery/JWKS and migration-list checks do not prove account enrollment, schema-dependent token writes, service bindings, R2 retrieval, or logout delivery. Qualify those concrete positive/negative paths against the recorded version. An archive manifest does not identify the bytes Cloudflare actually serves; promotion and runtime-version mapping remain unfinished.

The OP's `/version` response returns Cloudflare's Worker version ID, the embedded Git commit and whether the source checkout was clean when the Wasm was compiled. It sets `Cache-Control: no-store` and fails with 503 if the version-metadata binding is missing. The new `/ready` requires `Authorization: Bearer <MIKAKI_READY_TOKEN>` and returns 404 with no body for absent or invalid credentials before touching R2, D1 or the Claim Worker. An authorized check returns 204 or 503 with no body. It checks a valid active runtime policy, the build's latest D1 migration, a private signing key matching an active public key, issuer/version metadata, a metadata-only R2 HEAD for `__mikaki_readiness__/r2-head` in the Vault bucket, and an internal Claim Worker schema query over the service binding. An absent probe object is healthy; no sentinel is created. An R2 error or a HEAD pending for three seconds returns 503. The complete authorized dependency probe has a five-second deadline, so a pending D1 query or Claim Worker response also returns 503. The three-second R2 timeout still applies within that overall deadline. Timed-out Rust futures are dropped; this does not guarantee cancellation of the underlying platform request. All probes remain read-only. It does not write D1/R2, read object bodies, qualify ciphertext read/write permissions or bucket identity, verify recipient secret material, exercise a real token exchange, or prove alert delivery.

For a version-aware public check, provision the same 32-byte base64url `MIKAKI_READY_TOKEN` as an OP Worker secret and a GitHub Actions repository secret, then run the [production smoke workflow](../.github/workflows/production-smoke.yml) with **both** `expected_version_id` (from the reviewed Cloudflare activation record) and `expected_source_commit` (from the verified release manifest). It checks health/Discovery/JWKS, exact version/clean-commit agreement and authenticated `/ready` = 204, then retains `production-smoke.json` as run evidence. Omitting both inputs keeps the legacy reachability-only check; supplying only one fails. The `/version` and `/ready` endpoints have not been deployed as of this review.

The embedded source commit and Cloudflare version ID identify the source checkout and active Cloudflare version; they do **not** prove that Cloudflare received the archive whose digest was attested. The prepared bundle inventory provides the local archive-to-upload-input link, but the promotion operator must independently record the exact uploaded bytes/version IDs, binding inventory and activation event before claiming a runtime-to-artifact link. The internal UserInfo Claim Worker also needs an independently recorded version. Do not infer it from the OP's public response.

Code rollback keeps the current database and authority. Do not automatically reverse migrations or restore an older DB to accompany older code. If the chosen version cannot operate on the current schema, keep authentication unavailable until a reviewed compatible version or forward repair is ready. Reapplying old policy must not re-enable retired keys or revoked grants.

## Backup boundary

Account login and encrypted Vault recovery are separate. The supported user path is retention of usable Passkeys and, where needed, explicit transfer of each saved name/note to another PRF-capable credential. Multiple synced credentials do not prove independent recovery paths. Losing every usable Passkey has no account recovery path; restoring ciphertext cannot replace its PRF secret. See [ADR 0005](adr/0005-invitation-bootstrap-and-recovery.md).

Operator backup must cover more than D1:

| Component | Required protected backup and verification |
| --- | --- |
| D1 | A usable bookmark or independently protected export, schema/revision inventory and security audit reconciliation source |
| Vault R2 | Every nondeleted head's immutable object, object key/digest, and owner envelope at the matching DB boundary |
| Secrets | OP signing-key history, claim/agent recipient keys where active, binding configuration and rotation state; outside public CI artifacts |
| Authority outside restore | Recovery generation or equivalent external fencing, independent revoked/deleted credential/client/grant records, and RP invalidation procedure |

D1 [Time Travel restores a database in place](https://developers.cloudflare.com/d1/reference/time-travel/); it does not supply the separate Vault objects or key material. The current Vault GC deletes unreferenced objects older than 24 hours. An old D1 bookmark can therefore refer to already removed ciphertext. D1 history retention alone is not the Vault recovery window.

For a rehearsed backup, isolate the environment, quiesce writes and GC for the capture boundary, record the DB bookmark/export, copy all referenced immutable objects to independently retained storage, verify every expected digest, and record completion before resuming. Do not place private keys or production DB contents in Actions artifacts. A live incremental snapshot/retention service and a tested external recovery fence are not implemented here.

## Historical restore gate

1. Keep ingress, authentication, issuance, protected resource access and background jobs fenced outside the restored database. Save the current boundary and incident evidence before destructive restore.
2. Establish a new externally retained recovery generation before accepting traffic. The current product does not implement this fence; leave the activation gate closed until an equivalent reviewed mechanism exists.
3. Restore the intended DB and matching object set, validate the migration ledger, integrity, foreign keys and object digests, and apply a reviewed forward migration plan while still isolated.
4. Reconcile account, credential, administrator, client, connection, sharing and recipient-key state against independent authoritative records. Preserve closed bootstrap and all disable/revocation decisions. An old DB is not that independent record.
5. Invalidate restored SSO, codes, access/refresh tokens, management/registration continuations, agent/OAuth grants and derived RP sessions; rotate or fence keys as the incident requires. Recheck persistent replay records and logout delivery state. Blindly resetting tables is not a reconciliation procedure.
6. Prove old credentials/tokens/grants stay denied, independent new authentication works, saved ciphertext reopens with its actual intended credential, and RP sessions/logout agree. Record the actual version, restore boundary and reconciliation decisions before reopening ingress.

Historical restore can revive authority that was revoked after the snapshot. The local exercise explicitly demonstrates that old SSO and credential bits return, and reports `production_restore_ready: false`. No production restore or ingress-fencing automation is supplied by this change.

## Local exercise and its limits

```sh
npm run test:release
```

The release tests substitute archive and SQL bytes, unexpected/duplicate/linked members, source commits, tracked/untracked inputs and migration gaps. The [migration exercise](../scripts/migration-recovery.test.ts) uses a disposable SQLite database and ciphertext file, applies migrations `0001`–`0013`, seeds an encrypted head, audit and closed bootstrap, takes a real SQLite backup, then applies all remaining checked-in migrations. It verifies preserved rows and integrity, rollback after a later failing statement, restoration/upgrading of the backup, successful AEAD reopening of matching ciphertext, and rejection of missing/corrupt objects. It also demonstrates resurrection of historical revoked state. Temporary fixture DBs/objects are removed; only the secret-free summary `artifacts/migration-recovery.json` is retained by CI.

This checks SQL/data compatibility and a local backup round trip. It does not emulate D1 Time Travel, distributed consistency, R2 permissions/GC, production credential removal, signing-key escrow, binding preservation, RP logout, runtime byte promotion or real device recovery. The production recovery gate remains open.

## Monitoring and incident evidence

Before user activation, assign an operator and prove notification delivery for these signals: issuer/public-endpoint failure, schema-dependent login/token/session-check error rates, Vault object/digest failures, missing/corrupt active policy, absent signing/recipient keys or service bindings, and backlog/permanent failure/deadline exhaustion in the logout outbox. The outbox thresholds in [OIDC operations](oidc-operations.md) are design requirements; public smoke and this local rehearsal do not prove an alert is wired.

For an incident, record environment/version, first/last affected timestamps, route/status/error class, active schema/policy revision, affected capability and containment/recovery decisions. Exclude cookies, tokens, assertions, plaintext notes and private keys. Retain sufficient independent revocation/audit evidence for the intended restore window. Qualification requires an injected failure reaching the responsible operator and a measured recovery/denial result, not only a dashboard screenshot.

## Automatic production deployment

On a push to `main`, `local-authentication-slice` waits for `verify` and the reusable signed `supply-chain-build` to succeed, then calls `deploy-production`. Pull requests and manual CI runs do not deploy. The deployment job downloads this run's `attested-worker-<commit>` artifact, verifies GitHub attestations against the exact source digest, `main` ref and supply-chain signer workflow, and rechecks the release and upload inventories. It promotes the prepared bundles with `--no-bundle`; it does not rebuild them.

The GitHub `production` environment allows only the `main` branch. Its secrets are `CLOUDFLARE_API_TOKEN`, `OP_PRIVATE_JWK` and `MIKAKI_READY_TOKEN`. The repository readiness secret is also used by the reusable public smoke workflow. These secrets are configured separately from source control. Main CI runs and production promotions are not cancelled by newer pushes; an older run skips promotion if application files have changed on main. The four metrics-bot output files are the only permitted newer changes because that bot's GITHUB_TOKEN commits do not trigger CI.

Pending D1 migrations stop promotion before upload. Reconcile the schema using the reviewed migration/backup procedure in this runbook, then rerun the failed CI jobs. The flow stages both Workers, verifies their configured DB/R2/service/Secrets Store/runtime secret bindings, activates Claim Worker followed by OP at 100%, and synchronizes each production configuration's triggers. `production-deployment-<commit>-<attempt>` records previous deployments and which versions were activated, including partial failures. A failure does not automatically roll back either Worker or the database; use the recorded version IDs and the compatibility procedure in this runbook.

The final reusable `production-smoke` job checks the exact OP version, clean source commit, signed login asset hashes, readiness, Discovery/JWKS and native association. A failed smoke marks CI red after activation and requires investigation; it does not qualify an owner Passkey ceremony or a completed relying-party login. Deployment and smoke artifacts are retained for 30 days.

## 0031 reconciliation recovery boundary

The [bounded 0031 reconciliation procedure](cloudflare-deployment.md#manual-reconciliation-of-reviewed-migration-0031)
records its source/DB/migration hashes, pending state, schema fingerprint,
Time Travel timestamp and bookmark before applying. The same timestamp is read
back to confirm the service returns the same bookmark. The apply step checks
that record is less than two minutes old and the reviewed ledger/schema state
still matches. This verifies a currently readable recovery coordinate; it is
not a restore rehearsal, an export, or proof of a quiesced database boundary.

The sanitized preflight artifact is retained before any write; a separate result
artifact distinguishes verified completion from an uncertain attempted operation.
Copy the record/run URL to the restricted activation record. Actions artifacts
are requested for 30 days, but repository retention limits/deletion still apply.
Artifact retention does **not** extend D1 Time Travel retention. Cloudflare
[documents](https://developers.cloudflare.com/d1/reference/time-travel/) up to
30 days for Workers Paid and 7 days for Workers Free. The bookmark response does
not establish this account's plan or usable retention window; verify and record
those independently. A bookmark is not an access credential, but keep recovery
records under the existing operations access rules.

0031 is additive and does not modify prior application rows. A code rollback
normally leaves these tables and the current migration ledger in place, subject
to the existing code/schema compatibility review. A database restore would
overwrite the whole database and could lose later legitimate writes or revive
revoked authority; it requires the historical restore gate above and separate
explicit authorization. The bookmark does not back up R2 objects, signing keys,
Passkey PRF material or an external revocation/recovery fence. It provides no
proof of complete Vault recovery. No table drop, ledger repair, restore, Worker
rollback or deployment is automated by this reconciliation workflow.
