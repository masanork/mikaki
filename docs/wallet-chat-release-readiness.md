# Wallet and Chat release readiness

The release candidate is based on main, rather than the older Work workspace
snapshot. The normal entry exposes Wallet and Chat. Existing native WebView
account authentication, age predicates, eight-credential receipt and explicit
presentation consent remain in place.

## Candidate validation

- Ordinary and opt-in Chat Workers build separately. `npm run test:wallet-chat`
  exercises both compile/runtime gates and the native two-destination UI.
- The main-based browser test completes two-owner enrollment, fingerprint review,
  invitation approval, encrypted delivery, Wallet handoff, draft protection,
  reopen and lock. Missing local state does not generate a replacement device.
- Both compile profiles package `crates/worker/service/entrypoint.ts` beside
  their own Rust shim. The product journey uses the emitted `service.mjs`, and
  package boundary tests exercise all seven named entrypoints, public HTTP
  denials, raw authority RPC denials and allowed catalogued Agent/Claim access.
- After the product tests, `npm run qualify:messaging-package` requires a clean
  checkout, performs a local Wrangler dry run, checks the complete module size
  and exact named exports, and checks the running service's compile profile and
  source revision. CI retains `messaging-package-<attempt>/summary.json` with
  archive-member and Chat asset hashes. The beta release inventory incorporates
  this evidence and rejects a different archive, runtime profile or asset set.
- Release inventory version 2 explicitly selects `default` or `messaging-beta`.
  Verification reads retained profile exports from the optimized Wasm module
  without executing archive JavaScript. Ordinary releases exclude generated
  `chat/` static assets. Beta candidates require exactly the qualified browser
  client and crypto module and stage those bytes with the complete service.
- `chat-release-candidate` builds and tests the beta release in PR/main CI.
  The required `verify` lane includes this candidate and rejects its failure,
  cancellation or skipped result before the existing branch check can pass.
  Its artifact is `release-candidate-messaging-beta-<commit>`. After the main
  qualification gates, `chat-supply-chain` rechecks and attests it as
  `attested-worker-messaging-beta-<commit>`, including the browser Rust SBOM
  and profile-specific cryptography inventory. PRs receive no signing authority.
  Actual attestation still needs the merged main run to finish successfully.
- Both release profiles use the same archive preparation and byte verification.
  A beta upload has `promotion_ready=false`; ordinary production rejects it and
  requires default-profile login assets. Creating or attesting a beta candidate
  neither applies Chat migrations nor enables the runtime flag.
- Chat ingress uses its own policy and counters, with default limits of 600
  admissions per source and 2400 per deployment per minute. The product journey
  runs with these defaults and the ordinary authentication limits. Exhaustion,
  capacity, concurrent isolates, storage failure and bounded-expiry checks are
  included in `npm run test:messaging-beta`.
- Production evidence below is bound to its exact source revision. A later
  promotion still requires its own passing qualification, signing and deploy run.
- Native Rust and UI checks cover existing batch/age/one-use receipt and consent
  behavior. Ordinary test screenshots go under ignored `local/generated/`.
- CI and physical-device results are distinct from these local checks.

## Physical checkpoint: 2026-10-20

A signed candidate was installed on a Pixel 10 Pro using an in-place update.
Its signing certificate matches the previously installed app. Cold launch opens
Wallet; Wallet/Chat navigation and settings/return work on the physical device.
No app storage was cleared. These checks do not qualify card receipt, Passkey/PRF,
encrypted delivery or presentation to a real verifier.

The candidate has no compiled `MIKAKI_HAIP_WALLET` operator configuration, so the
HAIP receipt task stays hidden. A qualified receipt build must include the
reviewed public issuer/attester trust configuration described in
[native wallet issuance](identity-card-issuance.md#opt-in-native-wallet-issuance-commands-and-ui).
Do not enable the task by bypassing that native trust check.

## Production checkpoint: 2026-10-22

The qualified deployment record for Worker `mikaki-auth` on `auth.mikaki.org`
and its [main CI run](https://github.com/masanork/mikaki/actions/runs/39709189220)
establish:

- Activated default-profile Worker version:
  `18e5bf6f-ebbc-4da9-bf72-ef225c6e5604`, serving 100% of traffic from clean source
  `6a5142e9687fcece02e643b15b80ebb69b397cf8`.
- All 29 jobs passed on attempt 2, including both release profiles' signing,
  deployment and production smoke. SonarCloud's main Quality Gate passed for
  that exact source. Both beta manifest attestations were independently verified
  against the same source, signer workflow and main ref.
- After the compatible normal Worker was deployed, the three pinned Chat
  migrations were applied once through `wrangler.messaging-migrations.jsonc`.
  The dedicated `messaging_schema_migrations` ledger contains the exact chain;
  no Chat migration remains pending. The remote schema audit reports
  `applied:3`, `complete:true`, and foreign-key validation passed.
- A Time Travel bookmark was recorded privately before the first ledger
  operation. Pre/post hashes match for the Owner schema and migration ledger,
  credential ownership/status and stable Passkey material. Mutable authentication
  counters were outside the stable-material comparison.
- The [post-migration production smoke](https://github.com/masanork/mikaki/actions/runs/39720844487)
  passed both jobs. It verified the same Worker/source and login JS/CSS hashes,
  public endpoints, protected readiness and font rendering after the DB change.
- Live version metadata still matches the reviewed normal configuration.
  `MESSAGING_BETA_ENABLED` and `MESSAGING_ISSUER_KEY` bindings are absent;
  Chat remains disabled. No Chat key values were read or provisioned.

Refresh schema and deployment observations before promotion. This checkpoint
qualifies the remote schema rollout; beta activation, populated rollback,
two-person delivery and real-device issuance remain unqualified.

## Chat activation dependencies

Keep Chat disabled until the following work is qualified together:

1. Qualify the merged main run's explicit beta release candidate and its trusted
   attestations. The candidate path now binds the compile profile, complete
   service upload and generated Chat assets. A protected beta promotion path
   must still combine this evidence with the schema, key and rollback gates
   below before it can accept the candidate for activation. Ordinary promotion
   deliberately accepts only the default profile.
   The manual `chat-beta-preflight` workflow supplies the read-only first stage
   described below; it does not upload a version or authorize activation.
2. Apply the reviewed messaging migration chain, including
   `0003_ingress_budget.sql`, using the separate migration-only configuration and
   `messaging_schema_migrations` ledger. The exact production schema audit now
   accepts the complete, byte-pinned Chat chain alongside Owner and optional
   Work. Incomplete/unknown chains remain rejected by ordinary promotion.
   `npm run check:chat-schema -- --remote` is read-only and accepts exact prefixes
   for preflight; it refuses existing multiple device heads before the unique
   index. Deploy the compatible normal Worker before an approved remote apply,
   following the [schema rollout procedure](chat-schema-rollout.md). The
   2026-10-22 production checkpoint qualified remote application and parity for
   the current three-file chain; recheck that state before beta promotion.
3. Provision the independent Ed25519 signing key through the existing protected
   secret/version workflow. Check the public key and same-origin configuration
   without exposing its private component. The compile feature and
   `MESSAGING_BETA_ENABLED=true` must agree with the staged artifact.
4. Rehearse disable and code rollback after actual enrollment and delivery on a
   disposable environment. Verify that login still works, messaging routes close,
   existing rows/history remain, and re-enabling resumes the same device and
   conversation. The Chromium product journey now checks this on the same local
   D1 store: it retains an undelivered encrypted message, disables the beta without
   its key, loads the ordinary compiled Worker with beta settings/key still
   present, and re-enables the original beta. No reset or repeated migration is
   used. Schema, Owner credentials/key wrappers, device/channel rows, queued
   ciphertext and encrypted browser records remain unchanged while closed;
   re-enabling receives the queued message and replies without device enrollment.
   Normal ingress counters are outside the data-preservation comparison.
   `messaging-populated-rollback-<attempt>` retains the source-bound, sanitized
   result. SSO and PRF remain fixtures; this local rehearsal does not qualify a
   remote Workers version rollback, distributed D1 behavior or physical Passkey
   use. Those operational/device checks remain required before activation.
5. Qualify real Passkey/PRF, two-person messaging, restart, lock, missing local
   profile, Chat-to-native presentation and card receipt on supported devices.

The 2026-10-20 E2EE handoff referred to conflicted snapshot `00990d83`. Those
conflicts are resolved, and the release branch is based on main. The normal entry
is `OwnerVaultSession` → `ProductWorkspace` → `ProductChat` → the canonical
`ui/messaging` runtime; probe wrappers reuse that runtime. There is no competing
`ui/chat` implementation or ordinary `0004_messaging.sql`. Keep these bounded
release tasks ahead of adding more recovery permutations.

The [D1 migration documentation](https://developers.cloudflare.com/d1/reference/migrations/)
allows a custom migration directory and ledger table. Worker code rollback does
not remove migrated data. Disabling Chat must retain its tables and stop new
messaging requests; do not reset owner credentials or native Wallet storage.

The first credential remains Mikaki's existing linked-document attribute
credential. Passport reading, municipal/employer issuance and additional issuers
are subsequent integrations, as described in [the MVP scope](wallet-chat-mvp.md).

## Protected Chat candidate preflight

After merging this workflow, wait for a successful push-to-main CI run at the
current main commit, then dispatch `chat-beta-preflight` on `main` with that
run's `main_ci_run_id`. The job uses the existing `production` environment and
its Cloudflare credential. It receives no runtime signing keys or secret-writing
step. It has its own concurrency group, so reading production does not displace
an ordinary pending deployment.

The preflight rejects PR/fork/manual CI candidates, incomplete or unsuccessful
runs, expired or ambiguous artifacts, dirty source, and a main application that
advances during inspection. It downloads only the selected run's
`attested-worker-messaging-beta-<commit>` artifact, verifies the release, login,
three Worker archives and upload manifest against the trusted signing workflow,
exact source digest and main ref, then rechecks all prepared bytes with the
explicit beta profile. It separately requires the latest main Sonar analysis to
match that exact source and its quality gate to be `OK`; the advisory scanner
job's completion alone is insufficient. It does not build or execute
artifact-supplied JavaScript.

Production must still serve the same source at a single 100% OP version, with
bindings matching the normal reviewed configuration and no Chat flag or issuer
key. Read-only SQL validates Owner, optional Work, and the complete three-file
Chat schema and foreign keys. No migration-list or apply command runs. Deployment,
candidate/run identity, and source are checked again after the audit; a concurrent
change causes failure. This is a point-in-time observation and must be refreshed
before a later staging or activation operation.

Only `artifacts/chat-beta-preflight/report.json` is retained as
`chat-beta-preflight-<commit>-<attempt>` for 14 days. Failures retain a stage name,
without assertion diffs, API bodies, subprocess output, binding values or DB rows.
A passing `mikaki-chat-beta-preflight-v1` report always has
`promotion_ready=false` and `mutations=false`. Protected key staging/public-key
verification, remote populated rollback, physical Passkey/PRF and two-owner
qualification, and the protected activation path remain explicit pending work.
No report is accepted as authorization by ordinary promotion.

The [2026-10-23 production preflight](https://github.com/masanork/mikaki/actions/runs/39923082806)
passed for clean source `065e9f007d91d4ddb766cb77a7ed63679e2f83ed` and successful
main CI `39917244237`. Its six attested subjects, candidate bytes, exact main
Sonar gate, disabled OP baseline and complete three-file Chat schema matched.
It made no production changes. This is historical evidence; refresh it at the
source selected for any later operation.

## Protected Chat key staging

The manual [chat-beta-stage-key workflow](../.github/workflows/chat-beta-stage-key.yml)
prepares an independent Ed25519 issuer key without activating a Worker version.
It runs only on this repository's `main`, uses the existing `production`
environment, and shares ordinary OP promotion's `production-deployment` lock.
It first repeats the complete candidate preflight at the selected successful
push-to-main CI run. The key is exposed only to the subsequent custody step.
There is no key-generation, secret-registration or dispatch step on merge.

Prepare custody outside the checkout with the
[key generator](../scripts/messaging-issuer-key.ts). Supply an absolute path to a
new private file. It creates the file exclusively with mode 0600, creates new
parent directories with mode 0700, and prints only its path, public JWK,
RFC 7638 thumbprint and runtime key ID. Retain the private file in the operator's
protected custody; the generator does not register it anywhere or overwrite a
previous file. Provision its canonical `{"kty":"OKP","crv":"Ed25519","x":...,"d":...}`
as the `production` environment's `MESSAGING_ISSUER_KEY` Actions secret through
the operator's existing secret-management process. Do not put the private JWK
in workflow inputs, source, issues, screenshots or artifacts.

Dispatch inputs are the exact successful main CI run ID, the reviewed active OP
version UUID, and the independently reviewed 43-character public `x` value.
[The staging script](../scripts/stage-chat-beta-key.ts) refuses a missing key,
ambiguous/noncanonical JWK, wrong algorithm, mismatched seed/public pair or
different public pin before any write. It checks the same fresh preflight,
candidate/run and actual main Sonar analysis. The active baseline must remain a
single 100% ordinary version with no Chat flag or key; workers.dev and version
preview URLs must both be disabled. The latest uploaded version must initially
be that exact active version. Another pending upload requires operator review.

The only writes are two `wrangler versions secret bulk` calls with JSON over
stdin. The first creates an inactive clone containing the Chat key. The second
creates a key-free inactive successor, because Cloudflare can inherit omitted
secrets from the latest upload. The original key-bearing version remains
available by its recorded UUID. No existing version's secrets are edited, and
neither call changes active traffic. Before and after each write, the script
checks current source, active deployment, preview exposure and latest upload.
Each resulting version must retain the baseline script ETag, runtime and every
original binding, with only the permitted Chat secret addition/removal.
See Cloudflare's [version secret commands](https://developers.cloudflare.com/workers/wrangler/commands/workers/#versions-secret-bulk)
and [secret inheritance](https://developers.cloudflare.com/workers/configuration/secrets/#upload-secrets-alongside-code).

Writes are never retried. A timeout, changed latest upload, unknown returned ID
or failed verification retains a sanitized failed report with the attempted
stage and any confirmed version IDs; it never automatically deletes secrets,
activates or rolls back traffic after an uncertain outcome. Inspect metadata
before any further operation. The workflow serializes repository promotions;
operators must also avoid concurrent dashboard/API uploads. A successful run
leaves an inactive successor, so a repeat stage requires a fresh ordinary
promotion first rather than modifying an unreviewed latest upload.

Only the preflight and `mikaki-chat-key-stage-v1` reports are retained for 14
days. The key-stage report includes public material and confirmed inactive
version IDs, always with `active_change_requested=false` and
`promotion_ready=false`. Local public/private consistency plus a successful
secret write does not prove a remote signing ceremony: the report explicitly
keeps `remote_public_key_verified=false`. Remote same-origin configuration and
public-key verification, populated rollback, real Passkey/PRF and two-owner
acceptance, and protected beta activation remain separate gates. This workflow
does not execute a beta artifact, enroll users, migrate, write D1/R2 or enable
Chat. Ordinary promotion remains default-profile-only.

## Offline release candidate checks

The beta candidate builder archives `build-messaging-beta`, after the actual
product/ingress checks and `npm run qualify:messaging-package`. It supplies
`--profile messaging-beta` explicitly to `release:inventory`, `release:verify`,
`release:prepare-upload` and `release:verify-upload`. Omitting that selection
requires a default-profile Wasm module. A dirty checkout requires the existing
explicit local option and cannot produce a production-ready upload.

The release inventory binds all owner migration bytes and the complete static
asset tree selected for the profile. A beta inventory additionally binds all
three reviewed Chat SQL hashes, the separate ledger name and migration-only
configuration bytes. It does not apply SQL. Remote Chat schema/ledger parity
remains an activation prerequisite. Reusing a beta candidate in ordinary
deployment fails before Cloudflare operations.

## Chat ingress behavior

`messaging_resource_policy` and `messaging_request_window` are beta-only tables.
They neither read nor change `auth_resource_policy` or `auth_request_window`.
Both per-source and deployment reservations succeed together; rejected requests
cannot leave a partial reservation. A full 10,000-row counter store permits
existing buckets to advance within their limits and rejects new buckets that
would exceed capacity. A transaction failure returns 503 without retaining a
partial reservation or sweep. Missing policy also returns 503, including the
authenticated Chat configuration preflight.

The edge-provided `CF-Connecting-IP` is hashed with a Chat-specific domain tag;
the address itself is not persisted or logged. Missing addresses share one
source bucket. Cookies and forwarded-address headers cannot create more buckets.
The dynamic `/messaging/` API retains its 429/no-store/Retry-After response;
the three lazy browser assets do not consume API reservations.

Each admission transaction and enabled beta scheduled sweep removes at most
1000 counters older than 120 seconds, using the expiry index. Chat sweep failure
does not prevent authentication collection. Disabled and ordinary builds do not
require these tables. These checks establish independent admission state, not
dedicated database or CPU capacity; production load qualification remains part
of promotion.
