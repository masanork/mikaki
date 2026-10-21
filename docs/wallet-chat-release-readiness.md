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
- The main run for `276ef361` completed the three-browser CI graph, Sonar analysis,
  signing, deployment and production smoke. A later promotion still requires its
  own passing run.
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

## Production checkpoint: 2026-10-21

The qualified deployment record for Worker `mikaki-auth` on `auth.mikaki.org`
and its [main CI run](https://github.com/masanork/mikaki/actions/runs/39537412997)
establish:

- Activated Worker version: `1b55c367-4b2c-4326-9c3d-1577f2101f38`, clean source
  `276ef3618ec24d00979c361d28b6650c66b40f62`.
- All 27 active jobs passed, including signing, deployment and the public
  endpoint/login-asset smoke. SonarCloud's main Quality Gate passed.
- The #281 certificate-trust advisory fixes and #282 independent Chat admission
  are qualified by that run. It supersedes the `2c139b07` deployment, after the
  earlier #278 promotion had been blocked by RUSTSEC-2026-0382. Every later main
  revision still requires its own qualification.
- The 2026-10-20 secret-name inspection did not include `MESSAGING_ISSUER_KEY`.
  No secret values were read.
- This ingress change has not applied Chat migrations, uploaded keys or
  activated Chat in production.

Refresh these observations before promotion. They do not establish the presence
or shape of any Chat tables, browser/device compatibility, or current load limits.

## Chat activation dependencies

Keep Chat disabled until the following work is qualified together:

1. Qualify the merged main run's explicit beta release candidate and its trusted
   attestations. The candidate path now binds the compile profile, complete
   service upload and generated Chat assets. A protected beta promotion path
   must still combine this evidence with the schema, key and rollback gates
   below before it can accept the candidate for activation. Ordinary promotion
   deliberately accepts only the default profile.
2. Apply the reviewed messaging migration chain, including
   `0003_ingress_budget.sql`, using the separate migration-only configuration and
   `messaging_schema_migrations` ledger. The exact production schema audit now
   accepts the complete, byte-pinned Chat chain alongside Owner and optional
   Work. Incomplete/unknown chains remain rejected by ordinary promotion.
   `npm run check:chat-schema -- --remote` is read-only and accepts exact prefixes
   for preflight; it refuses existing multiple device heads before the unique
   index. Deploy the compatible normal Worker before an approved remote apply,
   following the [schema rollout procedure](chat-schema-rollout.md). The remote
   apply and production parity verification remain pending.
3. Provision the independent Ed25519 signing key through the existing protected
   secret/version workflow. Check the public key and same-origin configuration
   without exposing its private component. The compile feature and
   `MESSAGING_BETA_ENABLED=true` must agree with the staged artifact.
4. Rehearse disable and code rollback after actual enrollment and delivery on a
   disposable environment. Verify that login still works, messaging routes close,
   existing rows/history remain, and re-enabling resumes the same device and
   conversation. The current disabled tests start without a Chat schema/key;
   they do not establish this populated-database rollback behavior.
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
