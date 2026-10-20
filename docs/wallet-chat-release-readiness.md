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
  and exact named exports, and records module/Chat asset hashes with the source
  commit. CI retains `messaging-package-<attempt>/summary.json`. This evidence
  does not replace the production promotion inventory or attestation.
- Chat ingress uses its own policy and counters, with default limits of 600
  admissions per source and 2400 per deployment per minute. The product journey
  runs with these defaults and the ordinary authentication limits. Exhaustion,
  capacity, concurrent isolates, storage failure and bounded-expiry checks are
  included in `npm run test:messaging-beta`.
- The main run for `2c139b07` completed the three-browser CI graph, Sonar analysis
  and production smoke. A later promotion still requires its own passing run.
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

Read-only inspection of account `4b749427a0c80c547e726a42aff4b6fc`, Worker
`mikaki-auth` on `auth.mikaki.org`, found:

- Public Worker version: `331acab4-ee46-4d57-a373-b6ac7a090ca1`, clean source
  `2c139b075032881f7d117a497fa6cf4a7c9af061`.
- PR #278 merged as `22003c16`. Its main run passed product checks and Sonar,
  but dependency audit found RUSTSEC-2026-0382 and production promotion was
  skipped. Qualify the patched dependency graph before the next promotion.
- The 2026-10-20 secret-name inspection did not include `MESSAGING_ISSUER_KEY`.
  No secret values were read.
- This ingress change has not applied Chat migrations, uploaded keys or
  activated Chat in production.

Refresh these observations before promotion. They do not establish the presence
or shape of any Chat tables, browser/device compatibility, or current load limits.

## Chat activation dependencies

Keep Chat disabled until the following work is qualified together:

1. A source-bound release path must still build the `messaging-beta` feature and
   include the generated `assets/chat/client.js` and `crypto.wasm` in its
   attested static asset inventory. The ordinary release builds without this
   feature, even if a runtime flag is set. Include the package qualification's
   commit-bound hashes and complete service upload measurements in that evidence.
2. Apply the reviewed messaging migration chain, including
   `0003_ingress_budget.sql`, through a separate configuration
   and migration ledger. Preserve the owner migration directory/ledger. Inspect
   existing device rows before the unique one-device-per-owner index is applied.
   Extend the exact production schema audit to validate the separately reviewed
   Chat schema and its ledger. The current owner/Work schema comparison does not
   allow these extra tables. Applying them ahead of that release-path change
   would block later normal promotions.
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
