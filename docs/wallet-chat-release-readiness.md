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

## Production checkpoint: 2026-10-20

Read-only inspection of account `4b749427a0c80c547e726a42aff4b6fc`, Worker
`mikaki-auth` on `auth.mikaki.org`, found:

- Current deployment: `eb40a0e9-9518-46c4-bd65-d11e07a2ee65`, source
  `c253a7babdcb53b4f876c1b0abbd71d4d188fffa`.
- The ordinary owner migration list reports no pending migrations.
- Secret names do not include `MESSAGING_ISSUER_KEY`. No secret values were read.
- No Chat migration, key upload, Worker upload or activation was performed.

Refresh these observations before promotion. They do not establish the presence
or shape of any Chat tables, browser/device compatibility, or current load limits.

## Chat activation dependencies

Keep Chat disabled until the following work is qualified together:

1. A source-bound release path must build the `messaging-beta` feature and
   include the generated `assets/chat/client.js` and `crypto.wasm` in its
   attested static asset inventory. The ordinary release builds without this
   feature, even if a runtime flag is set.
2. Apply the reviewed messaging migration chain through a separate configuration
   and migration ledger. Preserve the owner migration directory/ledger. Inspect
   existing device rows before the unique one-device-per-owner index is applied.
3. Extend the exact production schema audit to validate the separately reviewed
   Chat schema and its ledger. The current owner/Work schema comparison does not
   allow these extra tables. Applying them ahead of that release-path change
   would block later normal promotions.
4. Provision the independent Ed25519 signing key through the existing protected
   secret/version workflow. Check the public key and same-origin configuration
   without exposing its private component. The compile feature and
   `MESSAGING_BETA_ENABLED=true` must agree with the staged artifact.
5. Qualify real Passkey/PRF, two-person messaging, restart, lock, missing local
   profile, Chat-to-native presentation and card receipt on supported devices.

The [D1 migration documentation](https://developers.cloudflare.com/d1/reference/migrations/)
allows a custom migration directory and ledger table. Worker code rollback does
not remove migrated data. Disabling Chat must retain its tables and stop new
messaging requests; do not reset owner credentials or native Wallet storage.

The first credential remains Mikaki's existing linked-document attribute
credential. Passport reading, municipal/employer issuance and additional issuers
are subsequent integrations, as described in [the MVP scope](wallet-chat-mvp.md).
