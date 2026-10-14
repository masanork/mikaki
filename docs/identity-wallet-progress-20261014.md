# Identity Wallet progress — 2026-10-14

This checkpoint advances Issues #116–#120 from main `a19d30d`. The measured
implementation is `e01f168`, with a clean checkout at the start of the official
Issuer run. The initial subsequent report edits changed documentation only. This checkpoint does not
activate Identity, submit certification or qualify physical cards/devices.

The 2026-10-15 follow-up selects [public issuer discovery](identity-test-deployment.md#public-issuer-discovery-activation--2026-10-15)
in the production configuration, with `IDENTITY_ISSUANCE_ENABLED=false` and no
card-trust secret. It adds a workerd check for public age-only metadata/JWKS and
closed issuance APIs, including stale-trust rejection. The official-suite hashes
below continue to qualify `e01f168`, not the follow-up deployment.

## Implementation changes

- HAIP authorization codes now expire after **60 seconds**, as required by
  [FAPI 2.0 section 5.3.2.1](https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.3.2.1).
  The public Wallet code lifetime remains 90 seconds. The HAIP policy version
  changes so previous PAR/grant/token authority cannot retain the older contract.
- SD-JWT VC type metadata now emits claim display **`label`**. OID4VCI credential
  metadata continues to emit **`name`**. These are different display contracts;
  [SD-JWT VC section 5.6.2](https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-19.html#section-5.6.2)
  requires the label. An actual workerd regression checks the type response.
- The existing attested promotion validator can select a first-party,
  `age_over_18`-only SD-JWT test profile with dedicated signing custody, the
  reviewed limiter and an exact, live licence trust-policy digest. Its preflight
  rejects ambiguous/private/unsupported/expired policies. The workflow supplies
  `IDENTITY_TRUSTED_KEYS` only when the reviewed config selects it. See the
  [activation contract](identity-test-deployment.md#first-party-age-activation-contract).
  At this checkpoint the canonical config selected the disabled preparation profile;
  the 2026-10-15 follow-up selects discovery with issuance explicitly closed.
- `--authorization-lifecycle` extends the existing 42-module Issuer selection
  with five inherited authorization/token modules while retaining the official
  plan's original ordering and variants. Targeted `--module` selection remains
  available; the extension is a selected checkpoint, not a full-plan mode.

## Official-suite evidence

The isolated three-container suite uses **v5.3.1** / source
`440eec8bac7b12b7389d7ca9cbc459b53507a443` and the checked-in image digests.
Its private MongoDB, network and loopback 9443 listener are separate from the
historical suite data. Requests and assertions are upstream; actual workerd
handles issuance and actual shared Rust handles Wallet presentation.

The initial five-module run on clean main `a19d30d` produced **8 PASS / 2 FAIL**.
Both failures were `ServerAllowedExpiredAuthorizationCode`: the unchanged
official module waited 62 real seconds, then the 90-second code still worked.
The same ten tuples on clean `eed6861` produced **10 PASS**, without changing
the suite clock or D1 expiry. The subsequent 84-run diagnostic found
**69 PASS / 15 FAIL**, with failures/warnings in the SD-JWT type-metadata
validators. The diagnostic began before the label correction; a subsequent local rebuild
finished before its final completion. It is retained as diagnostic-only, not an
immutable-artifact qualification or an aggregate to add to later passes.

The final clean-source **47 modules × 2 formats = 94 runs** all finished
**FINISHED/PASSED**, with zero FAILURE, WARNING or ERROR log entries. Fourteen
plan modules per format remain unselected in this run. The five additions are:

| Module suffix (`fapi2-security-profile-final-`) | SD-JWT VC | mdoc |
| --- | --- | --- |
| `ensure-response-type-code-idtoken-fails` | PASS | PASS |
| `ensure-response-type-token-fails` | PASS | PASS |
| `ensure-client-id-in-token-endpoint` | PASS | PASS |
| `ensure-holder-of-key-required` | PASS | PASS |
| `ensure-token-endpoint-fails-with-expired-auth-code` | PASS | PASS |

The selected OID4VP Wallet regression has **22 official passes**, zero unexpected
failures, plus **four host rejections awaiting real Wallet error-screen evidence**.
The invalid-signature and mismatched-client cases remain official WAITING/null
before separate cleanup; they are not conformance passes. Credentials are the
custom linked-document type; the suite's mdoc variant is not a government mDL claim.

Private evidence and public summary hashes:

| Evidence | Private relative path | SHA-256 |
| --- | --- | --- |
| Extended Issuer | `local/generated/haip-1791987830515-a4cf525b/summary.json` | `7e4f17cf29546570431b95af1f827f4707cf8b81b6f2b9597d9526049c571552` |
| SD-JWT Wallet | `local/generated/haip-wallet-1791988241285-10ffe762/summary.json` | `54ca853c072776655e4f78a00b0782e51314d5441e24082435659d8cabf3dc07` |
| mdoc Wallet | `local/generated/haip-wallet-1791988273294-0cdbafbb/summary.json` | `ec51612126d0365565d0f1da2b4aa06249d014595163a12f8a555effd578f832` |

The measured normal Worker JavaScript hash is
`55fa8662180384f16c87ed68fa28286272d313d80167a63e19309f19ded99d72`, and its
Wasm hash is `4ab980a2b6730de4e30c561383e0535457df15c845755fc1d9dabf529767eeaf`.
The normal Worker, its current authority facade and browser Wasm were built
locally. The browser artifact predates these Identity-only changes, which do not
change its dependency inputs. Earlier failure logs/artifacts are retained separately.

Four pinned eudi-dev host cases pass with no skips after the metadata fix. Six
credentials (public, standalone-attestation and JWT-attestation paths, each in
both formats) survive Wallet restart and complete encrypted presentation. The
unmodified HAIP CLI's incompatible certificate purpose is correctly refused;
positive HAIP paths use a disclosed test-only software-attester patch. Eighteen
bad key proofs and sixteen bad client-authentication requests are refused, while
subsequent legitimate issuance succeeds. This is host interoperability with
synthetic card/SSO/PKI, not an activated deployment or mobile hardware qualification.

Validation also passes: **124** shared Rust tests; **77** release/provisioning
regressions; **87** Identity contracts; the **four** ordinary issuance/UserInfo/age
integration tests; a further actual-workerd metadata/issuance regression and the
suite-backed issuance/Wallet integration; Node typecheck, formatting, docs links
and Worker byte budgets. OP Wasm is 8,062,965 raw bytes / 2,730,954-byte gzip
estimate, within the existing 8 MiB / 3 MiB limits. Initial fresh-worktree attempts
with missing Claims build/dependency/generated-policy prerequisites remain
separate logs and are not counted as successful tests.

Reproduce using the pinned Compose suite and freshly built OP/Claims/browser
artifacts, with a clean source revision embedded in the Worker:

```sh
node local/conformance/haip-issuer.ts --authorization-lifecycle
npm run test:identity-wallet-suite
MIKAKI_EUDI_ISSUANCE_CHECKOUT=/private/tmp/PINNED_EUDI_CHECKOUT \
  npm run test:identity-wallet-eudi-issuance
```

See [external CLI prerequisites](identity-card-issuance.md#eudi-dev-actual-oid4vci-issuance-persistence-and-oid4vp-checkpoint)
for the exact eudi-dev commit. Raw configs/logs, disposable PKI, tokens and
credentials stay outside tracked/public artifacts.

## Issuer modules outside this checkpoint

All fourteen remain unselected **for this measured source**. Historical outcomes
are separate; none is inferred to be passing or N/A on this source.

| Module suffix | Existing evidence / next boundary |
| --- | --- |
| `metadata-test-signed` | Two historical SKIPs for unsigned metadata; signature validation was not exercised. |
| `happy-flow-skip-notification` | Historical two-format pass; not rerun here. |
| `batch-issuance` | Default one-key profile does not advertise standard batch; determine the unchanged official condition. Experimental age batches are separate. |
| FAPI `happy-flow` | Run inherited happy flow with actual credential/resource validation. |
| `user-rejects-authentication` | Actual owner denial, callback and required browser evidence. |
| `ensure-different-state-inside-and-outside-request-object` | Resolve unsigned/JAR applicability through the official module. |
| `state-only-outside-request-object-not-used` | Resolve unsigned/JAR applicability through the official module. |
| `ensure-request-object-without-redirect-uri-fails` | Resolve unsigned/JAR condition and actual redirect rejection. |
| `plain-fapi-tolerate-unregistered-redirect-uri` | Determine HAIP gating; unregistered callbacks continue to be refused. |
| `ensure-unsigned-authorization-request-without-using-par-fails` | Direct-authorization error page/callback and authentic UI evidence. |
| `ensure-redirect-uri-in-authorization-request` | Fixed official variant and registered redirect omission behavior. |
| `refresh-token` | No refresh token is advertised/issued; record the actual conditional outcome. |
| `par-ensure-reused-request-uri-prior-to-auth-completion-succeeds` | Local revisit regression exists; official browser-visit telemetry still needs its adapter. |
| `par-attempt-to-use-request_uri-for-different-client` | Two historical REVIEWs with real error-page images; official human review remains open. |

## Deployment and device observation

The GET-only provider observation at **14:13:50 UTC** saw OP version
`1c73f5cf-5073-45fd-8442-ee38feff10f4` at 100% traffic, with source annotation
`30b0aa92f3899a9e10bc1dd8d4cc87c30074a4cb`. Its deployment was stable across
the before/after reads. Identity had a secret binding for the dedicated issuer
key and the rate-limit binding, with `IDENTITY_ENABLED=false` and the age-only
claim selection. Secret values and Worker script content were not requested.

The independent public device preflight at **14:10:52 UTC** confirmed Android
association and the issuance callback fallback. Credential metadata,
authorization metadata and issuer JWKS returned 404. No Wallet configuration,
signed APK or connected authorized Android device was available;
`prerequisites_ready=false`, `qualification=not_run`. These observations do not
prove secret/private-key bytes or an Android Keystore/attester journey.

## Remaining acceptance by Issue

| Issue | Advanced in this checkpoint | Remaining concrete boundary |
| --- | --- | --- |
| [#116](https://github.com/masanork/mikaki/issues/116) | Deployed disabled signing/rate-limit custody observed; exact age-only activation/preflight path implemented. | Independently approved licence issuer policy/provenance, CI trust secret and reviewed activation selection; named accepting RP, profile smoke/rollback and deployed runtime measurements. HAIP additionally needs its separate PKI/encryption/attester and real Android verification service. |
| [#117](https://github.com/masanork/mikaki/issues/117) | Current public/device prerequisites recorded; host storage/consent/protocol regressions exercised. | Connected signed Android build with compiled trust; physical NFC/PIN, issuance, persistence/restart/migration/deletion, account switching, cancellation and key-loss checks. My Number DF31 intake/signature trust remains its own gate. |
| [#118](https://github.com/masanork/mikaki/issues/118) | Pinned eudi-dev public and software-attester HAIP host issuance/storage/restart/presentation rerun in both formats. | External full mobile/CLI application against the activated deployment, with production trust, actual App Links/browser/Keystore and intended failure/lifecycle evidence. Patched software attestation is not hardware evidence. |
| [#119](https://github.com/masanork/mikaki/issues/119) | Two protocol defects fixed; reproducible extended Issuer checkpoint and selected Wallet regression. | Remaining applicable modules, actual Wallet error screens, human REVIEW, explicit conditional outcomes, formal certification and HAIP 1.1 version/difference inventory. |
| [#120](https://github.com/masanork/mikaki/issues/120) | Shared/host proximity and revocation regressions exercised. | Physical BLE/NFC/TNEP reader interoperability and exact ISO 18013-5/-7/23220 profile evidence; broader doctypes and transports remain separate. |

These Issues remain open. The next enabled-device boundary is one independently
approved card → one age-only credential → one named RP presentation with explicit
owner consent. The custom credential continues to declare static issuer evidence,
no verified live possession and no government-credential status.
