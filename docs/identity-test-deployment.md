# Identity test-deployment checkpoint

## Latest selected profile — HAIP operator age experiment, 2026-10-15

The canonical configuration now selects `operator-card-haip-age`: the same
operator-confirmed card trust and `age_over_18` claim, with authenticated HAIP
authorization-code issuance in SD-JWT and mdoc formats. The source binds the
purpose-separated LabPKI certificate bundle, Wallet registration and exact
Android verifier policy through `IDENTITY_HAIP_POLICY_SHA256`. Public Wallet,
UserInfo and batch variants are not separately selected. On this Issuer, HAIP
disables pre-authorized token exchange and Bearer credential access.

The Android verifier has been deployed to the dedicated Cloud Run service
`mikaki-android-verifier` in project `ocspd-poc-masanork`, region
`asia-northeast1`. Its authenticated readiness confirmed live Google status and
policy `q3js6eUGLqFvJvrrdkWs8pzbeH0vUMSo0EzCGSh6GBo`; unauthenticated requests
returned 401. The private bridge `mikaki-android-attestation-verifier` has
Workers.dev and preview URLs disabled and holds only its dedicated verifier
token. It reads no Issuer/Attester private signing key or account database.

Ordinary main CI must still verify and promote the selected OP source; local
configuration and dependent-service deployment alone do not establish OP
activation. The production smoke workflow checks both public metadata and the
token-protected `/identity/ready`, which validates local Issuer custody and the
actual bridge/JVM/Google status path. This is separate from base OP readiness so
an Identity dependency failure does not mark ordinary OP/Vault readiness failed.
Source-matched deployment/smoke receipts establish which source is live.

A release-signed Android APK with the public Wallet configuration has been built
and its package/signature/App Link checked. No physical device was connected at
this checkpoint; native hardware enrollment, owner approval, credential receipt
and presentation remain separate evidence. See [LabPKI deployment details](identity-labpki.md).

The sections below retain the earlier preparation and first-party activation
history.

### Approved single-card trust renewal — 2026-10-30

The operator explicitly approved the reviewed extension and normal deployment in
this conversation: “そうだね。通常配備に進めて良い”. Only `not_after` of the same
single-card `mikaki_test` / `age_over_18` policy changes, through
`2026-11-06T09:38:47Z` (2026-11-06 18:38:47 JST), bounded by the renewed selected
credential CRLs. The compact policy SHA-256 is
`2ff30cc2bfa66e9f4db008456e3c1f18a7425bc7983d48d84ef3162f47e8258f`;
the previous policy and both previous deadline records remain intact.

The new restricted approval record is
`local/generated/identity-keys/card-issuer-operator-test-renewal-20261030.approval.json`.
It links the preceding approval by digest. The public deadline registry and
production source selection bind this exact approved policy; they do not replace
validation of the production-environment secret. Government issuer root-chain
verification and live card possession remain unqualified. No additional card,
claim, Chat activation, or physical qualification is authorized by this renewal.
Use the existing attested main promotion and source/version-bound production smoke.

### Proposed single-card trust renewal — 2026-10-22

Main CI [39695682430](https://github.com/masanork/mikaki/actions/runs/39695682430)
passed its build, verification and signing jobs, then stopped promotion before
Worker upload because the selected card-trust policy expired at
`2026-10-21T13:14:39Z` (22:14 JST). CRL renewal in PR #287 does not renew this
separate operator approval. Keep the expiry and exact-policy checks in place.

This configuration proposes extending only `not_after` of the existing single
operator-confirmed card policy to `2026-10-28T21:43:47Z` (2026-10-29 06:43:47 JST),
the earlier of the selected credential CRLs' expiry times. The compact policy
SHA-256 changes from
`0bf9e8cd3d2916034333f669cfafbd3a2b0c55e3ba954020de2d4bea81dde207` to
`51bae1540d65288588ab4f307d6f5376470a113e2586349f91d9b0315139b116`.
The modulus, key ID, document kind, original `not_before`, null licence identifier,
one-card limit and `mikaki_test` / `age_over_18` scope are unchanged. Government
issuer root-chain verification and live card possession are still unqualified.

The previous approval record ends at the original deadline. Obtain explicit
operator approval of this extension through review of this change before
provisioning the proposed compact policy to the GitHub **production environment**
`IDENTITY_TRUSTED_KEYS` secret. Retain the original policy and approval record;
record the new approval separately. This PR alone does not provision that secret,
deploy a Worker, apply Chat migrations or enable Chat.

After approval, validate the exact proposed bytes with the existing trust
preflight and confirm that the digest equals the reviewed configuration. Update
only the selected trust secret; use the normal source-bound main promotion and
login/Identity readiness smoke. The schema-compatible normal Worker must deploy
and pass smoke before following the [Chat schema rollout](chat-schema-rollout.md).
If the approved window expires again, repeat the explicit renewal review rather
than extending the deadline automatically or disabling validation.

Issue [#116](https://github.com/masanork/mikaki/issues/116) prepares the deployed
test service for [#117's physical-card/device journey](https://github.com/masanork/mikaki/issues/117).
The next completion boundary is one approved card read → one age-only credential
→ one named RP presentation, with separate owner consent. The
[experimental host batch implementation](identity-haip-age-pool.md) is complete
within its recorded scope; further batch features are not prerequisites to this
journey. Physical-device qualification and formal certification are later evidence,
not prerequisites to enabling a provisioned test profile.

## Read-only deployment observation — 2026-10-14

At 01:48 UTC, the `mikaki-auth` deployment was
`f94e47f5-e178-4db1-b7a0-a6b4b2a06002`, serving version
`6ee57337-1798-4512-b1bc-f9e4bfa6e3db` at 100%. Its public `/version` reported
clean source `b53a077a2acb6dd69f6a654ba269b740fa66d484`; the version annotation
tag matched `b53a077a2acb`. Its message recorded a separate reviewed Work copy
activation. Live Work copy execution was enabled with profile `single-disclosure`.

The active version had **no `IDENTITY_*` bindings**, including no Identity
variables, secret names, service binding or rate limiter. This observation records
binding presence only; no private key, secret value or card evidence was retrieved.
Public health returned 200, while Identity credential metadata, authorization-server
metadata and issuer JWKS returned 404. Android association returned 200; Apple
association remained 404, consistent with the unconfigured iOS signing identity.

The app host's `/identity/issuance/callback` returned 404. The app Worker only
handled the login callback even though the native client already accepted the
issuance path. This
change adds the exact issuance path to the same GET-only, query-free 303 fallback,
with an empty body, `no-store`, `no-referrer` and no cookies. Website integration
tests and production association smoke now check both paths. Until the changed
website is merged, deployed and checked, this remains a source fix.
Follow-up public callback probes encountered TLS connection resets; they do not
establish a successful deployed callback check.

PR [#227](https://github.com/masanork/mikaki/pull/227) merged as
`41206e917eef26ed8b7cc489e6ce26ed0c48875e`. Its
[main CI run](https://github.com/masanork/mikaki/actions/runs/38494720023) passed
the verification lanes but stopped promotion with
`Active Work copy requires separate reviewed deactivation`. The ordinary config
selects closed Work gates and correctly refuses to overwrite the active trial.
Do not turn off Work or bypass this guard to activate Identity. Coordinate a
reviewed configuration retaining the active Work profile before any OP promotion;
the separate website deployment can publish the callback fix independently.

## Follow-up observation — 2026-10-14 14:13 UTC

The [Wallet progress checkpoint](identity-wallet-progress-20261014.md) observes
OP version `1c73f5cf-5073-45fd-8442-ee38feff10f4` at 100%, with source annotation
`30b0aa92f3899a9e10bc1dd8d4cc87c30074a4cb`. The dedicated Identity secret and
rate-limit **bindings** are now present; Identity remains explicitly disabled
with age-only claims selected. The public preflight confirms both Android
association and the issuance callback fallback, while Identity metadata/JWKS
remain 404. Key values, real card trust and a physical device were not qualified.

## Required inputs and the smallest activation

### Operator-confirmed card test activation — 2026-10-15

The activation request selects first-party, single SD-JWT `age_over_18` issuance
for the operator-confirmed My Number card key. The private operator approval record
`local/generated/identity-keys/card-issuer-operator-test-20261014.approval.json`
records one physical card, explicit user approval for `mikaki_test`, independent
civ/self-consistency and matching Mikaki signature verification. Its key modulus
SHA-256 is `4f165687b442164881e40b9f2d06a50a3b6e7ddeb45844fbdb7ab604dd9ee6ff`.
**The government issuer root chain was not verified.** This is operator-selected
test trust, not an approved government issuer/certificate framework.

The same public trust policy is normalized to compact JSON for the existing GitHub
production secret; no new signing key, private card key or raw evidence is provisioned.
The selected policy digest is
`0bf9e8cd3d2916034333f669cfafbd3a2b0c55e3ba954020de2d4bea81dde207`.
Its original validity ends at **2026-10-21 13:14:39 UTC**. The exact single modulus,
key ID, null licence identifier, live validity, document kind and age-only profile
are checked before promotion and at runtime. A changed policy/modulus, additional
card, expired policy or raw-attribute profile cannot activate this selection.

The canonical config selects `IDENTITY_ENABLED=true`, the two reviewed digests,
`IDENTITY_ISSUANCE_CLAIMS='["age_over_18"]'` and `IDENTITY_TRUSTED_KEYS`. It removes
the discovery-only issuance stop. Metadata publishes
`mikaki_trust_profile=operator-confirmed-card-test` and
`mikaki_issuer_root_chain_verified=false`. Credentials retain static-data evidence,
`live_possession_verified=false` and `government_credential=false`; approval does
not establish person/account binding. Independent Wallet authorization, HAIP,
mdoc, Attester, UserInfo and batch extensions remain unselected.

This scoped experiment uses the existing server signature-verification path:
the signed My Number input includes DF31. The activation does not resolve
[#208's general-service decision](identity-age-predicates.md#my-number-evidence-decision-before-real-intake)
or claim that the data is never transmitted. Physical receive/persist/presentation
and authenticated owner/device qualification remain separate evidence.

For this explicit operator profile, the preflight accepts the public modulus digest
as its optional second argument. It validates selection, not provenance or approval:

```sh
npm run check:identity-test-trust -- /absolute/path/to/compact-test-trust.json 4f165687b442164881e40b9f2d06a50a3b6e7ddeb45844fbdb7ab604dd9ee6ff
```

The earlier discovery-only main promotion was blocked by the already-applied
Owner migration; the follow-up also updates current Work packets to include all
18 Owner/Work migrations while preserving retained 14–17-file packet verification.
Source-matched promotion and public smoke must establish the actual deployment.

### Public issuer discovery activation — 2026-10-15

The initial experimental production configuration selected `IDENTITY_ENABLED=true`,
`IDENTITY_ISSUANCE_ENABLED=false` and `IDENTITY_ISSUANCE_CLAIMS='["age_over_18"]'`.
This publishes the issuer's credential metadata, authorization-server metadata,
dedicated public signing key and credential type description. Credential metadata
reports `mikaki_issuance_enabled=false`. It does not select a card-trust secret.

All intake, approval, polling, token, nonce and credential endpoints return 503
`issuer_unavailable` before consuming request bodies or accessing issuance state.
The policy gate also rejects use of existing linked documents while issuance is
closed, and independent Wallet authorization/PAR remain disabled even if a stale
Wallet flag is present. Tests cover absent trust and stale configured trust, the
public key without private coordinates, age-only metadata and no issuance DB writes.
This is public discovery activation, not an issued credential or active HAIP Wallet.

Keep the dedicated key, production rate limit and exact binding checks. To enable
the first-party issuance profile, remove `IDENTITY_ISSUANCE_ENABLED=false` and
select the approved trust secret/digest described below in the same reviewed
configuration. Do not substitute repository fixtures for approved card issuer trust.
Record the source-matched public observation after promotion; this section alone
records the requested configuration, not a successful deployment.

The first main promotion (`871fc9c`, run `38589090581`) passed every verification
lane after one browser-test rerun, then stopped before Worker upload because the
production Owner ledger already contained `0006_owner_login_wrap.sql`. That
additive Vault migration was applied by the separate PR #242 workflow before its
feature merge. The alignment follow-up imports only the exact migration bytes,
schema pin and runtime/readiness recognition. It does not activate that PR's
login/Vault behavior or apply another DB migration. The fresh read-only check
reconstructs and verifies the complete Owner/Work schema, ordered ledgers and
unchanged empty supplemental table. Keep exact schema checks rather than admitting
an unknown ledger entry. A new source-qualified main promotion is required.

### Signing custody preparation — 2026-10-14

PR [#228](https://github.com/masanork/mikaki/pull/228) merged as `da96679`.
The subsequent [main deployment and public smoke](https://github.com/masanork/mikaki/actions/runs/38506303332)
passed for source `d3202521bda3088506dd1dcc3c4a9f396eb41c23`, OP version
`994c4a2d-90b0-441a-8234-e9015c2bdfde`, including both callback fallbacks.
The earlier Work promotion conflict is historical; this successful run does not
requalify an active Work trial or Identity. Direct public probes from this host
still encountered TLS resets, so the deployed evidence here is the linked CI run.

A fresh dedicated P-256 signing key was generated and stored as
`IDENTITY_ISSUER_JWK` in `masanork/mikaki`'s GitHub **production environment**
at `2026-10-14T05:40:10Z`. Its public identity is:

| Field                       | Public value                                                |
| --------------------------- | ----------------------------------------------------------- |
| `kid`                       | `mikaki-identity-test-0d878e2d-3b54-4dd4-a064-3d2c13bfaad6` |
| RFC 7638 SHA-256 thumbprint | `aI1NQnj1WPnTUqYPXyQDj6ASntF1C8DMzfO-12bE7y4`               |

The private backup is the mode-0600 ignored file
`local/generated/identity-keys/issuer-test-20261014.jwk.json` in the primary
checkout, within a mode-0700 directory. Keep it under operator custody; GitHub
does not provide secret-value readback. The generator reports only the public
JWK/thumbprint and refuses to replace a file:

```sh
node scripts/identity-issuer-key.ts local/generated/identity-keys/NEW_PRIVATE_FILE.jwk.json
```

The earlier preparation configuration staged this key with `IDENTITY_ENABLED=false`,
`IDENTITY_ISSUANCE_CLAIMS='["age_over_18"]'` and the `IDENTITY_RATE_LIMIT`
binding (namespace `1031`, 30 requests per 60 seconds per hashed IP/operation).
This limit uses Cloudflare's [local, permissive rate-limit API](https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/),
not a strict global request quota. Its deployed behavior still needs measurement.
No card trust, mdoc, independent Wallet, UserInfo, HAIP, attester or batch profile
is selected. The promotion validator keeps this preparation profile disabled, rejects additional
Identity variables/services, verifies the private/public key
coordinates, and rejects reuse of the OP key even with a different `kid`.

The workflow passes the selected key in the existing private mode-0600 secrets
file to `wrangler versions upload --secrets-file`, inspects every binding, then
uses the existing attested promotion path. [Cloudflare preserves omitted secrets](https://developers.cloudflare.com/workers/configuration/secrets/#upload-secrets-alongside-code);
unexpected live secret bindings still fail the repository's exact binding check.
This source change is preparation, not proof that the key/rate limit has reached
the Worker. Record the source-matched deployment after merge. Certification and
physical-device success are not activation gates.

### First-party age activation contract

The promotion validator now permits a separate first-party `age_over_18` SD-JWT
test profile when dedicated signing custody, the reviewed limiter and an exact
live driving-licence trust policy are selected. The checked-in production config
now selects the separate operator-confirmed card test described above; it does
not select the licence issuer profile.

First obtain an independently approved licence issuer key and record its source,
EF07/B6 identifier, validity and operator approval. Validate its **compact JSON**
policy (one JSON line, optional final newline) without printing public key contents:

```sh
npm run check:identity-test-trust -- /absolute/path/to/approved-licence-trust.json
```

The tool reports a SHA-256 digest, count, document kind and earliest validity bound.
It validates encoding and key shape; it cannot establish who owns a key or approve
trust provenance. It accepts only live RSA-2048/65537 licence keys with canonical
32-byte EF07/B6 identifiers, rejects duplicate JSON members/IDs, private/unknown
fields, expired/future policies and My Number keys pending the separate DF31 gate.

After provenance review, select the returned `IDENTITY_TRUST_POLICY_SHA256`,
`IDENTITY_ENABLED=true` and `IDENTITY_ISSUANCE_CLAIMS='["age_over_18"]'` in a
reviewed canonical production configuration. Add `IDENTITY_TRUSTED_KEYS` to
`secrets.required` and provision those exact compact policy bytes to the GitHub
production-environment secret. The existing private secrets-file upload path now
passes that selected secret; before upload the validator rechecks validity and
compares its digest with the reviewed configuration. A changed secret, absent
trust, expired policy, raw-attribute selection or added Wallet/HAIP/UserInfo/batch
flag fails promotion. The disabled preparation profile excludes the trust secret
even if it exists in the CI environment.

Keep the existing Work deployment guards and exact binding checks. Verify the
selected profile's metadata/JWKS, disabled other profiles and one approved
issuance/presentation after source-matched promotion; generic OP smoke and a
successful policy preflight are not that E2E evidence. Trust secret provisioning,
the actual activation config, named RP and physical device remain required inputs.

| Profile / requirement     | Remaining concrete input or work                                                                                                                                                                                                                                                                                                                                                               |
| ------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Card trust                | The selected single-card operator experiment has its explicit test approval and pinned public modulus above, without government-root verification. A broader licence/issuer trust profile still needs an independent source and validation decision; repository fixtures are not an approval source.                                                                                           |
| First-party single SD-JWT | The canonical selection enables one `age_over_18` receipt from the operator-confirmed key. Verify source-matched promotion, intake/nonce availability and a separate owner/device issuance. No independent Wallet/HAIP, mdoc or batch activation is needed for this slice.                                                                                                                     |
| CI secret custody         | The dedicated Identity signing key is prepared, and the existing approved test-card policy is normalized to compact JSON in the production-environment secret. Exact digest/profile checks still gate promotion; secret provisioning alone does not establish deployment.                                                                                                                      |
| mdoc                      | Matching Document Signer certificate and its operator/RP trust decision (`IDENTITY_MDOC_CERT_DER`, or the reviewed credential-certificate configuration). This is required for mdoc, not the initial SD-JWT-only slice.                                                                                                                                                                        |
| Independent Wallet        | Registered exact client ID/name/HTTPS callback in `IDENTITY_WALLET_CLIENTS`, then `IDENTITY_WALLET_ENABLED=true`; compile the corresponding public Wallet configuration. The callback fix alone does not register or authenticate a Wallet.                                                                                                                                                    |
| HAIP / native attester    | Purpose-specific client/key-attester and credential-signing trust, separate request-encryption key, required DPoP nonces, attester signing authority/client policy and a deployed Android verifier service binding. Enable the HAIP/attester flags only for this provisioned profile. See the [existing configuration contracts](identity-card-issuance.md#native-attester-enrollment-broker). |
| UserInfo                  | Separate `IDENTITY_USERINFO_ENABLED` selection and actual RP-specific owner consent; qualify the chosen age request and release policy separately from Wallet issuance.                                                                                                                                                                                                                        |
| Presentation              | Name the accepting RP and its exact verifier registration/callback and request. It must inspect the age boolean, validity, signatures and holder/request binding and accept the documented static-evidence assurance.                                                                                                                                                                          |
| Device                    | Signed Android build, matching verified app link and explicit public trust configuration; run the [existing device preflight](../scripts/check-identity-wallet-device.ts), then #117's actual NFC/PIN, receive/persist/delete, account-switch and interrupted-delivery checks. iOS additionally needs the real Apple team/signing identity.                                                    |

The operator's LabPKI can now prepare the purpose-separated HAIP development
certificate material. Its Go-issued chains/CRLs passed Mikaki's actual Rust
certificate validators and native Wallet configuration parser. See the
[LabPKI preparation and qualification boundary](identity-labpki.md); the Android
verifier service and HAIP production-profile deployment remain separate work.

For the first test, select one source document kind and one format. A driving-licence
profile with independently approved licence issuer keys avoids depending on the
unresolved My Number DF31 intake decision. The explicitly selected single-card
operator experiment above uses the existing verification path; general My Number
intake remains subject to the separate
[decision](identity-age-predicates.md#my-number-evidence-decision-before-real-intake).
Select `IDENTITY_ISSUANCE_CLAIMS='["age_over_18"]'` explicitly; absence selects the
existing full raw-attribute profile. Keep independent Wallet, UserInfo, HAIP,
attester and both batch extensions disabled until their own inputs are ready.

The owner DB is `mikaki-auth-owner` (`d0258938-0d27-4110-8aa9-c82e20f3885b`).
Recheck its current migration ledger/schema with the existing deployment checks;
this read-only checkpoint did not requalify it. Its checked-in Owner migration
chain is `0001`–`0006`, including the integrated Identity baseline, additive
login-review schema and the already-applied supplemental login-wrapper table.
Never apply the
historical `0036`–`0046` migration sequence to this DB.

Before activation, retain the exact source, active and staged version IDs, selected
profile, public key/certificate fingerprints, trust-policy provenance and rollback
target. Use the attested main artifact/promotion path and source-matched public
smoke. Then qualify one real issuance and presentation plus unlink/expiry, and
measure deployed startup, memory, CPU and bounded/rate-limited intake. Worker byte
budgets alone are not runtime measurements. The credential still says
`issuer_signed_static_data`, `live_possession_verified=false` and
`government_credential=false`; this work does not establish certification or
person-to-account binding.
