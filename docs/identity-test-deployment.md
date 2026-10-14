# Identity test-deployment checkpoint

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

## Required inputs and the smallest activation

| Profile / requirement | Remaining concrete input or work |
| --- | --- |
| Card trust | Operator-validated issuer policies in `IDENTITY_TRUSTED_KEYS`: key ID, document kind, canonical RSA-2048 `n`/`e`, validity and licence subject-key identifier. Record the independent source and validation decision. Card-supplied or fixture keys are not an approval source. |
| First-party single SD-JWT | Dedicated `IDENTITY_ISSUER_JWK`, separate from OP/DPoP keys; a production `IDENTITY_RATE_LIMIT` binding; explicit age-only `IDENTITY_ISSUANCE_CLAIMS`; then `IDENTITY_ENABLED=true`. No Wallet/HAIP, mdoc or batch activation is needed for this first slice. |
| CI secret custody | The current production workflow passes only OP/readiness/mail/Work secrets, and `productionRuntimeSecrets` rejects Identity secrets. A reviewed provisioning and promotion change must carry the selected Identity secrets without logging them or erasing existing custody. Adding dashboard secrets alone does not complete that path. |
| mdoc | Matching Document Signer certificate and its operator/RP trust decision (`IDENTITY_MDOC_CERT_DER`, or the reviewed credential-certificate configuration). This is required for mdoc, not the initial SD-JWT-only slice. |
| Independent Wallet | Registered exact client ID/name/HTTPS callback in `IDENTITY_WALLET_CLIENTS`, then `IDENTITY_WALLET_ENABLED=true`; compile the corresponding public Wallet configuration. The callback fix alone does not register or authenticate a Wallet. |
| HAIP / native attester | Purpose-specific client/key-attester and credential-signing trust, separate request-encryption key, required DPoP nonces, attester signing authority/client policy and a deployed Android verifier service binding. Enable the HAIP/attester flags only for this provisioned profile. See the [existing configuration contracts](identity-card-issuance.md#native-attester-enrollment-broker). |
| UserInfo | Separate `IDENTITY_USERINFO_ENABLED` selection and actual RP-specific owner consent; qualify the chosen age request and release policy separately from Wallet issuance. |
| Presentation | Name the accepting RP and its exact verifier registration/callback and request. It must inspect the age boolean, validity, signatures and holder/request binding and accept the documented static-evidence assurance. |
| Device | Signed Android build, matching verified app link and explicit public trust configuration; run the [existing device preflight](../scripts/check-identity-wallet-device.ts), then #117's actual NFC/PIN, receive/persist/delete, account-switch and interrupted-delivery checks. iOS additionally needs the real Apple team/signing identity. |

For the first test, select one source document kind and one format. A driving-licence
profile with independently approved licence issuer keys avoids depending on the
unresolved My Number DF31 intake decision. Do not add My Number trust until that
[real-intake gate](identity-age-predicates.md#my-number-evidence-decision-before-real-intake) is resolved.
Select `IDENTITY_ISSUANCE_CLAIMS='["age_over_18"]'` explicitly; absence selects the
existing full raw-attribute profile. Keep independent Wallet, UserInfo, HAIP,
attester and both batch extensions disabled until their own inputs are ready.

The owner DB is `mikaki-auth-owner` (`d0258938-0d27-4110-8aa9-c82e20f3885b`).
Recheck its current migration ledger/schema with the existing deployment checks;
this read-only checkpoint did not requalify it. Its checked-in Owner migration
chain is `0001`–`0004`, including the integrated Identity baseline. Never apply the
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
