# Identity Wallet

The native Wallet shows identity-document read summaries as a collection of cards,
separately from issuer-signed credentials. The visual direction takes inspiration
from `~/repo/doma`'s document-specific materials: sakura for My Number Card, indigo
for driving licences, and burgundy for passports. Layout,
card patterns and icons are implemented locally using CSS and SVG.

## User flow and custody

1. Add a document and choose a supported reader.
2. Read the physical card and review its contents. Reading alone does not save it.
3. Choose **このWalletに保存** to save a local read summary. One summary per supported
   document type is retained; saving another read updates that type.
4. Open a card to inspect its contents or delete its local record. Names can be
   hidden on the collection. Leaving Wallet or hiding the app clears its displayed
   attributes and invalidates late inventory responses.
5. From a read card's details, reopen the matching reader or continue to issuance
   from registered account attributes. A saved passport with current Japanese
   CSCA/CRL verification can instead start the separate DG1 issuance review below
   when the issuer advertises it. Reading, saving and opening a card never upload evidence.
6. From a credential's details, open presentation-request review. mdoc also offers
   nearby-presentation preparation. The verified request determines the selected
   receipts; opening a card does not constrain or authorize the native selection.
   Expired credentials and their open details disappear before a pending inventory
   refresh completes.

Android saves the summaries in separate, account-scoped AES-256-GCM files in
`noBackupFilesDir`. The wrapping key remains in Android Keystore. Account identity
comes from the verified native OIDC session; the WebView supplies neither owner IDs
nor document attributes to the save command. The native pending read must belong
to that account and be no more than five minutes old. Logout invalidates a pending
read. Persisted summaries are available again after signing in to the same account.
Deleting the last summary removes that account's file and wrapping key.

Saved fields are name, address, birth date, gender and document expiry date, plus
source, local timestamps and the unverified-read state. Passport records additionally
retain the document number, the chip's full TD3 MRZ and available EF.SOD evidence
after an explicit save.
Personal number, PINs, portraits, domicile, communication keys, raw transport logs
and non-passport signature evidence are not archived. Summaries have
no credential string or holder key and cannot be selected for presentation.
A local read is not labelled government-issued digital ID or trusted issuer proof.
The initial reader cannot obtain every document's expiry; missing dates are shown
as unknown and never inferred.

Reading and persistent summary storage are currently Android-only. Desktop/iOS
show that limitation when adding documents. My Number Card and traditional IC
licences use the existing native reader. BAC-enabled TD3 passports now use the same
Android IsoDep transport and cancellation/session lifecycle. A passport appears in
the collection only after a successful native read and explicit save.

## Passport read scope

The initial passport reader accepts an uppercase alphanumeric document number
(up to nine characters), full ISO birth date and full ISO expiry date. It derives
BAC keys from the padded MRZ fields, performs mutual authentication, then reads
EF.DG1 and available EF.SOD over secure messaging. All individual and composite MRZ check digits
and the access fields must match. Full years come from the user's input and are
labelled accordingly: the chip's two-digit MRZ years do not establish the century.

The bounded native reader uses OS randomness, verifies the mutual-authentication
response MAC and both nonces, authenticates secure responses before decryption,
and rejects duplicate/unknown/reordered objects, noncanonical lengths, invalid
padding, replay and sequence overflow. A fresh read clears any older card's pending
link evidence before opening NFC. The reader does not create a legacy account-link grant. Legacy card verification
and linked-document SD-JWT/mdoc issuers explicitly reject the passport document
type, including a validity object borrowed from another type. The separate
`passport_dg1` profile revalidates explicitly transferred raw evidence.

After a successful read and explicit save, the native pending record retains the
matched document number, the exact 88 ASCII characters of the chip's TD3 MRZ,
and available EF.SOD (up to 8 KiB, encoded in the encrypted document record).
They use the same account-scoped encrypted file and Android Keystore protection as
the other document fields. The WebView supplies no passport attributes to save.
On restoration, bounded MRZ fields, check digits and document attributes must agree.
Communication keys, counters and nonces have no persistence fields; native transient
buffers and key schedules are zeroized on drop.

The collection inventory exposes a `passport_saved` flag and a native-computed
DG1/SOD report alongside the usual summary, never the passport number, MRZ or SOD.
The report is recomputed from stored evidence, rather than trusting a cached success
flag. The explicit MRZ detail/prefill command also omits raw SOD. In card details they remain masked until
the user chooses **旅券番号・MRZを表示**, which calls an authenticated native detail
command for the current account. Hiding or closing details, navigation, app hiding,
logout and deletion clear the displayed data and invalidate pending responses.
**パスポートを読み取り直す** uses the same explicit lookup to prefill number and dates;
starting NFC still requires the read button. Navigation, type changes and manual
edits invalidate late prefill results. These values are never put into web storage.

Older summaries without passport data still restore, with no invented MRZ or
prefill. A new physical read and save adds the missing document data. The collection
now supports all three types; the optional passport field extends version 1 without
requiring a rewrite of older records. The WebView still clears access inputs on
submit, cancellation, type change, navigation, app hiding and logout.

**BAC is access control, not issuer authentication.** DG1/SOD signature consistency
is now checked as described below, followed by bounded offline CSCA/CRL checks
for Japanese issuers. Chip authentication, DG2 portrait, PACE and extended passport
numbers remain unsupported. PACE-only documents fail; there is no unprotected
retry. A passport summary remains `unverified` and `backend_verifiable: false`.
It cannot itself authorize identity linking or VP presentation. Separate issuance
requires the explicit reviews, original-evidence verification and holder binding below.

### DG1/SOD consistency

The native reader selects EF.SOD (`011D`) in the same authenticated BAC session.
A MAC-authenticated `6A82` response records missing signature evidence; transport,
cancellation and MAC failures abort reading. Evidence beyond 8 KiB or malformed EF
lengths fails reading. Existing records without SOD remain readable and explicitly
show that signature information has not been checked.

The bounded verifier checks the CMS/ICAO content types, a single signer and digest,
exact DER encoding, signer identifier to DSC binding, DSC key usage, required unique
content-type/message-digest attributes and the CMS signature. It verifies the LDS
DG1 hash over the complete DG1 file. Duplicate groups, attributes, signers and
ambiguous certificate matches are rejected. CMS algorithm-protection attributes
and RSA-PSS parameters are bound to the selected digest/signature, including MGF1,
salt and trailer. Unknown signature algorithms remain unsupported, never successful.

Supported signature profiles are RSA PKCS#1 v1.5 and RSA-PSS with SHA-256/384/512,
and P-256/SHA-256 or P-384/SHA-384 ECDSA. RSA keys are bounded to 2048–4096 bits.
DG hash algorithms must be SHA-256/384/512. Legacy SHA-1 DG hashes are unsupported,
including when the SOD itself has a stronger signature. SHA-1 is confined to the
native BAC key derivation required by ICAO Doc 9303 Part 11 sections 4.3 and 9.7.1;
it cannot establish issuer-authenticated DG1 evidence. Named curves and explicit
parameters matching every mathematical P-256/P-384 domain field are supported;
point size alone never selects a curve. SHA-1 signatures and other curves remain
unsupported. The verifier follows
[RFC 5652](https://www.rfc-editor.org/rfc/rfc5652.html) and the DG/SOD relationship in
[ICAO Doc 9303 Part 11, Appendix E](https://www.icao.int/sites/default/files/publications/DocSeries/9303_p11_cons_en.pdf).

The policy fingerprint uses the `mikaki-passport-dg1-policy-v2` domain to bind this
stronger digest policy as well as the pinned anchors and CRL. The earlier
SHA-1-compatible policy fingerprint is rejected by production smoke.

Only DG1 is read and verified; listed hashes for other groups are not proof that
those groups were read or matched. A successful report therefore contains only
`checked_data_groups: [1]`, with a separate `issuer_trust`, `revocation`, native
`checked_at` and bounded `valid_until` report. Embedded
certificates are used to verify signature consistency, never enrolled as trusted
CSCA roots. A self-signed synthetic DSC can thus demonstrate consistency while
establishing no government provenance. Full Passive Authentication is not qualified.

Wallet differentiates not checked, unsupported, invalid and signature-consistent
results. Without a matching trusted CSCA it says **署名整合 · 発行国未確認**.
Details always state that other data, including portraits, is unchecked. Neither
this result nor the persisted SOD changes the credential/presentation authority boundary.

### Offline Japanese CSCA and CRL verification

Four Japanese CSCA roots (2013, 2015, 2019 and 2024) are embedded with the exact
SHA-256 fingerprints published by the
[Ministry of Foreign Affairs](https://www.mofa.go.jp/ca/pss/page23e_000598.html).
The downloaded BSI Master List was used only to recover those exact public DER
bytes after direct MOFA downloads returned HTTP 403. Other certificates in that
list are never enrolled. Provenance, hashes and CRL refresh instructions live in
[the shared trust directory](../crates/identity/src/passport/trust/README.md). The source/key policy follows
[ICAO Doc 9303 Part 12, sections 4.1.5 and 6.1](https://www.icao.int/sites/default/files/publications/DocSeries/9303_p12_cons_en.pdf).

After CMS/DG1 consistency passes, the chip's signed MRZ issuer must match the
application's pinned country metadata. The direct DSC-to-CSCA path binds exact
issuer/subject names and AKI/SKI, verifies the DSC signature, checks both certificate
lifetimes at the native system time, and enforces CA/key usage, duplicate-extension
and supported critical-extension constraints. Name/policy constraints and EKU outside
this bounded profile are rejected as unsupported. Self-signatures do not confer trust.
SOD-embedded roots, platform TLS roots and WebView input cannot add anchors.

The bundled Japanese complete CRL was issued 2026-09-14 02:16:11 UTC and has
`nextUpdate` 2026-12-13 00:00:00 UTC. The native verifier authenticates its signature
and AKI against a pinned, currently valid key for the same CSCA. This allows the
newest pinned CSCA key's CRL to cover DSCs issued under older pinned keys. DSC and
selected CSCA serials are checked. Bounds are 8 CRLs, 64 KiB each, 256 KiB total,
and 2048 unique revoked serials. Duplicate issuers, unsupported critical extensions,
delta/indirect/partitioned lists, future dates and malformed entries cannot produce
`good`. Freshness requires both `nextUpdate` and a maximum age of 90 days, reflecting
the passport PKI publication interval rather than the credential reader's TLS policy.

The default report is recalculated on every native read/inventory restoration.
**発行国署名 · DG1確認** requires a valid direct chain and fresh, authenticated complete
CRL with no matching revocation. Missing, stale, not-yet-valid, unsupported or invalid
CRLs remain separate from chain success; a revoked DSC/CSCA is labelled
**失効リスト掲載**. Certificates outside their current validity are reported separately.
The successful deadline is bounded by DSC/CSCA/CRL-signing-key expiry, CRL
`nextUpdate` and maximum age. UI labels and open details are removed at that deadline
before awaiting native refresh; the read preview also downgrades on expiry.

There is no runtime network fetch, automatic Master List enrollment, CRL rollback
cache or trusted external clock. A release build may override the CRL snapshot using
`MIKAKI_PASSPORT_CRLS`, a bounded JSON array of canonical padded standard Base64 DER
CRLs. Invalid configuration fails closed; `[]` deliberately yields unknown revocation.
This is build-time native configuration with no WebView setter. Refreshing the bundled
CRL or adding a new authenticated CSCA requires a reviewed app update. A compromised
or incorrect device clock is outside the offline freshness guarantee.

This is a Japanese direct-path DG1 subset, not general ICAO conformance or complete
passport Passive Authentication. Other countries, link-certificate path building,
all listed data groups and real-device qualification remain work. Passport summaries
stay `unverified`, `backend_verifiable: false`, and unavailable for direct linking/VP.
An explicitly requested, separately issued credential has its own authority.

BAC primitives are adapted from civ commit
`54a843e656513930df60bbc20d752ff3289e7078`; provenance and MIT/Apache notices live
beside `identity_passport/crypto.rs`. The protocol and known-answer tests use
[ICAO Doc 9303 Part 11, Appendix D](https://www.icao.int/sites/default/files/publications/DocSeries/9303_p11_cons_en.pdf).
BAC cryptography and DES are confined to the native reader. Passport signature,
CSCA and CRL verification now live in the shared identity library, without adding
BAC/DES to the Worker. The separate DG1 issuance endpoint below uses the shared verifier.

## Passport DG1 credential issuance

`IDENTITY_ENABLED=true` and `IDENTITY_PASSPORT_ENABLED=true` advertise `passport_dg1`
(`dc+sd-jwt`) with VCT `${issuer}/types/passport-dg1`. This uses the **same issuer**,
signing trust, nonce, PAR, authorization, token and credential endpoints as existing
HAIP issuance. It does not introduce a second issuer or weaken the HAIP policy.
The feature remains opt-in for other installations. The production configuration in this release candidate sets `IDENTITY_PASSPORT_ENABLED=true` alongside the existing HAIP settings; configuration is not evidence of production activation.

For production HAIP, retain `IDENTITY_WALLET_ENABLED=true` and
`IDENTITY_HAIP_ENABLED=true`, provision the existing registered-wallet, client/key
attestation, signing-certificate and request-encryption settings, and build Android
with the matching `MIKAKI_HAIP_WALLET` trust configuration. Apply
`crates/worker/migrations/0007_passport_issuance.sql` before promotion. Its bytes are
pinned in `scripts/production-owner-schema.ts`; readiness requires the complete
ordered ledger. The additive-table bridge accepts only the complete seven-migration chain in the
immediately preceding six-migration binary. That bridge must be deployed **before**
applying migration 0007; the currently deployed older binary does not acquire the
bridge simply because this source contains it. Exact-schema promotion remains closed
until all seven migrations are present.

1. From a saved passport with current native CSCA/CRL verification, choose the
   separate issuance action. Native code loads only the current signed-in owner's
   encrypted evidence, revalidates it and creates a dedicated Wallet linkage key.
   The WebView supplies no raw evidence, identity attributes, owner ID or key.
2. Review the six projected attributes, fixed issuer and linkage-key thumbprint.
   The transfer notice includes the original DG1's full MRZ, document number and
   personal-number field. Cancellation, expiry, account changes and stale responses
   invalidate this review; explicit cancellation returns focus to the source card.
3. Only **送信してブラウザで発行を承認する** sends DG1/SOD to
   `/identity/passport/intake`. The server independently verifies the original
   signatures, pinned Japanese CSCA and current complete CRL. It keeps only six
   projected attributes, canonical evidence/policy hashes and temporary grant data.
   Raw DG1/SOD are never stored server-side.
4. The native HAIP client authenticates its Wallet instance and submits PAR using
   S256 PKCE, DPoP and `scope=passport_dg1`. Standard `issuer_state` identifies only
   the temporary evidence transaction. The original review key becomes the DPoP
   sender key; the PAR sender must prove possession of that exact key. Raw evidence
   never enters OAuth parameters or the browser URL.
5. The system browser opens the existing authorization endpoint. Its owner reviews
   the six attributes, account, authenticated Wallet and matching linkage key.
   Same-origin POST, CSRF, owner/session/epoch, current client policy and unused PAR
   bind this one-use approval. Approval consumes PAR atomically and returns a code
   to the registered callback with exact Wallet state and issuer binding.
6. Explicit receipt uses the existing HAIP token exchange: Wallet authentication,
   PKCE, the same DPoP sender and nonce/replay checks. At the encrypted Credential
   endpoint it resends original `passport_evidence`, a current nonce and an attested
   holder proof. A fresh credential holder key is separate from the DPoP linkage
   key. The issuer revalidates the original evidence/hash/projection, trust policy,
   owner and deadlines; issuance consumes the nonce and scrubs temporary grant data
   atomically. There is no Bearer/pre-authorized fallback in HAIP mode.
7. Native code checks the issuer signature/certificate trust, holder binding and
   exact passport VCT before displaying **旅券MRZ属性証明**. It retains the receipt
   in memory for the current native owner, including independent credential trust
   for mixed DCQL selection. Account changes, expiry or process exit remove it;
   global credential persistence rejects this profile. The source passport remains
   in its encrypted account-scoped storage until explicitly deleted.

The profile selectively discloses only `name_mrz`, `issuing_state`, `nationality`,
`birth_date_mrz`, `expiry_date_mrz` and `sex_mrz`. Dates remain `YYMMDD`. Signed metadata
fixes `checked_data_groups: [1]`, `document_validity_verified: false`,
`live_possession_verified: false` and `government_credential: false`. An authentic
historical MRZ can pass; the credential does not attest current travel validity,
a full year, age or face match. It is Mikaki's DG1 authenticity attestation, not a
government DTC or mDL. These claim limits are independent of HAIP transport security.

Credential validity is at most five minutes, clipped by transaction, evidence,
issuer-certificate and key-attestation deadlines. The review deadline is at most ten
minutes; issue/deny clears projected attributes and secrets immediately, and bounded
GC removes expired rows. Account/client-policy changes invalidate pending authority.
Disabling the feature stops further issuance; already issued credentials retain
only their bounded signed lifetime. No persistent account attribute is enrolled.

Metadata publishes the current `passport_evidence_policy` fingerprint and freshness
deadline. Authenticated `/ready` and metadata fail closed for missing schema/key,
invalid policy or missing/stale/unauthenticated CRLs. `Policy::valid_until` verifies
pinned anchors and signed CRL readiness without accepting any document. Worker
`IDENTITY_PASSPORT_CRLS` and native `MIKAKI_PASSPORT_CRLS` accept bounded canonical
standard-Base64 CRL arrays; neither enrolls roots. Refresh the reviewed CRL snapshot
and installed app configuration before its deadline. There is no automatic fetch or
rollback cache for passport CRLs in this release.

OID4VP/DCQL recognizes the actual verified passport VCT alongside linked-document
credentials, with separate disclosure consent and holder-bound presentation. HAIP
receipts carry independently provisioned credential certificate trust. The local
non-HAIP prototype retains its old single-receipt path; its poll/pre-authorized and
direct-approval endpoints are closed in HAIP mode. Passport mdoc/proximity and a
Multipaz ceremony for this new profile remain unqualified. Previous Multipaz host
results apply to existing linked-document SD-JWT/mdoc flows.

See [OpenID4VCI 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html),
[HAIP 1.0](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html)
and [the evidence contract](passport-evidence.md). Implemented HAIP-path checks,
interop certification, installed-device behavior and real-passport qualification
are separate results.

## Multipaz and presentation interface

Multipaz separates displayable documents, stored credentials, secure areas and
presentment. See the official [DocumentStore guide](https://developer.multipaz.org/docs/getting-started/holder/documentstore/)
and [presentation guide](https://developer.multipaz.org/docs/getting-started/holder/presentation/).
The display adapter in `apps/mikaki-client/ui/wallet-model.js`, with its declaration
file, follows that separation:

| Wallet item | Source | Presentable formats | Authority |
| --- | --- | --- | --- |
| Read summary | `card_read` | None, `available: false` | Recent native physical-card read; unverified summary |
| Issued credential | `issued_credential` | Native-verified `dc+sd-jwt` or `mso_mdoc` | Issuer signature and native holder-key custody |

`presentation.available` on an issued item means a signed representation exists
for selection. Actual presentation still requires a current receipt, a supported
request, configured verifier/reader trust, holder binding and explicit consent.
The existing native OpenID4VCI, OpenID4VP/DCQL and mdoc proximity paths remain the
protocol boundary. No new self-signed credential, invented mDL/DTC doctype, direct
key export or generic JSON-to-VP conversion is introduced.

For a future Multipaz-backed document store, map each display item to document
metadata and attach credentials only after accepted issuance. Keep their real
`vct` or mdoc doctype and issuer/holder binding; a licence read must not be renamed
`org.iso.18013.5.1.mDL`. Shared passport evidence verification is available through the
[portable evidence interface](passport-evidence.md). A chosen issuer/claim profile,
explicit evidence-transfer review and holder binding are implemented for the bounded
`passport_dg1` profile below. Original-document verification, issuer attestation and
derived VP remain separate decisions.

The product does not bundle the Multipaz SDK. The SDK is used as an independent
host verifier through the existing pinned issuance/presentation harnesses, detailed
in [identity-card-issuance.md](identity-card-issuance.md). A UI adapter is not
certification or a successful third-party Wallet ceremony.

Use the explicit runner to require actual SDK execution instead of a silently
omitted optional check:

```sh
chmod 700 /private/tmp/mikaki-multipaz-checkout
JAVA_HOME=/path/to/jdk21 ANDROID_HOME=/path/to/android-sdk \
  npm run test:identity-wallet-multipaz -- --checkout /private/tmp/mikaki-multipaz-checkout
```

The disposable SDK checkout must belong to the current operator with mode `0700`
so other users cannot traverse it or change writable nested files. Its parents
must prevent group/other writes and directory replacement; a root-owned sticky
temporary parent is permitted. A temporary path alone does not establish this
boundary. The runner checks canonical paths and POSIX ownership before executing
SDK code. The checkout must be at the pinned commit, with unchanged tracked
sources and complete Git history/tags (the upstream version calculation uses its
release tag). The default command tests native mixed presentation, rebuilds the
local Worker, then tests SDK issuance and presentation in the opposite direction.
`--native-only` selects the native mixed-presentation check. Java/Android SDK and
Gradle dependency-cache setup follow the existing harness documentation.

The command requires fresh SDK XML reports with executed tests and no skips,
checks SDK source integrity again afterward, and writes only a redacted host-test
summary to ignored `local/generated/wallet-multipaz-summary.json`. Missing checkout,
wrong pin, stale report, build error or skipped SDK tests fail the command.

## Verification

The current-main candidate is checked with the shared identity suite, native Rust
suite, Android aarch64 compile check, strict shared/Worker Clippy, Node type check,
and release/schema tests. UI regressions cover the new shelf plus the existing
card reader, age credential batches, HAIP receiver, presentation consent and Web
navigation. The Wallet-only login tests verify that no document collection is read
before authentication and that logout/cancellation removes visible source data.
Responsive screenshots and accessibility checks use synthetic identities.

In actual workerd, the passport tests check authenticated PAR/code, owner/CSRF,
client/PKCE/DPoP binding and replay, attested holder proofs, required encrypted
transport, policy freshness, nonce consumption, grant scrubbing and rollback.
The readiness tests check the ordered seven-migration ledger and dependent
services. The existing card issuance and independent SD-JWT/mdoc presentation
contracts also run against the candidate.

Positive DG1 authentication -> short-lived SD-JWT -> selective holder-bound VP
checks use test-only OpenSSL roots. Production-pinned Japanese trust rejects those
synthetic documents. Privileged projected-attribute database seeds isolate the
positive protocol tests; they do not prove successful Japanese-passport intake.

The archived [Multipaz host report](identity-wallet-preview/multipaz-host-results.json)
dates to 2026-10-21 and covers existing linked-document SD-JWT/mdoc host interop.
It does not qualify the new passport profile, a full Multipaz Wallet app ceremony,
installed Android behavior, production trust or certification. Use the explicit SDK
runner above for fresh host evidence.

No physical passport or Android device is connected in this environment. A real
passport read, encrypted storage/restart, Android key-attestation round-trip and
external passport verifier ceremony remain separate qualification work. Production
activation is recorded only after the source/version, migration and smoke checks
in the following sequence succeed.

## Release candidate and deployment sequence

The current-main release candidate is isolated from the original dirty checkout.
It preserves the in-app Web navigation and the age-only operator-card HAIP profile,
including multiple age-credential receipt and single-use retirement. Native Wallet
login is a separate, verified OIDC session used to scope encrypted document storage;
account/Chat Web navigation remains usable without starting that login. Logout clears
visible document details and transient passport issuance/presentation state. Signing
out of this Wallet does not sign out the separate Web session.

Production adoption requires this ordered sequence:

1. Deploy a preparation release that permits the immediately previous binary's
   readiness check to recognize the exact additive 0007 ledger, while retaining
   the six-file promotion inventory and keeping passport issuance unadvertised.
2. Inspect the target `mikaki-auth-owner` feature, Work and Chat ledgers and complete
   schema. Apply only the reviewed `0007_passport_issuance.sql` and verify the exact
   post-migration schema and immutable file digest. Existing passport transactions
   cannot be synthesized to qualify production readiness.
3. Merge/promote this candidate through the existing source-bound CI and attested
   upload pipeline. Its production configuration retains HAIP and adds the passport
   flag. Do not use a dirty local upload or replace the existing issuer/age profile.
4. Verify `/version`, protected `/ready`, existing HAIP readiness, and issuer metadata
   (including `passport_dg1`, key attestation, required encryption and current passport
   evidence-policy deadline). Run the installed Android approval/receipt/presentation
   ceremony using a real Japanese passport before recording device qualification.

The development machine currently has no connected Android device. Its Cloudflare
credential exposes account read/artifact scopes, without Workers/D1 deployment
permissions; deployment must use the existing CI custody or an appropriately scoped
operator credential. Public production endpoints also reset connections from this
machine during the current check, so no current-production success is inferred from
local tests. See [release and recovery](release-and-recovery.md) for attested promotion.
