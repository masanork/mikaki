# Age predicates from linked static document evidence

Issue [#208](https://github.com/masanork/mikaki/issues/208) adds the Wallet path: the issuer can issue `age_over_18` and `age_over_20` without issuing the source birthdate, name, address or gender. Each boolean has its own SD-JWT disclosure or mdoc IssuerSignedItem. The credential remains a Mikaki linked-document credential, with the existing `vct` and custom mdoc doctype/namespace `app.tossa.mikaki.linked_document.1`.

The element names and boolean encoding follow the age predicate pattern in the [EU Age Verification Blueprint](https://docs.ageverification.dev/Technical%20Specification/architecture-and-technical-specifications/#412-attribute-set). This implementation does not use its `eu.europa.ec.av.1` doctype or claim Blueprint certification. It also does not issue government PID/mDL or replace the Digital Authentication App.

## Issuer profile

Set the optional Worker variable `IDENTITY_ISSUANCE_CLAIMS` to a JSON array of allowed claim names. The same issuer-selected profile applies to both `linked_document` and `linked_document_mdoc`, and both public/pre-authorized and authorization-code Wallet issuance paths.

```json
{"IDENTITY_ISSUANCE_CLAIMS":"[\"age_over_18\"]"}
```

For both thresholds, use `["age_over_18","age_over_20"]`. To include a raw attribute, add it explicitly: supported names are `name`, `address`, `birthdate`, `gender`, `document_expiry_date`, `age_over_18`, and `age_over_20`. Each raw attribute is independently selectable. Without the variable the existing full-attribute profile remains in effect: name, address, birthdate, available gender and available document expiry. Invalid JSON, unknown names, duplicates and an empty profile fail closed; they do not select the default profile. No production configuration or feature flag is enabled by this change.

The issuer metadata advertises the configured claim paths under OID4VCI Final's `credential_metadata.claims`, including namespace/element paths for mdoc. `/identity/issuer/types/linked-document` describes all supported claims and the static-assurance limitation. The shared Rust `ClaimProfile` selects claims before salts, disclosures or items are constructed. In an age-only profile the omitted raw values have no disclosures, digests or IssuerSignedItems. The linked D1 record still contains the verified source attributes under the existing retention policy; this is minimum disclosure to the Wallet/RP, not minimum intake or storage.

## Calculation and assurance

The boolean is inclusive: true means the Nth birthday has occurred on the **UTC issuance date**. It is a calendar comparison, not a fixed-duration year. A February 29 birthday reaches a threshold on March 1 in a non-leap year. This is the credential's documented computational rule; it is not an implementation of jurisdiction-specific legal age calculations.

The computation uses `Validity.evaluated_at`, preserving the actual issuance clock even when HAIP rounds `iat`/MSO validity to a minute. Predicate evidence `verified_at` uses exactly that clock; `source_verified_at` preserves the original static-signature verification time. The issuer also checks the existing linked-record, account, trust-key, certificate and document-expiry bounds before issuance.

The original card date must be a definite valid calendar date. Era year zero, dates outside their era, impossible dates, unknown eras and future birthdays cannot produce a predicate. Pre-1873 Japanese-era dates are rejected because a simple year-offset conversion does not resolve the historical calendar; see the [National Diet Library's calendar history](https://www.ndl.go.jp/koyomi/chapter1/s2.html). Both My Number and licence parsing validate the original date. A profile with no issuable claims returns an error rather than a guessed boolean or empty credential.

SD-JWT carries the existing signed evidence object. Predicate mdocs carry a **custom signed MSO extension**, `mikakiEvidence`, with document kind, source, trusted key ID, the two verification times and the following limits. It survives selective presentation without adding another disclosed attribute item. A verifier of this custom doctype must inspect this extension; generic ISO format/signature verification alone is not acceptance of Mikaki's assurance policy. Existing non-predicate mdocs remain compatible.

All predicates retain `assurance=issuer_signed_static_data`, `live_possession_verified=false`, and `government_credential=false`. The source birthdate and raw card signature are absent from predicate evidence. Static signatures can be copied and replayed; holder key binding proves possession of the Wallet key, not current possession of the physical card or that the account owner is the named cardholder. An RP must accept this limited assurance explicitly; deriving an age predicate does not raise it.

## Wallet consent and request matching

Native consent shows the selected boolean as 「18歳以上である」/「20歳以上である」 with 「はい」 or 「いいえ」. A separate provenance description names the source document and birthdate attribute, without displaying its value. Provenance comes from the authenticated credential, not a caller-supplied preview. Only requested values enter the consent's attribute list and presentation; the other threshold also stays undisclosed when it is not requested.

This DCQL query requests only the 18-year predicate:

```json
{
  "credentials": [{
    "id": "age",
    "format": "dc+sd-jwt",
    "meta": {"vct_values": ["https://issuer.example/identity/issuer/types/linked-document"]},
    "claims": [{"path": ["age_over_18"]}]
  }]
}
```

For mdoc use `format: "mso_mdoc"`, `meta: {"doctype_value":"app.tossa.mikaki.linked_document.1"}`, and `path: ["app.tossa.mikaki.linked_document.1","age_over_18"]`. The verifier must check that the authenticated boolean is **true**, as well as signature, holder/request binding, validity and the agreed assurance; merely receiving the claim does not establish adulthood. The RP authenticates its request using the existing verifier registration policy.

A required `birthdate` request cannot be satisfied by an age-only credential, even if the request also asks for `age_over_18`. The Wallet rejects the match and sends no partial presentation. DCQL credential-set alternatives retain the existing behavior: select a complete satisfiable alternative and omit optional sets. There is no automatic substitution of a predicate for a raw attribute or of one threshold for another.

## Host verification and physical-card follow-up

```sh
cargo test --locked -p mikaki-identity
cargo test --locked --manifest-path apps/mikaki-client/src-tauri/Cargo.toml --lib
worker-build --release crates/worker
node --test --test-concurrency=1 local/conformance/identity-issuance.test.ts
node --test --test-concurrency=1 local/conformance/identity-presentation.test.ts local/conformance/identity-card-ui.test.ts local/conformance/identity-proximity.test.ts
```

The issuance regression runs workerd with an 18-only profile for both synthetic card types, issues both formats through OID4VCI, and feeds the actual receipts to the Rust Wallet selection/presentation code. The independent Node verifier checks issuer signatures, disclosure/item digests, boolean types, exact age-only receipt contents, holder proof, nonce/audience/transcript binding and absence of raw attributes in presentations. Separate vectors issue both thresholds and present only `age_over_18`. Rust tests cover UTC birthday boundaries, leap days, old birthdays, invalid/future dates, era boundaries, minute rounding and independent raw-attribute profile choices. Browser tests cover both true/false results and both source document labels without exposing raw values.

These are synthetic host tests. Add to [#117](https://github.com/masanork/mikaki/issues/117)'s physical-device procedure: provision the reviewed age-only profile, read each permitted real card type, receive both formats on the device, restart the Wallet, inspect the predicate-only consent, verify the actual RP response and reject a birthdate request. Check a birthday boundary using authorized test evidence and the documented UTC rule. Physical card/Keystore/transport qualification, external Wallet interoperability (#118), HAIP (#119) and the custom mdoc profile (#120) remain separately qualified.

## My Number evidence decision before real intake

EF0003 includes DF31, a hash derived from the personal number, inside the signature preimage. The current intake sends it to the server to verify DF33; absence from D1/logs does not settle whether transmitting it is permissible. This change uses synthetic My Number evidence only and does not resolve the legal question or authorize real My Number intake/deployment.

There are two implementation choices to review before enabling real intake: retain server verification after an appropriate legal review of DF31 transmission, or verify DF33 locally and send an independently trusted attestation of only the normalized attributes/result. Local verification without trusted attestation weakens the server's independently verifiable evidence: an ordinary client can fabricate its verification result. Removing DF31 from the signed preimage would invalidate verification and is not a supported shortcut. The pending decision is tracked by #208 and the #116/#117 activation/qualification gates. No source hash is added to credentials or presentations.

## Correlation and deferred work

Minimum disclosure does not provide unlinkability. Reusing one credential repeats its signed issuer JWT/MSO, issuer signature, disclosure hashes/item digests, holder public key and salts. The issuer key ID/`x5c`/document-signer chain can identify an issuer or a smaller issuance cohort. `iat`/MSO validity and evidence verification timestamps, source document kind and trusted-card-key ID can narrow that cohort further. Card DS certificates/DF31/DF33/raw evidence are not presented, but credential DS certificates are. Fresh salts alone cannot prevent linkage when the same credential is reused.

The native Wallet now treats a complete authenticated **age-only** receipt as single use: it has one or both supported age predicates and none of the supported raw attributes. This is derived from all verified disclosures/items, not from the selected fields, a UI marker or a persisted flag. Both true and false predicates use this policy. A mixed raw/age profile remains reusable even if a request selects only its age predicate. Each issuance already creates a separate holder key; this change prevents repeating an age-only credential's signed bytes and holder key through this Wallet.

After owner approval, the Wallet prepares the proof and revalidates the exact reviewed selection. Before HTTP or proximity dispatch it atomically stores the entire remaining encrypted inventory, clears the in-memory single-receipt cache and deletes the consumed Android holder keys. Multiple queries selecting one receipt retire it once; unrelated receipts remain available. The same policy covers plain/encrypted OID4VP, multi-credential responses, QR/BLE/NFC proximity and type-only requests that still expose credential proof information. Denying a review does not retire a receipt. Storage failure prevents dispatch and key deletion; successful retirement cannot be undone by a failed/unknown send, a rejected response, cancellation, expired request or failed browser completion. A key-deletion failure also suppresses dispatch while keeping the committed retirement. The owner needs a different unused receipt for the next presentation.

The encrypted inventory codec writes version 4 and supports an empty inventory as a durable tombstone. Legacy single records and nonempty version-3 inventories migrate after full validation; unknown schemas and profile downgrades fail closed. The Android AtomicFile write is read back as exact bounded ciphertext before acknowledgment, and the existing synchronized plugin methods serialize its accesses; see [AtomicFile's commit and locking contract](https://developer.android.com/reference/android/util/AtomicFile). The wrapping key stays available to authenticate an empty tombstone. No receipt, private key or consumed-credential fingerprint is sent to browser storage or a server ledger by this retirement path. Old binaries cannot interpret the new inventory; a downgrade must not restore spent keys or an old backup.

This is a local Wallet reuse policy, **not a cryptographic unlinkability guarantee or a verifier-wide spent list**. Other implementations could replay the underlying credential. Shared issuer keys/certificates, source metadata and validity/verification timestamps can still identify a cohort. Desktop keys/inventory are in memory; persistent retirement and Android Keystore deletion still need physical-device/crash qualification under #117. Add restart-after-success, interrupted storage write, process termination after retirement but before send, failed/unknown HTTP/BLE delivery and last-slot consumption to that procedure. Verify that unrelated receipts survive and neither the receipt nor its holder key can be selected again.

The experimental first-party **card intake** path supports one approved age-only batch of two to eight receipts with `IDENTITY_ENABLED=true`, `IDENTITY_AGE_BATCH_ENABLED=true` and an age-only `IDENTITY_ISSUANCE_CLAIMS` profile. It is disabled by default and when HAIP is enabled. The native reader defaults to one receipt; the owner explicitly selects a larger count. Intake accepts `holder_jwks` plus `credential_configuration_id` instead of the existing single `holder_jwk`. It stores the exact distinct public keys, count, format and canonical claim profile in the existing transaction's `holder_json`. The owner review shows every key identifier and the exact issuance terms. Linking without issuance still grants no receipt authority. No database migration is required.

The Credential Endpoint uses an ordered `proofs.jwt` array, one signed proof for each prebound key with a shared one-use nonce. It requires the exact approved count/order, configuration and unchanged age profile; disabled flags, substituted/repeated/missing keys, another format or inconsistent nonces fail before consumption. Each credential has independent salts, one fresh holder key and the existing at-most-five-minute validity clipped by every verified deadline. All credentials and optional authenticated response ciphertext are prepared before the existing atomic transaction/nonce consumption; only one concurrent request can return a batch. An unknown/failed delivery has no automatic retry, refill or new grant.

The Wallet checks capacity (at most eight **total** unexpired receipts, including existing slots) before starting. It verifies the entire response's count, signatures, holder bindings, format, exact age-only profile and deadlines before a single complete inventory write. Missing, reordered, duplicate, malformed or mixed/raw credentials abort the whole batch; persistence failure leaves the in-memory inventory unchanged, and uninstalled keys are discarded. Cancellation continues to invalidate in-flight work. Local single-use retirement applies independently to each installed receipt. Real Android Keystore/crash qualification remains part of #117.

Discovery exposes only `mikaki_age_batch_intake: {"batch_size":8}` for this scoped extension. The [OID4VCI 1.0 Final batch model](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-12.2.4) uses multiple proofs in the ordinary Credential Endpoint and `credentials` in its response; a separate batch endpoint is unnecessary. We do **not** advertise the standard global `batch_credential_issuance` capability because authorization-code/HAIP proof batches are not implemented. Those paths retain their existing per-key verification/attestation requirements and budgets (one for the non-HAIP public Wallet path; up to sixteen sequential issuances for the HAIP grant). The opt-in [HAIP age receipt pool](identity-haip-age-pool.md) now applies exact consent and independently attested holder enrollment to two to eight sequential single-credential requests, followed by one inventory installation. A multi-proof HAIP request/response remains follow-up work. No production flag, real-card activation or privacy-assurance claim is enabled by this change.

PR #212 delivered the Wallet path. The [OP follow-up and civ boundary](identity-op-age-and-civ.md) adds separately consented age predicates, a bounded internal ASC parser and an experimental custom-claim PAR/code/token binding with signed minimal UserInfo and mandatory response audit. A qualified trust framework/person-account binding remains a follow-up; no general ASC/`verified_claims` wire capability is advertised. The [Identity Assurance adoption boundary](identity-assurance-adoption.md) still applies.
