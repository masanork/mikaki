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

For unlinkability across RPs/presentations, a later batch/single-use design is needed. A candidate is at most eight credentials per explicit grant, each with a distinct holder key and independent salts, the existing maximum five-minute validity bounded by every verified deadline, and atomic Wallet retirement after one presentation. This is a design candidate, not a granted budget or an implemented privacy guarantee. The current one-grant/one-credential budget remains unchanged. Issuer/cohort correlation and the attestation/consent impact require review even with fresh credentials.

OP-transformed claims remain deferred until this Wallet path is qualified. No ASC request parser, `claims` parameter, `verified_claims`, trust-framework advertisement, new UserInfo release path or Discovery capability is added. The [Identity Assurance adoption boundary](identity-assurance-adoption.md) still applies; the existing identity release consent and Vault system-recipient/ClaimRelease design must be settled before introducing an OP predicate response.
