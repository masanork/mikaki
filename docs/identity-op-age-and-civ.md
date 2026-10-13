# OP age predicates and the civ consumer boundary

Follow-up to #208 / PR #212. The existing, disabled-by-default Identity UserInfo profile now supports `age_over_18` and `age_over_20` under `mikaki_linked_document.attributes`. The account owner grants each predicate explicitly for one RP on `/identity`; authorizing the calculation does not authorize disclosure of the birthdate value. Existing raw-attribute permission does not implicitly authorize a predicate. Replacing or revoking a release preserves the existing consent-version checks.

The OP checks the token's profile scope and current RP/account/connection/document consent, key policy and document deadlines before calculating the predicate on the UTC response date. An invalid/future birthdate makes the linked-document response unavailable. Only granted fields are returned. Predicate evidence preserves the original source verification time, adds `predicate_verified_at` for the calculation and a consumer-authored `electronic_record` description. It contains no raw attributes, card signature, DF31/32/33, PIN, reader identifier or personal document number. Static assurance, lack of live-card possession and `government_credential=false` remain explicit. A current key-policy check is not a card revocation check.

This is the existing custom UserInfo claim over HTTPS. It is **not an enabled ASC/OID4IDA wire profile**. Discovery continues to report `claims_parameter_supported=false`; it does not advertise transformed-claim functions or `verified_claims`. The [Identity Assurance adoption boundary](identity-assurance-adoption.md) remains in force.

Other independently consented `profile` claims, such as an owner-entered Vault name, retain their existing release rules. Predicate-only Identity permission removes raw values from `mikaki_linked_document`; exact request-only filtering of the entire UserInfo response requires the future authorization-request binding described below.

## ASC request preparation

[ASC Draft 02](https://openid.net/specs/openid-connect-advanced-syntax-for-claims-1_0.html) defines transformed-claim definitions separately from their requested locations. A `:` prefix references a custom definition. The new shared `op_age::AgeRequest` parser covers only this bounded UserInfo candidate:

```json
{
  "_asc": {
    "transformed_claims": {
      "age_over_18": {"claim":"birthdate","fn":["years_ago",["gte",18]]}
    }
  },
  "userinfo": {
    "verified_claims": {
      "verification": {"trust_framework":{"value":"jp_mikaki_card_static"}},
      "claims": {":age_over_18":null}
    }
  }
}
```

This is an internal request/projection API and test vector, not a request accepted by `/authorize`. It supports the canonical 18/20-year aliases, exactly two functions per definition, at most two definitions/requested predicates, and boolean `value`/`essential` constraints. It rejects duplicate/escaped duplicate JSON members, unknown functions, aliases, source claims, raw-attribute requests, caller-selected reference dates, unsupported constraints, ID Token delivery, SAO and excessive input. Projection needs the exact predicate consent fields and returns no partial result if any requested predicate is unavailable or lacks permission.

Before connecting this parser to the wire, bind the full validated request to an authenticated PAR and then to the one-use authorization code/token. ASC requires integrity protection for custom transformations; an unprotected browser query must not select a transformation or change an age threshold. The current OP's ordinary authorization adapter does not do this binding. Advertise only `years_ago`/`gte`, depth 2 and count 2 after the complete wire path passes the intended RP's tests; request-parser tests alone do not establish support.

## Consent, framework and response decisions

Reuse `identity_claim_release` for predicate calculation/release permission, with the existing document/RP/client-revision/connection-version/account-epoch checks and expiry. Keep it separate from owner-entered Vault attributes and its system-recipient Grant/ClaimRelease: a self-entered Vault birthdate must not become a static-card predicate source. Consent permits deriving the named predicate from the source birthdate, while the raw value has an independent permission.

`jp_mikaki_card_static` is a **candidate identifier**, not a qualified or advertised trust framework. Its required scope would distinguish independently verified static document data, account-owner linkage, current source/key checks and predicate calculation from proof that the human account owner is the named cardholder. Current static linkage does not establish that last binding. OID4IDA defines verified claims in relation to a verified person/account binding; a civ holder-device verdict or owner click cannot supply it. The [OID4IDA schema](https://openid.net/specs/openid-ida-verified-claims-1_0.html) also permits a verification metadata object outside a `verified_claims` assertion, which is useful while retaining this boundary.

Choose **signed UserInfo**, rather than identity attributes in an ID Token, for a future qualified ASC response. Include the RP audience, pairwise subject, issuer, creation/expiration times and exact requested predicate/evidence projection; use an operator-controlled OP signing key. Bound its expiry to consent, token, document and key deadlines. Persist the exact request/release version and response digest in an audit before returning it; the RP can retain the signature as evidence. This signing/audit/request-binding path is a follow-up, not implemented by the current custom JSON response. Signing alone would not qualify the candidate framework or strengthen the source assurance.

## What civ contributes

The local civ checkout's `018-kenmen-evidence` specification explicitly assigns card reading and independently verifiable evidence to civ, and issuance/presentation to Mikaki. Reviewed planning commit: `e54c096974495f9b4a47b968535d4bbcb02f41ba` (`018-kenmen-evidence` branch). During this review, Phase 1–2 was committed as `7ed406dc4581b4fc9f8ed2ccb8e461147fc1a451`: PC/SC-free `civ-kenmen` now exposes raw EF parsing, static signature verification and consumer-selected trust. Its native suite passed **28 tests** and its `wasm32-unknown-unknown` library check passed in a separate immutable checkout. It is not a Mikaki production dependency or real-card qualification.

| civ work | Mikaki use | Acceptance boundary |
| --- | --- | --- |
| PC/SC-free `civ-kenmen` raw parser/verifier | Reuse static My Number signature verification | Pin a reviewed commit and preserve Mikaki's semantic/date validation and source-scoped trust |
| Planned APDU/date/JIS compatibility helpers | Eventually replace the selected `vendor/civ-card` subset | These exports are not in Phase 1–2. Require the complete API, license/provenance, native/Worker Wasm builds and current hostile-input/date/evidence regressions |
| DF32 framing and strict DF33 TLV verification | Share signed-preimage fixtures and rejection cases | civ proposes four framing candidates; Mikaki currently admits three. Any additional candidate must hash-match and independently parse to exactly the same four attributes; a plan is not real-card framing evidence |
| Consumer versus holder-device verification/evidence record | Reuse the data-check vocabulary and a common source-verification result | Reverify with Mikaki's own trust before consumer metadata; never import `_civ.verifier=holder_device` into an assured OP assertion |
| Trusted-key schema and capture procedure | Coordinate issuer-key IDs, validity and generation/framing qualification for #116/#117 | No card-supplied key automatically becomes trusted. Explicitly map document kind and optional provenance; the planned key shapes are not yet identical |
| Local ZK predicate research | Future proof that age derivation is backed by a trusted DF33 signature without uploading its private preimage | Needs implemented proving/verifying code, public-journal review, fresh nonce/audience binding, negative tests and measured Worker/device budgets |

The current vendor provenance remains pinned to civ commit `509a08d7b45e43f5f9b056b2453f66319dbe039f`. Its parser is deliberately lenient; Mikaki validates TLV input and original Gregorian/era dates before using it. A replacement must preserve era-boundary checks, year-zero/impossible-date rejection, future-date omission and the documented UTC/leap-day rule. Do not silently switch to an upstream year-offset conversion that accepts ambiguous dates.

civ accepts Mikaki's bare key array by ignoring extra `document_type`/`subject_key_identifier` fields; its own key type also permits `provenance`. **Filter to `document_type=my_number_card` before passing Mikaki's mixed policy to civ**: otherwise a key authorized only for a driving licence can verify an input-support signature when the key material matches. The cross-verifier probe exercises this difference. The reverse mapping into Mikaki must explicitly restore document kind and retain strict unknown-field handling. RSA/key validity and trust remain consumer-profile checks. `self_consistent` using EF0004 is not a trust verdict.

civ also separates its raw `civ-evidence/v1` package from its metadata record. The older `jpki_surface.card_ap` path can contain a personal number; it is not the new input-support package and is not an allowed Mikaki import shortcut. The proposed `jpki_input_support` package excludes EF0001 but contains DF31 via EF0003. One-shot delivery and user consent limit retention/distribution; they do not resolve the DF31 legal/transmission question. The existing [real-intake decision](identity-age-predicates.md#my-number-evidence-decision-before-real-intake) remains open.

civ's proposed local ZK proof is the relevant option for keeping DF31 **out of the server request**, while preserving independently verifiable backing. Ordinary local signature verification followed by an unsigned boolean is advisory. The research's engine/performance comparisons are planning material, not benchmark or interoperability evidence; no prover engine, circuit, nullifier or remote proving service is adopted here. DF31-derived nullifiers remain excluded from the design.

## Verification

```sh
cargo test --locked -p mikaki-identity
cargo clippy --locked -p mikaki-identity --all-targets -- -D warnings
worker-build --release crates/worker
worker-build --release crates/userinfo-claim-worker
node --test --test-concurrency=1 local/conformance/identity-userinfo.test.ts
```

The shared tests cover request bounds, substitution/duplicate JSON, function/source/framework/reference-date rejection, exact derivation consent, UTC birthday boundaries, unavailable values and attribute-free consumer evidence. The workerd test exercises actual RP-specific owner consent and UserInfo, including raw-to-predicate replacement, true/false values, disabled policy, invalid/future dates, stale policy, withdrawn/expired consent and stale-form rejection. Existing token/DPoP/account/document revocation regressions remain applicable. These are synthetic host tests; no real card, production activation or external civ runtime is qualified by them.

### Opt-in comparison against the committed civ verifier

```sh
# Create a clean separate checkout in the civ repository, without changing its active branch:
git -C /path/to/civ worktree add --detach /tmp/civ-kenmen-interop 7ed406dc4581b4fc9f8ed2ccb8e461147fc1a451
node scripts/probe-civ-kenmen-interop.ts --civ-checkout /tmp/civ-kenmen-interop --civ-commit 7ed406dc4581b4fc9f8ed2ccb8e461147fc1a451
```

The probe builds a disposable host consumer of both Rust libraries, sends only freshly generated synthetic signed inputs over stdin, validates the input commit/clean tree before and after execution, and prints only case/result metadata. It needs locally cached Cargo dependencies for `--offline`; it does not change civ, activate a profile or retain evidence bytes/keys. The caller chooses the exact civ commit explicitly, so this is opt-in qualification rather than a new mandatory upstream dependency.

The **13 cases** cover valid Gregorian/era dates, tampered attributes/signature/DF31 value, duplicated attributes, unknown/expired keys, truncated EF0003, signed invalid Gregorian/era dates, a future birthday and a wrong document-type trust policy. Both libraries agree on acceptance of valid data and rejection of the seven corruption/trust cases. Error categories differ without promoting a rejection into acceptance. The deliberate semantic differences remain visible: civ authenticates the raw invalid-date data, Mikaki rejects its date; both authenticate a future birthday, but Mikaki produces no age predicate; civ ignores the wrong document-type key label, while Mikaki rejects it. These results establish the required adapter checks, not permission to replace the current consumer with an unchecked `result=verified` test.
