# OP age predicates and the civ consumer boundary

Follow-up to #208 / PR #212. The existing, disabled-by-default Identity UserInfo profile now supports `age_over_18` and `age_over_20` under `mikaki_linked_document.attributes`. The account owner grants each predicate explicitly for one RP on `/identity`; authorizing the calculation does not authorize disclosure of the birthdate value. Existing raw-attribute permission does not implicitly authorize a predicate. Replacing or revoking a release preserves the existing consent-version checks.

The OP checks the token's profile scope and current RP/account/connection/document consent, key policy and document deadlines before calculating the predicate on the UTC response date. An invalid/future birthdate makes the linked-document response unavailable. Only granted fields are returned. Predicate evidence preserves the original source verification time, adds `predicate_verified_at` for the calculation and a consumer-authored `electronic_record` description. It contains no raw attributes, card signature, DF31/32/33, PIN, reader identifier or personal document number. Static assurance, lack of live-card possession and `government_credential=false` remain explicit. A current key-policy check is not a card revocation check.

The existing JSON path remains a custom UserInfo claim over HTTPS. A second, **experimental custom-claim ASC subset** now accepts authenticated PAR requests and returns signed UserInfo, described below. Neither path is a qualified ASC/OID4IDA `verified_claims` profile. Discovery continues to report `claims_parameter_supported=false`; it does not advertise general transformed-claim functions or `verified_claims`. The [Identity Assurance adoption boundary](identity-assurance-adoption.md) remains in force.

Other independently consented `profile` claims, such as an owner-entered Vault name, retain their existing release rules in the legacy JSON path. A token bound to an experimental age request selects only the requested predicates across the entire signed UserInfo response; it never invokes Vault name delivery or falls back to broader JSON after withdrawal.

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

The `verified_claims` shape above remains internal and is rejected by the wire adapter. The experimental adapter uses the same bounded transformation validation at a custom claim location. ASC requires integrity protection for custom transformations; an unprotected browser query must not select a transformation or change an age threshold. General Discovery support remains gated on a named RP/profile qualification, including function metadata (`years_ago`/`gte`, depth 2, count 2).

## Authenticated request and signed response

Opt in only for a test deployment with `IDENTITY_ENABLED=true`, `IDENTITY_USERINFO_ENABLED=true`, `IDENTITY_AGE_REQUESTS_ENABLED=true` and `MIKAKI_PAR_MODE=required` (or the existing FAPI mode). None of these flags is enabled in production by this change. Migration `0004_identity_age_requests.sql` adds immutable code-bound request rows, a current-eligibility view and response audit records; the owner readiness and exact schema/byte inventory gates include this additive migration. The immediately preceding waitlist binary has the narrow complete-ledger bridge. Older fourteen/fifteen-migration authority packets remain verifiable without acquiring new migration bytes or capabilities.

Send this `claims` JSON as a form parameter at `/par`, using the RP's current registered `private_key_jwt` authentication and existing redirect/PKCE controls:

```json
{
  "userinfo": {
    "mikaki_linked_document": {
      "attributes": {":age_over_18": null}
    }
  },
  "_asc": {
    "transformed_claims": {
      "age_over_18": {"claim":"birthdate","fn":["years_ago",["gte",18]]}
    }
  }
}
```

The source location is relative to `mikaki_linked_document.attributes`. Only `openid profile` / `profile openid` are accepted. Both 18/20 aliases may be defined/requested within the two-definition/two-claim limit; unsupported locations, raw fields, duplicate members, custom thresholds and ID Token delivery fail closed. The authenticated PAR query is authoritative, consumed once, and never overridden by browser parameters. Browser `claims` parameters are rejected, including alongside a valid `request_uri`.

Authorization requires the exact predicate's current RP release; birthdate disclosure consent does not authorize derivation. Missing permission yields `consent_required`; unavailable evidence or an unsatisfied boolean constraint yields `access_denied`. The exact request JSON/hash, requested fields, document and release version are inserted atomically with the code and PAR consumption. A later replacement of the release requires a new authorization, even if the same fields remain granted.

The bound access token selects a minimal `application/jwt` response with `iss`, the RP `aud`, the ID Token's pairwise `sub`, `iat`, `exp` and `mikaki_linked_document`. Requested attribute names retain the `:` reference prefix. Evidence remains consumer-authored static-source metadata without a trust-framework/person-binding assertion. No separately granted name/birthdate or other profile attributes are included. The OP's registered active ES256/RS256 key signs the response. Lifetime is at most 300 seconds and clipped to access-token, parent-session, release, document, trusted source-key and source-document expiry. An RP must check the signature, issuer, audience, times, exact requested predicates and `sub` equality with its ID Token; see [OIDC signed UserInfo validation](https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse).

After signing, a conditional D1 insert rechecks current permissions, account/client/connection revisions, token/session validity, the exact request/release/document snapshot, policy and signing-key generation/public JWK. It stores a digest of the signed response, request hash, RP/document/release identifiers, signing generation, static assurance and time bounds **before** returning the response. It stores no token bytes, raw attributes, full JWT or card bytes. Audit failure suppresses the response. Each code permits at most 100 audited responses; exceeding the bound fails closed and needs a new authorization. Audits record prepared-and-authorized responses, not confirmed network receipt. The source policy hash is the existing deployment policy check, not a card-derived public identifier.

Permission/feature withdrawal, unavailable predicates, stale policy or replaced releases yield no signed claims; a bound token never downgrades to the legacy JSON path. Bearer and DPoP token validation retain their existing rules, including proof replay protection and refusal of Bearer access with a DPoP-bound token. This local test profile does not add `userinfo_signed_response_alg` client registration or claim general OIDC claims/ASC conformance. Production activation, named RP integration, real cards and a qualified person/account binding remain separate work.

## Consent, framework and response decisions

Reuse `identity_claim_release` for predicate calculation/release permission, with the existing document/RP/client-revision/connection-version/account-epoch checks and expiry. Keep it separate from owner-entered Vault attributes and its system-recipient Grant/ClaimRelease: a self-entered Vault birthdate must not become a static-card predicate source. Consent permits deriving the named predicate from the source birthdate, while the raw value has an independent permission.

`jp_mikaki_card_static` is a **candidate identifier**, not a qualified or advertised trust framework. Its required scope would distinguish independently verified static document data, account-owner linkage, current source/key checks and predicate calculation from proof that the human account owner is the named cardholder. Current static linkage does not establish that last binding. OID4IDA defines verified claims in relation to a verified person/account binding; a civ holder-device verdict or owner click cannot supply it. The [OID4IDA schema](https://openid.net/specs/openid-ida-verified-claims-1_0.html) also permits a verification metadata object outside a `verified_claims` assertion, which is useful while retaining this boundary.

The experimental adapter implements signed UserInfo, request/release binding and audit at the custom claim location. Identity predicates stay out of the ID Token. The legacy JSON response remains available for tokens without an age request. Signing does not qualify the candidate framework or strengthen the static source assurance; a future qualified `verified_claims` response still needs the person/account binding and named RP/profile gates above.

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
npm run build:policy
node --test --test-concurrency=1 local/conformance/identity-userinfo.test.ts local/conformance/identity-age-request.test.ts local/conformance/dpop-worker.test.ts
```

The shared tests cover request bounds, substitution/duplicate JSON, function/source/framework/reference-date rejection, exact derivation consent, UTC birthday boundaries, unavailable values and attribute-free consumer evidence. The workerd test exercises actual RP-specific owner consent and UserInfo, including raw-to-predicate replacement, true/false values, disabled policy, invalid/future dates, stale policy, withdrawn/expired consent and stale-form rejection. The new end-to-end workerd suite executes authenticated PAR, owner consent, authorization, token exchange, independent Node JOSE ID Token/UserInfo verification, both OP signing algorithms, request substitution/replay rejection, response lifetime clipping, mandatory-audit failure, consent replacement/withdrawal, false predicates, unsatisfied boolean constraints, source/policy expiry and account revocation. Existing token/DPoP/account/document revocation regressions remain applicable. These are synthetic host tests; no real card, production activation or external civ runtime is qualified by them.

### Opt-in comparison against the committed civ verifier

```sh
# Create a clean separate checkout in the civ repository, without changing its active branch:
git -C /path/to/civ worktree add --detach /tmp/civ-kenmen-interop 7ed406dc4581b4fc9f8ed2ccb8e461147fc1a451
node scripts/probe-civ-kenmen-interop.ts --civ-checkout /tmp/civ-kenmen-interop --civ-commit 7ed406dc4581b4fc9f8ed2ccb8e461147fc1a451
```

The probe builds a disposable host consumer of both Rust libraries, sends only freshly generated synthetic signed inputs over stdin, validates the input commit/clean tree before and after execution, and prints only case/result metadata. It needs locally cached Cargo dependencies for `--offline`; it does not change civ, activate a profile or retain evidence bytes/keys. The caller chooses the exact civ commit explicitly, so this is opt-in qualification rather than a new mandatory upstream dependency.

The **13 cases** cover valid Gregorian/era dates, tampered attributes/signature/DF31 value, duplicated attributes, unknown/expired keys, truncated EF0003, signed invalid Gregorian/era dates, a future birthday and a wrong document-type trust policy. Both libraries agree on acceptance of valid data and rejection of the seven corruption/trust cases. Error categories differ without promoting a rejection into acceptance. The deliberate semantic differences remain visible: civ authenticates the raw invalid-date data, Mikaki rejects its date; both authenticate a future birthday, but Mikaki produces no age predicate; civ ignores the wrong document-type key label, while Mikaki rejects it. These results establish the required adapter checks, not permission to replace the current consumer with an unchecked `result=verified` test.
