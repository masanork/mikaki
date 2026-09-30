# FIDO2 Server certification preparation, 2026-09-29

This is a reviewable preparation record, not a certification claim or submission. No result, contract, registration, or payment has been sent by this task.

## Implementation and evidence

Candidate implementation: Mikaki Rust WebAuthn verifier plus the isolated server adapter. The native adapter uses synchronous SQLite transactions; the Wasm adapter runs the same verifier in Node. The conformance adapter supports broader algorithms and attestation than the default product passkey policy. A certified scope must name the implementation/version, protocol/profile, deployment and configuration being submitted; test-adapter success alone does not certify the OIDC product or Workers deployment.

Tools 1.9.2, all Server Tests and all ten optional checkboxes selected: latest native **167 passes / 0 failures** (2026-09-29, 8.97 s); Wasm **167 / 0** (2026-09-29, 14.26 s). See [detailed results](../local/conformance/results-2026-09-28.md). MDS was explicitly `mds3.0` because the service BLOBs omit the header `iat` required by 3.1.1. The strict default is retained. These were development runs, not official test submissions. ES256K is implemented and independently tested; the installed suite marks its test pending and does not execute it.

Independent fixtures exercise added RSA-PSS, RSA PKCS#1 SHA384/512, P-384/P-521/secp256k1, Android Key DER, MDS ES256/RS256, malformed keys/signatures, algorithm mismatch, and revocation. Parser fuzzing and the operation adapter provide supplementary regression evidence. Physical authenticator checks require the operator and available devices; their absence is documented in the [device matrix](webauthn-device-compatibility.md).

## Official process and outstanding inputs

The [official server certification page](https://fidoalliance.org/certification/functional-certification/functional-certification-servers/) requires conformance self-validation, including MDS tests, and confirmation of submitted results by the Secretariat at least fourteen days before an interoperability event. It distinguishes development runs from official runs recorded by the tools. The page links the active FIDO2 Server Requirements v2.3 (2026-02-26), registration, and interoperability testing. Passing this installed tool does not establish complete coverage of that active requirements document.

Before an official run, the operator must choose the exact product/version and freeze a reproducible source revision and configuration. The current workspace has other ongoing changes and was not committed or presented as a frozen candidate. Prepare a clean release checkout, record its commit, build/tool versions, selected algorithms/attestation, MDS profile, and store the tool-generated evidence from the official run.

The applicant must provide legal entity/contact, product/version, certification account and intended protocol scope; review the applicable agreements and current fees; and arrange the required interoperability testing. The user must approve any binding terms/payment and supply the applicant details before those external actions. Nothing in this draft authorizes sending them.

A practical submission packet should contain the frozen configuration and source identifier, official conformance records, interoperability evidence, requirements mapping for the actual deployment, and the required applicant forms. [Test startup and restart](../local/conformance/README.md) and [MDS operation](webauthn-mds-operation.md) now provide the reproducible development setup. The public-feed `iat` issue needs resolution or an explicitly accepted certification profile before claiming MDS 3.1.1 compliance.
