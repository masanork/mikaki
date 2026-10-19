# SonarQube Cloud initial findings review

The 2026-10-17 review uses main analysis `ff24024db5e69ab63ac21ace491ae7f1b8fecc0d`
(09:30:40 UTC). It reported 94 open security, 163 reliability and 819 maintainability
findings. Quality dimensions can overlap. The passing new-code gate does not mean
these existing findings were resolved.

The [review inventory](sonarqube-triage-2026-10-17.json) records every security issue
key, source location and disposition, all 89 high reliability sorting findings,
and the complete remaining rule counts. Line numbers refer to that analysis.
Repository dispositions describe code review, not an automatic change to Cloud
issue status. Findings fixed by this change need analysis of the merged code.

## Input and file handling changes

- Android Wallet preflight resolves SDK/APK paths before invoking SDK tools and
  explicitly uses `shell: false`. An APK filename beginning with `--` cannot become
  a tool option. Tests also exercise spaces and shell metacharacters. SDK selection
  remains an operator trust decision: choosing an SDK permits executing its tools.
- Device reports use exclusive creation (`wx`, mode `0600`). Existing files and
  symlink targets cannot be overwritten. Use a new report filename for each run.
- Production promotion and prepared-upload verification accept only direct
  `artifacts/promotion-XXXXXX` directories from this checkout. Canonical-path checks
  reject redirected promotion directories and redirected `artifacts` parents.
  Release manifest, source, archive and bundle verification still run afterward.
- The disposable OAuth container probe uses `/probe/logs` rather than a fixed
  `/tmp/probe-logs`. Host-side temporary files already use `mkdtemp`.
- Android App Links output is parsed per trimmed line, so a newline cannot join
  two values into a successful check. Digest parsing excludes whitespace in the
  verified APK path. USTAR octal fields use a bounded NUL lookup instead of a
  backtracking expression.
- The explicit U+FFFD test fixture uses a Unicode escape to preserve the malformed
  input test while avoiding Sonar's source-encoding warning.

## Reviewed security contexts

| Context | Findings | Review and retained boundary |
| --- | ---: | --- |
| PATH-selected tools (`S4036`) | 58 | Local build, evidence, release and capture helpers use the operator/runner toolchain. All reported calls use argument arrays; several executables already have explicit paths. CI images and developer PATH must be trusted. These tools do not sandbox arbitrary agent instructions. |
| Git SHA-1 (`S4790`) | 7 | Existing Git object IDs and pack checksums require the repository's SHA-1 object format. Disclosure, consent and artifact commitments retain SHA-256. See [Git copy](work-git-copy.md) and [composition](work-preparation-compose.md). |
| Other standard SHA-1 identifiers (`S4790`) | 5 | X.509 subject-key identifiers, U2F metadata identifiers, UUIDv5 and macOS signing identity lookup require their existing encoding. This does not authorize SHA-1 signatures or new issuance. |
| TPM SHA-1 compatibility (`S4790`) | 1 | Verification compatibility is intentional and policy bounded; it is not a false assertion that SHA-1 is strong. Retain the algorithm allow list, [ADR 0008](adr/0008-webauthn-conformance.md) and [crypto agility policy](crypto-agility.md). |
| HTTP event URI (`S5332`) | 4 | `http://schemas.openid.net/event/backchannel-logout` is an exact claim member identifier. No HTTP request is made to it. Replacing it with HTTPS breaks the protocol. |
| Structured logs (`S5145`) | 2 | Both reports use `JSON.stringify`; embedded newlines are escaped. The upstream pin report additionally validates commit/version syntax. |
| Policy revision log (`S8689`) | 1 | The logged revision is a validated SHA-256 policy identifier, not a secret. `validateWorkerPolicyProjection` verifies syntax and the projection digest before logging. |
| Explicit operator file operands (`S8707`) | 10 | Configuration, SDK, APK, policy and output selection are CLI capabilities of a trusted operator. Strict parsers, dry-run/remote choices and existing exclusive writes apply. A service must not pass untrusted remote/LLM paths into these CLIs without an authorization boundary. |
| Hardened command/file inputs and probe directory | 6 | Two APK invocation findings, one report output, two promotion findings and the probe directory are addressed above. Regression tests cover the exploitable interpretation and file-redirection cases. |

References: [Node child-process semantics](https://nodejs.org/api/child_process.html),
[OpenID Back-Channel Logout events claim](https://openid.net/specs/openid-connect-backchannel-1_0.html#LogoutToken),
[RFC 9562 UUIDv5](https://www.rfc-editor.org/rfc/rfc9562.html#name-uuid-version-5),
and the repository's [attestation policy](webauthn-attestation.md).

Cloud review on 2026-10-17 marked the four event-URI, three logging and 89
sorting findings as false positives, with the reasoning recorded on each issue.
Compatibility and operator-boundary findings retain their review rationale in
this inventory; they are not represented as code fixes. Code-hardening findings
remain open until the merged code is analyzed.

The PR analysis also reported four `S8707` flows at the SDK listing, APK read,
exclusive report creation and validated promotion-directory `stat`. Each was
reviewed as a false positive with the specific operand purpose, preceding checks
and regression evidence recorded in Cloud. See `pullRequestReview` in the inventory.

## Reliability and maintainability follow-up

All 89 high reliability findings are `S2871` suggestions to use `localeCompare`.
The reported sites compare string field/name sets or generate deterministic
protocol and evidence ordering, rather than human alphabetical presentation.
Default UTF-16 ordering is deliberate. Entry-array sorts in the service catalog
and checkpoint comparison likewise operate on unique, constrained field names.
A locale comparator would change canonical ordering across environments. Keep
this review specific to the recorded sites; numeric or user-facing sorting needs
its own comparator.

The other 74 reliability findings include error-constructor style (26), regular
expressions (15), promise-returning functions without `await` (12), binary byte to
character conversions (11), and smaller API/style suggestions (10). Five regex
findings in Android preflight and USTAR parsing are addressed here. Remaining
regex sites operate on repository Markdown, generated HTML or local SQL; their
parsers should be refactored with dedicated malformed-input fixtures before
expanding their input trust boundary. Removing `async` from rejection-only or
RPC methods can change synchronous exceptions into a different public contract;
`fromCharCode` in byte/base64 codecs is not a Unicode text decoder.

The maintainability inventory includes 300 awaits inside loops, 74 Rust wildcard
imports and 85 complexity findings. This pass does not claim those 819 findings
are individually resolved. Sequential database/crypto/protocol operations need
ordering and failure semantics preserved; test-module `use super::*` is deliberate.
Complexity and readability refactors remain tracked by the inventory and live
Cloud issue keys. Keep the advisory gate while those changes are qualified in
small, behavior-tested units. No rule-wide exclusions or `NOSONAR` blanket
suppressions are added.

### Parser follow-up (2026-10-18)

The ten remaining `S8786` sites in the 2026-10-17 inventory are addressed by
replacing the Markdown and HTML extraction expressions with parsers, and by
filtering local SQL fixture comments one line at a time. Markdown reference and
heading extraction uses the site's existing GFM parser versions. HTML inspection
uses the existing parse5 version, including browser rules for duplicate
attributes, entities, comments and raw script text. Heading labels are escaped
when inserted into generated HTML after extracting decoded text. The local SQL
helper still accepts the same restricted semicolon-separated fixture format.

`npm run test:markup` covers source locations, balanced link destinations,
Unicode and duplicate heading slugs, code fences, HTML attributes and SQL token
separation. A child process with a timeout checks long unfinished markup and
whitespace so a synchronous backtracking regression cannot hang the test runner.
The suite runs in core CI. These changes require a fresh Cloud analysis before
the corresponding findings can be counted as closed.

### AST transport follow-up (2026-10-18)

The main scan of `a4956c74` logged four invalid-UTF-8 Protobuf deserialization
errors despite completing analysis. Four test files contained eight string
literals whose decoded values include deliberately unpaired UTF-16 surrogates:
owner-note validation, selected agent record grants, WebMCP input validation and
thread search query validation. These are valid JavaScript fixtures in valid
UTF-8 source files; their decoded values cannot be transported as Protobuf UTF-8
string fields.

The SonarJS `14.1.0.46226` serializer puts decoded literal values in
`Literal.valueString`. A local reproduction used its pinned
[serializer](https://github.com/SonarSource/SonarJS/blob/dce7aac558697a3d1b3b4163820e394af561da29/packages/analysis/src/jsts/parsers/ast.ts),
[schema](https://github.com/SonarSource/SonarJS/blob/dce7aac558697a3d1b3b4163820e394af561da29/packages/analysis/src/jsts/parsers/estree.proto),
parser `8.71.0`, TypeScript `6.0.3` and protobufjs `8.8.0`, with `protoc 36.2`
decoding the resulting AST messages. All four original files failed UTF-8
decoding; all four modified files decoded successfully. Runtime construction
with `String.fromCharCode` retains the exact malformed code units while keeping
the AST's literal strings well formed. Unicode validation and the production
surrogate-rejection expressions are unchanged. No test or analyzer exclusion is
added. All 484 scoped JavaScript/TypeScript files parse without malformed decoded
string literals after the change. The four changed suites retain their rejection
and positive Unicode cases.

This reproduction identifies a transport incompatibility, not a defect in the
application's Unicode validation. Cloud verification must reanalyze these changed
files; a PR analysis that merely reuses cached ASTs would not prove the fix. Main
needs its own post-merge scan before the original scan errors can be considered
cleared there.

### Built-in API follow-up (2026-10-18)

Main analysis `420d92d2` reports 59 open reliability findings. This pass addresses
26 `S7723` sites with explicit `new Error(...)`, four `S7773` sites with
`Number.NaN` or `Number.parseInt`, and five `S7781` sites with string `replaceAll`.
The native Error constructor accepts both invocation forms with equivalent
behavior ([ECMAScript](https://tc39.es/ecma262/2022/multipage/fundamental-objects.html#sec-error-constructor)).
Error messages, catch boundaries, numeric validation, radix 16, replacement order
and exact literal matching are retained. Existing MDS, logout, native Wallet,
Git packet, website and workerd bridge tests qualify the changes.

The remaining 24 reliability findings require separate contract review: 12
promise-returning functions (`S7503`), 11 byte/code-unit conversions (`S7758`)
and one default object parameter (`S7737`). Removing `async` can change rejected
promises into synchronous throws, and byte/base64 codecs require their existing
code-unit semantics. These sites retain their implementation and issue status.
No analyzer exclusions are added. A fresh Cloud analysis is required to confirm
closure of the 35 changed sites.

The first PR scan reported no new reliability or security issues, but failed its
coverage gate because the existing archive handoff tests were not included in
the Node coverage runner. Add that suite to the measured run rather than exclude
the changed file. Its sequence-ID rejection cases also cover missing/non-string
IDs, non-ASCII digits and unsafe integers. The same expression uses `\d` for the
trailing ASCII digits to address the scan's `S6353` style finding without changing
the accepted IDs.

### Contract follow-up (2026-10-19)

Following PR #264, this pass addresses the 24 retained reliability findings in
source reviewed at `d712895b`. No Cloud issue dispositions, rule exclusions or
quality-gate thresholds are changed.

- Twelve `S7503` sites retain their Promise contracts. D1 capabilities that always
  refuse now return explicit rejected promises. Database, qualification RPC and
  asset-fetch adapters keep `async` and await their delegated operation, so setup
  errors still become rejections. The two private WebMCP projection callbacks
  return plain values to guards that accept either a value or a Promise; the
  guards still await the result between their existing authority checks.
- Eleven `S7758` sites use code-point APIs with their input domains preserved.
  Base64 helpers operate on `Uint8Array` elements or `atob` byte strings, whose
  values are all in 0–255; this is not UTF-8 decoding. Woven material still hashes
  the canonical URL origin and retains its established profile. Note validation
  iterates code points, accepting complete surrogate pairs while rejecting lone
  surrogates before UTF-8 encoding. It does not replace malformed input.
- The `S7737` inventory budget is initialized by a factory for each independent
  call and passed unchanged to recursion. Explicit caller-supplied budgets still collect
  shared entry/byte usage. An explicit `null` remains invalid. No shared default
  object or module-level counter is introduced.

Tests verify rejected D1 promises without service dispatch, all 256 byte values
against Node's independent Base64url encoding, all 2,048 lone surrogates and valid
boundary pairs, the retained woven profile, and independent/concurrent inventory
calls with shared recursive limits. Existing RPC, WebMCP, recipient, logout,
helpdesk and website suites remain in use. The frontend coverage run includes the
WebMCP and woven-profile suites so changed UI code is measured. Main needs a
post-merge scan before these 24 findings can be counted as closed there.

### Helpdesk request routing follow-up (2026-10-19)

Source at `31d853a7` has two Helpdesk RP complexity findings: the request
handler (`S3776`, 92) and backchannel logout handler (22). Separate configuration
validation, demo-only routing, public help pages, authentication endpoints,
ticket routing and localized error rendering. Reuse the existing OIDC logout
implementation. The demo allowlist and rate limiter still run before shared
routes, CSRF validation and session checks. Await every delegated route so
rejections reach the request's existing error boundary.

Backchannel logout now separates bounded form decoding and cryptographic token
verification from claim validation and session revocation. Body/token limits,
fatal UTF-8 decoding, JWT header restrictions, issuer/audience/algorithm checks,
claim checks, primary session reads and tombstone writes retain their order.
Named HTML fragments remove five nested-template findings in the moved pages
without changing their contents. The local SonarJS rules reproduce the original
scores; the request handler is now 7, backchannel is 6, and all extracted
functions are at most 14 against the existing limit of 15. Cloud must confirm
these results on the final PR revision.

The existing passkey/ticket and login-demo browser scenarios remain. Additional
real Worker tests cover method/origin rejection, malformed and oversized logout
bodies, independent rate limits before CSRF/session checks, and localized 503
responses when delegated database operations fail. No rule exclusions, issue
dispositions or quality-gate changes are made.

### Agent Worker routing follow-up (2026-10-19)

Source at `71d7c1dd` retains three complexity findings in the Agent Worker:
tool execution (27), the private owner entrypoint (38), and public fetch (34).
Separate snapshot/operation dispatch, authenticated owner handlers, public OAuth
routing and public record proposals. The existing named owner entrypoint remains
separate from public fetch; caller-supplied owner headers cannot select it.
OAuth enablement, exact method/query/origin guards, body limits and bearer
challenges retain their existing endpoint-specific behavior.

Tool execution still checks the active grant before dispatch, awaits the audit,
rechecks the grant and expiration, refreshes record-proposal receipts, and only
then attaches provenance and returns data. Recipient and initial grant failures
retain their outer error boundaries. Owner failures deliberately retain an
opaque 409 response so grant/storage details are not disclosed; the catch now
documents this rationale. Tool descriptions use a separate selector instead of
a nested ternary. No analysis rules, issue dispositions or gate settings change.

Local SonarJS reproduces all three original scores and reports 10, 14 and 12
after refactoring, with no extracted function above 15. The synthetic
Worker/SQLite suite adds public/private routing, disabled OAuth and rejected
service-call cases; its existing post-audit race and proposal retry tests remain.
The real workerd suites separately qualify the private OP bridge, OAuth PKCE,
SDK MCP calls, revocation, rollback and browser review. Cloud analysis on the
final PR and post-merge main revisions must confirm closure.

### DCQL selection follow-up (2026-10-19)

Source at `3aeabc57` retains `rust:S3776` on DCQL selection (75 against a limit
of 30) and a wildcard import (`S2208`). Separate credential type checks, claim
path validation, whole-query matching, set-reference validation and ordered
selection. Import the used names explicitly. Validation still covers every
query and option before selecting credentials, including optional/nonmatching
entries. A potentially matching query's fields are checked before receipt
availability is considered. Authority validation retains its own error code.

The bounded wallet profile still chooses the first complete option for every
required set, merges indices in first-seen order, and omits optional sets when
required sets exist. Its existing optional-only fallback chooses the first
complete option across sets. Missing required credentials never yield a partial
result. Array/string limits, byte-based identifiers, supported formats, claim
retention and error categories are unchanged. See
[OpenID4VP credential selection](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#name-selecting-credentials)
for the surrounding protocol; this change does not extend the supported profile.

Five focused unit tests cover all 256 availability masks for eight credentials
using independent bit-mask expectations, ordered/deduplicated required-set
unions, optional-only fallback, validation errors on unselected entries, maximum
query/set/option dimensions and availability-length mismatch. Existing signed
request, mixed SD-JWT/mdoc inventory, authority, encrypted response and retrieval
one-use tests remain. Native coverage measures the changed Rust source. Cloud
analysis must verify the final PR and merged revision; no exclusions, issue
dispositions or gate thresholds are changed.

### Credential certificate validation follow-up (2026-10-19)

Source at `51697fd5` retains `rust:S3776` on credential certificate parsing
(92 against a limit of 30). Separate certificate header/public-key checks,
extension allowlisting, key usage, basic constraints and the mdoc profile's
subject, identifiers, signer purpose and CRL distribution points. The parser
still runs these stages in their original order, including SD-JWT's distinct
`unsupported_credential_eku` error after key usage and before basic constraints.
Subject attributes retain their encoded traversal order, including across
multi-valued relative distinguished names.

Six added tests cover exact validity boundaries, accepted/rejected subject
encodings, contact alternatives, key identifiers, exact signer EKU, partial or
indirect CRL pointers, forbidden extensions, malformed extension DER, CA/leaf
usage and error priority. These tests also pass against the original parser.
Existing chain, pinned-key receipt and fail-closed offline revocation suites
remain. Certificate URLs are never fetched and trust still comes from separately
provisioned roots or the caller's independently pinned key.

The retained `S4790` site compares the existing SHA-1 subject-key identifier
profile with the public-key bits; it does not select the certificate signature
algorithm. This identifier form is described in
[RFC 5280 section 4.2.1.2](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.2).
Signature verification remains P-256/SHA-256. This refactor leaves that profile
and finding unchanged. No rule exclusions, issue dispositions or gate thresholds
change. Cloud must confirm the final PR and post-merge results.

### Work owner routing follow-up (2026-10-19)

Source at `66ac9af8` retains `rust:S3776` on the Work owner HTTP handler
(135 against a limit of 30). Represent supported method/path combinations as
private routes and separate input guards, authenticated dispatch, session leases,
listing, revocation, preparation composition, copy consent and copy execution.
Feature gates still run before Origin, identifier/query validation and ingress
admission. Source/review routes keep their existing delegated handlers.

Ingress admission, D1 access, live SSO lookup and request-scoped store creation
retain their order. Session leases still recheck SSO after checkpoint I/O.
Copy account configuration is checked before body parsing. Content types,
256/4,096/16,384-byte body limits, JSON depth limits, version/digest checks and
endpoint-specific validation remain unchanged; revocation retains its existing
Serde validation. Expected input refusals remain HTTP responses and header
transport errors retain the outer Worker error boundary. Cleanup still requires
the current review digest before it can stop a copy job, then rereads the result.
Storage failures retain the existing opaque 503 response.

Two additional workerd/D1 test matrices verify disabled/unsupported routes,
length limits, Origin and identifier/query rejection before ingress, and
authentication before mutation JSON validation. They pass against the original
handler as well as the refactor. Existing product entry, stale checkpoint,
owner/session isolation, audit rollback, compose, consent and Workflow/Git copy
suites qualify the extracted operations. Worker Rust remains outside the
existing native coverage scope; these runtime tests do not claim a coverage
percentage. Cloud must verify the final PR and merged revisions.

The product journey also waits for the independently loaded Owner note's
`aria-busy` state to clear before testing manual lock. Clicking during that read
correctly asks to discard unfinished work; Playwright's default dialog dismissal
had intermittently kept the Vault open. The explicit readiness assertion keeps
the existing lock and authenticator assertions. No analysis rules, issue
dispositions or gate thresholds change.

### Operator CLI startup follow-up (2026-10-19)

Source at `e0cf323a` retains five `typescript:S7785` findings in authority
allocation/completion, offline deployment preparation, source registration and
reviewed auth-GC settlement. Use top-level `await` inside the existing direct
entrypoint guards, with explicit `try`/`catch`. Keep JSON serialization and
stdout writes inside those error boundaries. Allocation/completion retain their
Error-message and non-Error fallback handling; the other tools retain their
fixed redacted messages. Failure still sets `process.exitCode = 1`, and each
operation's awaited cleanup remains in its existing function.

Existing allocation, completion, deployment, source-version and local
workerd/D1 GC recovery suites pass all 38 tests. Eight additional smoke cases
run copied source modules in a disposable unborn Git checkout: importing all
five modules, caught failures in each CLI and the two usage errors. Before/after
results have identical exit statuses and byte-for-byte stdout/stderr, including
the fixed messages that omit raw arguments. These checks preserve the existing
operation guards, journal identities and recovery behavior. Final PR and
post-merge Cloud analyses must confirm closure; no rule settings, issue
dispositions or coverage exclusions change.

## Coverage regression checks

`npm run test:frontend-coverage` now includes existing owner-key cryptographic
vectors, record userinfo/approval tests and the new client-side owner-store suite.
The store suite uses the real scope and cryptography with controlled transport
responses. It verifies owner/credential/revision binding, ETags, strict wrapper
registries and receipts, exact operation retries, lost-bootstrap reconciliation,
conflicts and invalidation during PRF, and additive login custody.

Selected-module line/branch floors now also cover owner crypto (95%/80%), owner
store (85%/85%) and owner session (95%/65%). Node/V8 executable-line percentages
are not the same denominator as Sonar's imported combined coverage metric, and
they do not measure Svelte DOM or workerd execution. Existing Worker integration
and browser tests remain separate.
