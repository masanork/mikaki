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
