# Phased adoption of ML-KEM and ML-DSA

**Implementation update, 2026-10-30:** The claim Worker now delegates ML-KEM-768, HMAC-SHA256, SHA-256 and AES-256-GCM to Workers Web Crypto. Existing record-v2 headers, info/AAD, 64-byte recipient seeds and authorization predicates remain unchanged. This change has local workerd and Chromium qualification; it has not been deployed or used to enable production sharing. ML-DSA product activation is a separate decision. SLH-DSA and FN-DSA are outside the current adoption scope.

**Previous production observations, 2026-09-24:** Production sharing remains disabled. The product browser sender and claim Worker receiver implement a candidate ML-KEM-768 HPKE envelope. An owner approval path stores an envelope and system Grant atomically and supports revocation when D1 policy permits. Node, Chromium, RustCrypto, SQLite, and local workerd tests exercise the pieces. A read-only production probe opened a synthetic product envelope with the live Secrets Store key and rejected owner/ciphertext substitutions. FIDO registration/assertion capture and verification tools are ready for hardware evaluation. Passkey enrollment and OIDC signing have not changed.

| Boundary | Current product | Next unit of work | Activation gate |
| --- | --- | --- | --- |
| Vault | Owner-only PRF → HKDF → AES-GCM wrapping; disabled system-sharing path and candidate ML-KEM envelope | Exercise the owner browser against production after public reachability is restored, review recovery and key failure behavior, then design RP-specific ClaimRelease | Public-key authenticity and continuity, standard KEM/AEAD composition, independent vectors, browser performance, and failure behavior |
| FIDO authenticator | Product registration/verification uses ES256 (COSE `-7`) | Measure support in actual authenticator, browser, and OS; add isolated ML-DSA-65 (COSE `-49`) registration/assertion verification | Successful enrollment and reauthentication on supported hardware, tamper and mix-up rejection, coexistence with ES256 credentials, and a defined enrollment policy |
| OIDC/JOSE | Production client authentication uses ES256; ID Tokens use ES256/RS256 | Probe RFC 9964 ML-DSA JWK/JWS interoperability | Check RP libraries, JWKS and rotation, HTTP limits, conformance profile, and signing-key custody before explicit per-client enablement |

ML-KEM establishes a shared secret for key delivery; it is not a passkey signature algorithm. ML-DSA signs but does not by itself improve the Vault's long-term confidentiality. Vault bodies already use AES-256-GCM, and owner data keys are wrapped under passkey PRF-derived keys. ML-KEM is relevant to delivery of a data key to another device or system recipient. The [grant and disclosure design](vault-claim-sharing.md) and authentic recipient public keys must come first. Do not invent a format that directly treats an ML-KEM shared secret as an AES key.

## Sequence before product use

1. Finish the [UserInfo recipient-key lifecycle](vault-recipient-key-lifecycle.md). D1 holds public keys and lifecycle state; the claim Worker's Secrets Store binding holds the private seed. Generation 1 is active; key identity and a synthetic product envelope were verified through the live binding. Define and exercise recovery before shared data depends on it.
2. The owner-only browser now creates an additional recipient envelope for a saved attribute's data key after PRF unlock. It binds origin, account, attribute, revision, service, key ID, and exact ciphertext in HPKE info/AAD. D1 stores the envelope, Grant, and audit atomically. The D1 policy starts disabled; attribute updates and policy disable revoke the Grant.
3. The claim Worker now checks decryptability before accepting a system Grant. A production synthetic probe verified correct and incorrect owner/ciphertext bindings. Test the full owner path, rotation, wrong key/revision/attribute substitution, and key-service failures across Worker and browser. Add RP-specific consent and ClaimRelease before UserInfo returns `name`. Owner-only Vault use must not require a PQC key or ML-DSA-capable FIDO device.

The system Grant only permits a future claim service to consider the attribute; it grants no RP access by itself.

An assigned COSE number does not establish support in an available FIDO device, browser, or OS. An existing credential cannot be converted to PQC on the server. Enroll a new credential on verified hardware and run it alongside ES256 before migration. Do not advertise `-49` in `pubKeyCredParams` until verification works, or label an implicit fallback as PQC support.

The September probe predates Cloudflare's [October 1 native Web Crypto support](https://blog.cloudflare.com/workers-ml-kem-ml-dsa-support/). Workers supports ML-KEM-768/1024 and ML-DSA-44/65/87 behind `webcrypto_modern_algorithms`. The claim Worker's local, example and production configurations opt into that flag without advancing the existing compatibility date. The API follows a moving draft; compatibility remains explicitly tested. Browser support is a separate boundary, so the browser sender continues to use noble. The isolated RustCrypto and noble probes remain independent correctness references rather than the Worker release backend.

The product envelope currently names draft-04 and decrypted one official [draft-05 vector](../design/probes/pqc/hpke-pq-draft05-vector.json) for ML-KEM-768/HKDF-SHA256/AES-128-GCM. The product AES-256-GCM sender and independent RustCrypto receiver interoperate locally and with the live seed in a synthetic probe. Recovery, full owner flow, and final suite versioning remain gates before enabling writes.

## Native claim Worker migration, 2026-10-30

Rust retains strict source/authority parsing, fixed frame/suite checks, seed-to-public-key matching, key IDs, UTF-8/UTF-16 bounds, Grant/ClaimRelease checks, and the final live audit predicate. Only primitive operations cross the asynchronous [Web Crypto boundary](../crates/userinfo-claim-worker/src/native_crypto.ts). The HPKE base-mode labeled key schedule preserves the existing draft-04 suite; native ML-KEM output is never used directly as an AES key. This is not a migration to a newer HPKE wire format.

The [Rust adapter](../crates/userinfo-claim-worker/src/crypto.rs) copies returned secrets into zeroizing Rust buffers and clears their JS transfer buffers. JS snapshots all Wasm views before the first await and clears seed/shared-secret/PRK/AEAD-key temporaries on success and failure. Imported private and symmetric CryptoKeys are non-extractable. Runtime key handles and Secrets Store custody are still software boundaries; this does not change the existing key-custody model.

The wasm32 release dependency graph excludes `ml-kem`, `hpke`, `aes-gcm`, `aes`, `sha2`, `hmac`, `hkdf`, `digest` and `crypto-common`. The small `zeroize` utility remains for secret-buffer hygiene. Host-only dev dependencies retain the independent RustCrypto receiver so existing source, authority, frame and name-bound tests continue to exercise the shared Rust checks. Their presence in Cargo.lock does not mean they are linked into the release Worker. CBOM source markers now point to the native boundary.

Local verification used workerd 1.20261012.1 with compatibility date 2026-09-23 and the explicit flag:

- Three host Rust tests passed against the independent reference backend; host and wasm32 Clippy passed with warnings denied.
- The [native boundary tests](../local/conformance/claim-native-crypto.test.ts) check the transitive release graph, a NIST ML-KEM keygen fixture, the existing noble record fixture, eight concurrent opens, snapshots of caller input, wrong seed/info/AAD/ciphertext rejection, and flag omission. Retained seed/HMAC/AES import buffers are checked for erasure on success and after failure at every import stage.
- The compiled Rust Worker runs with real disposable local Secrets Store, D1 and R2 bindings in both workerd and Chromium sender flows. Sharing CAS, selected RP consent, post-decryption consent withdrawal and service failures passed. The final runtime selection passed six tests; the existing independent record suite passed another 30 tests.
- Node TypeScript, the native TypeScript boundary check, CBOM generation and its profile-isolation test, documentation links, and served UI/server Wasm accounting passed; the six bundle-accounting tests also passed.

Same-machine release builds against current main commit `b018f438`, with the same lockfile versions apart from the claim adapter's dependency edges, measured:

| Artifact | Before, bytes | After, bytes | Before gzip estimate | After gzip estimate |
| --- | ---: | ---: | ---: | ---: |
| claim `index_bg.wasm` | 707,893 | 625,833 | 235,485 | 212,304 |
| claim `index.js` | 24,296 | 27,097 | 6,377 | 7,251 |
| Combined | 732,189 | 652,930 | 241,862 | 219,555 |

Wasm shrank 11.59%; combined source bytes fell by 79,259. Gzip values are local level-9 estimates, not observed transfer sizes. These are size measurements, not speed or production-capacity results. The Wasm reporting thresholds are reduced to 675,840 raw / 230,400 gzip-estimate bytes. As on current main, individual resource growth produces warnings; the complete Worker bundle limit is enforced separately. The release dependency-graph test rejects reintroduction of the bundled cryptographic implementations.

Reproduce after installing the repository's pinned dependencies and Rust/Worker build tools:

```sh
cargo test --locked -p mikaki-userinfo-claim-worker
cargo clippy --locked -p mikaki-userinfo-claim-worker --all-targets -- -D warnings
cargo clippy --locked -p mikaki-userinfo-claim-worker --target wasm32-unknown-unknown -- -D warnings
npm run build:policy
worker-build --release crates/worker
worker-build --release crates/userinfo-claim-worker
worker-build --release -d build-conformance crates/userinfo-claim-worker --features conformance-gate
npm run check:claim-crypto
node --test --test-concurrency=1 local/conformance/claim-native-crypto.test.ts local/conformance/userinfo-claim-worker.test.ts local/conformance/vault-record-userinfo-live.test.ts local/conformance/vault-record-userinfo.test.ts
npm run check:worker-budgets
node scripts/build_cbom.ts --component userinfo-claim-worker
```

### Next dependency boundary: OIDC

The next bounded candidate is the Worker's ES256 signer. RS256 already imports a Web Crypto key, while ES256 uses `P256TokenSigner` and RustCrypto. Move ES256 signing to a non-extractable runtime CryptoKey while keeping claim construction, client algorithm policy, `kid`, JWKS and rotation unchanged. Acceptance must cover ID Tokens and logout tokens, independent JOSE verification, 64-byte P1363 signature encoding, rejected malformed or mismatched private/public JWKs, and old/new signing-key coexistence. This transition does not require enabling ML-DSA for any client.

Removing that signer alone will not remove P-256 or all RustCrypto from the OP: shared OIDC verifiers, WebAuthn, identity/card operations and native clients still depend on it. WebAuthn's DER signature handling and ES256K support need their own compatibility assessment. The separate MLS work also uses a synchronous RustCrypto provider, so it cannot simply call asynchronous Web Crypto through the claim adapter. Full removal needs those boundaries qualified independently.

Production deployment, real-key verification and the complete production owner/RP flow remain rollout gates. This implementation neither enables a sharing policy nor changes passkey/OIDC algorithm allow lists.

## References

- [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) and [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)
- [RFC 9964: ML-DSA in JOSE and COSE](https://www.rfc-editor.org/info/rfc9964/)
- [FIDO Server Requirements 2.3 Review Draft](https://fidoalliance.org/specs/fidoserver/fido-server-v2.3-rd-20260226.html) (review draft, not hardware evidence)
- [WebAuthn Level 3](https://www.w3.org/TR/webauthn/)
- [Cloudflare Workers WebCrypto](https://developers.cloudflare.com/workers/runtime-apis/web-crypto/)
- [RustCrypto ML-KEM](https://docs.rs/ml-kem/0.3.3/ml_kem/) and [ML-DSA](https://docs.rs/ml-dsa/0.1.1/ml_dsa/)
- [NIST ACVP samples](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files) and [noble-post-quantum](https://github.com/paulmillr/noble-post-quantum)
- [draft-ietf-hpke-pq-05](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-pq-05) (working draft; product format undecided)
