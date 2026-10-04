# Authorization-code reuse and revocation

The product rejects every second exchange. A replay can revoke previously issued access authority only after the request proves the same eligible client, exact callback and PKCE binding, and any required sender/client proof. Invalid requests never gain a revocation capability from knowledge of a code alone.

| Profile | Required evidence before reuse has side effects | Revocation scope |
| --- | --- | --- |
| Confidential OIDC RP | Current registered client authentication and fresh replay reservation, matching client revision, callback and PKCE; accepted DPoP if the issued token is bound | Issuance for that code |
| Native public OIDC | Current native registration, exact registered/actual callback, S256 verifier; accepted matching DPoP when bound | Issuance for that code |
| Future Identity Wallet authorization code profile | Current wallet/profile authority, exact callback, S256 verifier; matching accepted DPoP and client-attestation binding where required | Must revoke remaining token issuance authority for that grant, including a single-credential budget |

Absent, malformed, stale, replayed or substituted proofs; wrong client/callback/verifier; and stale client revisions fail before revocation. A different code's token and the owner SSO session are unaffected. A concurrent exchange has at most one issuance; an authenticated losing reuse applies the same revocation contract. Back-channel logout is a separate session-level operation.

A future Wallet profile cannot recall a credential already delivered to its holder. Its validity/status contract still applies. No bearer/resource call may request code-reuse revocation as a substitute for client authentication.

The ordinary/native Rust handler is `crates/worker/src/token.rs`. Product regressions run through actual Wasm/workerd in `dpop-worker.test.ts` and `native-oidc.test.ts`. The separately developed Identity Wallet profile is outside this branch; its reuse behavior needs its own product regression before issue #101 is fully closed. SQL/core models under `design/` test separate layers; their success alone does not qualify the Worker boundary.
