# HAIP targeted notification and Issuer checkpoint — 2026-10-09

This exact-source run attempted one selected Issuer notification-tolerance module plus the unchanged `--positive` Issuer selection, and refreshed the selected host Wallet cases. The notification module passed in both formats. Across 43 selected/attempted Issuer modules per format, SD-JWT recorded 42 passes and one transport-timeout failure; mdoc recorded 43 passes. **The selected Issuer checkpoint is incomplete.** This is not full HAIP conformance or certification, and it does not establish physical-device Wallet behavior or real Wallet error-screen behavior.

## Source, suite, and commands

- Clean source: `19a38c215371295c6a2b8f22eb1081efb584cb22`; Git tree: `0d15a472884ef602920c11b1f6cf76f2ac834d45`.
- Pinned OIDF suite: `release-v5.3.1`, revision `440eec8bac7b12b7389d7ca9cbc459b53507a443`, image `registry.gitlab.com/openid/conformance-suite@sha256:69495f453a920c262f66e5e72abd12501c33e05ce88051cddf300c00621a4d70`.
- Issuer selection: 43 unique modules per format were selected and attempted (the notification module plus 42 unchanged positive modules); 18 other Issuer modules per format remain unselected. The selected positive Issuer phase exited 1 because of the recorded timeout; that result is retained as a failure, not treated as a pass.
- Wallet selection: 22 official passes across two formats; four host-only silent rejections remain pending real Wallet error-screen evidence. Four other Wallet modules per format remain unselected.
- Exact run commands:

```sh
node local/conformance/haip-issuer.ts --module=oid4vci-1_0-issuer-happy-flow-skip-notification
node local/conformance/haip-issuer.ts --positive
MIKAKI_OIDF_WALLET_SUITE=1 node --test --test-concurrency=1 local/conformance/identity-issuance.test.ts
```

The first command received a credential in both formats. The second retained the existing positive Issuer selection and exited nonzero on the recorded failure. The Wallet command uses the host Wallet integration; it does not use a physical Wallet. The original helper's Wallet result guard compared the full suite revision against a short server revision. An offline validator checked each value against the pinned revision without rerunning the suite; see the corrected evidence chain below.

The single-module notification run used the plain fixture default. The unchanged `--positive` selector uses the encrypted fixture default. The recorded module-specific variants are shown separately because fixed OIDF module variants can override or omit that default. In the one failed SD-JWT row, token exchange succeeded, but the nonce endpoint request timed out before a holder nonce or credential was received; this artifact does not establish whether that endpoint was reachable.

## Build fingerprints

| Artifact | SHA-256 |
| --- | --- |
| `Cargo.lock` | `c59e0e9045cd766c2b7707aeb319aae8552c0e53afce87741fd66af0822dedcb` |
| `crates/browser-wasm/pkg/mikaki_browser_wasm_bg.wasm` | `cbae3f1ab4af7c9bc658a52240f396324fcccce5baa68f46564b686cbb82df73` |
| `crates/worker/build/index_bg.wasm` | `e2b04ca861c3d563c131d983fa17dfdc508702889dd129fd0484faf2cbfd8cfc` |
| `crates/worker/build/index.js` | `cfb86bb697b6ee10550097b4808311662376fd1a124f62aba012345f6fa9a057` |
| `crates/worker/build/worker/shim.mjs` | `ac99177861405a6046923cbacabbd6adfa1853a56d0c679b9f5e09097c2f4728` |
| `local/generated/worker-policy.json` | `d10e91025e987df030297a7d7a692494712a3a8ca17c97c6447efc79d2f9b013` |
| `package-lock.json` | `f3a608deff754d704069d9fe9fdedec9b35cd914bea649122c2e9616315adf47` |
| `target/debug/examples/haip_wallet` | `b0094c2165bf7145349b630a972a98ebaf1535755b99314b347076d20d5d846a` |

Private per-format configuration files were hashed only; their contents were not read into this report.

| Issuer phase | Format | Private config SHA-256 |
| --- | --- | --- |
| notification | sd_jwt_vc | `dd1dd8bab88bd32adc27681796a849b65979a8b86106800984370cd8faa945cc` |
| notification | mdoc | `e1a24cd0abd579785d91bd205ff552c7f4a8c734bc28f6a55e8be73a9d465078` |
| positive_issuer | sd_jwt_vc | `10832ae2670213b661e779ecd37326a7503df456d5303684c7b2539615e7b5c4` |
| positive_issuer | mdoc | `55a33a32d0753b519993e015cfddaeaab0d2e9475b730ba87356e81560242ca3` |

## Actual variants

The IDs below point to the complete, allowlisted variants recorded in the private result files. Each run row identifies its plan and module variant separately.

| Variant | Values |
| --- | --- |
| V1 | `{"credential_format":"sd_jwt_vc","grant_management":"disabled","vci_authorization_code_flow_variant":"wallet_initiated"}` |
| V2 | `{"authorization_request_type":"simple","client_auth_type":"client_attestation","fapi_profile":"vci_haip","fapi_request_method":"unsigned","fapi_response_mode":"plain_response","openid":"plain_oauth","sender_constrain":"dpop","vci_credential_encryption":"plain","vci_grant_type":"authorization_code"}` |
| V3 | `{"credential_format":"mdoc","grant_management":"disabled","vci_authorization_code_flow_variant":"wallet_initiated"}` |
| V4 | `{"client_auth_type":"client_attestation","fapi_profile":"vci_haip"}` |
| V5 | `{"authorization_request_type":"simple","client_auth_type":"client_attestation","fapi_profile":"vci_haip","fapi_request_method":"unsigned","fapi_response_mode":"plain_response","openid":"plain_oauth","sender_constrain":"dpop","vci_credential_encryption":"encrypted","vci_grant_type":"authorization_code"}` |
| V6 | `{"authorization_request_type":"simple","client_auth_type":"client_attestation","fapi_profile":"vci_haip","fapi_request_method":"unsigned","fapi_response_mode":"plain_response","openid":"plain_oauth","sender_constrain":"dpop"}` |
| V7 | `{"credential_format":"sd_jwt_vc","credential_type":"custom","response_mode":"direct_post.jwt"}` |
| V8 | `{"client_id_prefix":"x509_hash","credential_format":"sd_jwt_vc","credential_type":"custom","request_method":"request_uri_signed","response_mode":"direct_post.jwt","vp_profile":"haip"}` |
| V9 | `{"credential_format":"iso_mdl","credential_type":"custom","response_mode":"direct_post.jwt"}` |
| V10 | `{"client_id_prefix":"x509_hash","credential_format":"iso_mdl","credential_type":"custom","request_method":"request_uri_signed","response_mode":"direct_post.jwt","vp_profile":"haip"}` |

## Selected module results

Counts are FAILURE / ERROR / WARNING from each retained official module log. Wallet rows include their actual OIDF test IDs, including the four host-rejected cases that remain WAITING.

| Role | Format | Module | Plan / module variant | Result | Counts | Run |
| --- | --- | --- | --- | --- | --- | --- |
| Issuer | sd_jwt_vc | `oid4vci-1_0-issuer-happy-flow-skip-notification` | V1 / V2 | FINISHED/PASSED | 0/0/0 | `Y0GcdjiJFWAFAVf` |
| Issuer | mdoc | `oid4vci-1_0-issuer-happy-flow-skip-notification` | V3 / V2 | FINISHED/PASSED | 0/0/0 | `lWJxXIQP4m3VUQ8` |
| Issuer | sd_jwt_vc | `oid4vci-1_0-issuer-metadata-test` | V1 / V4 | FINISHED/PASSED | 0/0/0 | `RVs4m2mq4UGUNPN` |
| Issuer | sd_jwt_vc | `oid4vci-1_0-issuer-happy-flow` | V1 / V5 | FINISHED/PASSED | 0/0/0 | `1ojr5mY20EzO6KF` |
| Issuer | sd_jwt_vc | `oid4vci-1_0-issuer-happy-flow-additional-requests` | V1 / V2 | FINISHED/PASSED | 0/0/0 | `68cpvQPmuwbYl1Y` |
| Issuer | sd_jwt_vc | `oid4vci-1_0-issuer-happy-flow-multiple-clients` | V1 / V2 | FINISHED/PASSED | 0/0/0 | `2oWm9DLOHzoy1U4` |
| Issuer | sd_jwt_vc | `oid4vci-1_0-issuer-fail-invalid-nonce` | V1 / V2 | FINISHED/PASSED | 0/0/0 | `0U6pZDHrKEcB6Aw` |
| Issuer | sd_jwt_vc | `oid4vci-1_0-issuer-fail-invalid-jwt-proof-signature` | V1 / V2 | FINISHED/PASSED | 0/0/0 | `GJqylmN8eZ1YdGW` |
| Issuer | sd_jwt_vc | `oid4vci-1_0-issuer-fail-invalid-key-attestation-signature` | V1 / V2 | FINISHED/PASSED | 0/0/0 | `4KrjTSwxlEkQEct` |
| Issuer | sd_jwt_vc | `oid4vci-1_0-issuer-fail-invalid-client-attestation-signature` | V1 / V2 | FINISHED/PASSED | 0/0/0 | `vaB1tTZu63PqSI1` |
| Issuer | sd_jwt_vc | `oid4vci-1_0-issuer-fail-invalid-client-attestation-pop-signature` | V1 / V2 | FINISHED/PASSED | 0/0/0 | `iVV8jF3K889O27f` |
| Issuer | sd_jwt_vc | `oid4vci-1_0-issuer-fail-client-attestation-exp-in-past` | V1 / V2 | FINISHED/PASSED | 0/0/0 | `HfKoIAywTM5Vq4J` |
| Issuer | sd_jwt_vc | `oid4vci-1_0-issuer-fail-client-attestation-no-sub` | V1 / V2 | FINISHED/PASSED | 0/0/0 | `oRPtEH2wK6XyRCY` |
| Issuer | sd_jwt_vc | `oid4vci-1_0-issuer-fail-client-attestation-pop-wrong-aud` | V1 / V2 | FINISHED/PASSED | 0/0/0 | `xmLhRbcN8SESXW8` |
| Issuer | sd_jwt_vc | `oid4vci-1_0-issuer-fail-mismatched-client-attestation-pop-key` | V1 / V2 | FINISHED/PASSED | 0/0/0 | `KiLmzoakjvdbY5K` |
| Issuer | sd_jwt_vc | `oid4vci-1_0-issuer-fail-missing-proof` | V1 / V2 | FINISHED/PASSED | 0/0/0 | `ib8WqkYMg8tr2H6` |
| Issuer | sd_jwt_vc | `oid4vci-1_0-issuer-fail-unknown-credential-configuration` | V1 / V5 | FINISHED/PASSED | 0/0/0 | `9sZqvC1Q9Na8fEB` |
| Issuer | sd_jwt_vc | `oid4vci-1_0-issuer-fail-unknown-credential-identifier` | V1 / V2 | FINISHED/PASSED | 0/0/0 | `CXiVhQMAiVkbZHO` |
| Issuer | sd_jwt_vc | `oid4vci-1_0-issuer-fail-on-access-token-in-query` | V1 / V2 | FINISHED/PASSED | 0/0/0 | `2Wq9sjtilCN0ZOi` |
| Issuer | sd_jwt_vc | `oid4vci-1_0-issuer-fail-unsupported-encryption-algorithm` | V1 / V5 | FINISHED/PASSED | 0/0/0 | `jIchcVpuv6DYmJM` |
| Issuer | sd_jwt_vc | `fapi2-security-profile-final-discovery-end-point-verification` | V1 / V6 | FINISHED/PASSED | 0/0/0 | `JaDQII6VX5CP3yz` |
| Issuer | sd_jwt_vc | `fapi2-security-profile-final-ensure-authorization-request-without-state-success` | V1 / V2 | FINISHED/PASSED | 0/0/0 | `oC1jUObNewXv2RY` |
| Issuer | sd_jwt_vc | `fapi2-security-profile-final-access-token-type-header-case-sensitivity` | V1 / V2 | FINISHED/PASSED | 0/0/0 | `HmxBhObMxLRAuir` |
| Issuer | sd_jwt_vc | `fapi2-security-profile-final-check-dpop-proof-nbf-exp` | V1 / V2 | FINISHED/PASSED | 0/0/0 | `4uh6M4APQYdFNEl` |
| Issuer | sd_jwt_vc | `fapi2-security-profile-final-ensure-dpopproof-with-iat-10seconds-before-succeeds` | V1 / V2 | FINISHED/PASSED | 0/0/0 | `HV6V7rsy23fcCEL` |
| Issuer | sd_jwt_vc | `fapi2-security-profile-final-ensure-dpopproof-with-iat-10seconds-after-succeeds` | V1 / V2 | FINISHED/PASSED | 0/0/0 | `A2swdzxeUARvWHY` |
| Issuer | sd_jwt_vc | `fapi2-security-profile-final-ensure-mismatched-dpop-jkt-fails` | V1 / V2 | FINISHED/PASSED | 0/0/0 | `DjDWGpnEurzCVti` |
| Issuer | sd_jwt_vc | `fapi2-security-profile-final-ensure-token-endpoint-fails-with-mismatched-dpop-proof-jkt` | V1 / V2 | FINISHED/PASSED | 0/0/0 | `Gx5sF8KeqoNCw4D` |
| Issuer | sd_jwt_vc | `fapi2-security-profile-final-ensure-token-endpoint-fails-with-mismatched-dpop-jkt` | V1 / V2 | FINISHED/PASSED | 0/0/0 | `TYJxI1dcD3qI6Zg` |
| Issuer | sd_jwt_vc | `fapi2-security-profile-final-ensure-dpopproof-at-par-endpoint-binding-success` | V1 / V2 | FINISHED/PASSED | 0/0/0 | `lIgkukbn2mvH5zN` |
| Issuer | sd_jwt_vc | `fapi2-security-profile-final-ensure-dpop-auth-code-binding-success` | V1 / V2 | FINISHED/PASSED | 0/0/0 | `JQzhIgm1a42y6uB` |
| Issuer | sd_jwt_vc | `fapi2-security-profile-final-ensure-authorization-request-with-long-state` | V1 / V2 | FINISHED/PASSED | 0/0/0 | `UhzE4xzrrDd96hQ` |
| Issuer | sd_jwt_vc | `fapi2-security-profile-final-ensure-authorization-code-is-bound-to-client` | V1 / V2 | FINISHED/PASSED | 0/0/0 | `c0WgVpedS2oqmn3` |
| Issuer | sd_jwt_vc | `fapi2-security-profile-final-attempt-reuse-authorization-code-after-one-second` | V1 / V2 | FINISHED/PASSED | 0/0/0 | `ezaIQC3wxZwhl8A` |
| Issuer | sd_jwt_vc | `fapi2-security-profile-final-dpop-negative-tests` | V1 / V2 | FINISHED/PASSED | 0/0/0 | `HPu6agRPLPaAcXH` |
| Issuer | sd_jwt_vc | `fapi2-security-profile-final-par-attempt-reuse-request_uri` | V1 / V2 | INTERRUPTED/FAILED; CallCredentialIssuerNonceEndpoint; org.springframework.web.client.ResourceAccessException; org.apache.hc.client5.http.ConnectTimeoutException | 1/0/0 | `YZ76quPMFgDgmWi` |
| Issuer | sd_jwt_vc | `fapi2-security-profile-final-par-attempt-to-use-expired-request_uri` | V1 / V2 | FINISHED/PASSED | 0/0/0 | `zeLqN3MGF4rbIaj` |
| Issuer | sd_jwt_vc | `fapi2-security-profile-final-par-authorization-request-containing-request_uri-form-param` | V1 / V2 | FINISHED/PASSED | 0/0/0 | `QErSgIlK0Kkvta9` |
| Issuer | sd_jwt_vc | `fapi2-security-profile-final-par-attempt-invalid-http-method` | V1 / V2 | FINISHED/PASSED | 0/0/0 | `cJXpX886h9WrMuq` |
| Issuer | sd_jwt_vc | `fapi2-security-profile-final-par-ensure-pkce-required` | V1 / V2 | FINISHED/PASSED | 0/0/0 | `s0n0JWdHlB4HtFJ` |
| Issuer | sd_jwt_vc | `fapi2-security-profile-final-ensure-pkce-code-verifier-required` | V1 / V2 | FINISHED/PASSED | 0/0/0 | `t6LoXgZFpwUL9yi` |
| Issuer | sd_jwt_vc | `fapi2-security-profile-final-incorrect-pkce-code-verifier-rejected` | V1 / V2 | FINISHED/PASSED | 0/0/0 | `OsAMiGBIrsL3Jev` |
| Issuer | sd_jwt_vc | `fapi2-security-profile-final-par-plain-pkce-rejected` | V1 / V2 | FINISHED/PASSED | 0/0/0 | `f3wGW0bUcOocHuy` |
| Issuer | sd_jwt_vc | `fapi2-security-profile-final-par-without-duplicate-parameters` | V1 / V2 | FINISHED/PASSED | 0/0/0 | `ZX3ZRNMz2IsMLBs` |
| Issuer | mdoc | `oid4vci-1_0-issuer-metadata-test` | V3 / V4 | FINISHED/PASSED | 0/0/0 | `ZPsMS4QFg6sXfzt` |
| Issuer | mdoc | `oid4vci-1_0-issuer-happy-flow` | V3 / V5 | FINISHED/PASSED | 0/0/0 | `PKF5mqPdZVIobqy` |
| Issuer | mdoc | `oid4vci-1_0-issuer-happy-flow-additional-requests` | V3 / V2 | FINISHED/PASSED | 0/0/0 | `Q6JM80LdsXJ5Jbg` |
| Issuer | mdoc | `oid4vci-1_0-issuer-happy-flow-multiple-clients` | V3 / V2 | FINISHED/PASSED | 0/0/0 | `NhUrL8In0y5X6Ls` |
| Issuer | mdoc | `oid4vci-1_0-issuer-fail-invalid-nonce` | V3 / V2 | FINISHED/PASSED | 0/0/0 | `3DSI32mKEjYsNOW` |
| Issuer | mdoc | `oid4vci-1_0-issuer-fail-invalid-jwt-proof-signature` | V3 / V2 | FINISHED/PASSED | 0/0/0 | `Y84wtfDjefAOHHU` |
| Issuer | mdoc | `oid4vci-1_0-issuer-fail-invalid-key-attestation-signature` | V3 / V2 | FINISHED/PASSED | 0/0/0 | `uL8AqTLmO26RzV1` |
| Issuer | mdoc | `oid4vci-1_0-issuer-fail-invalid-client-attestation-signature` | V3 / V2 | FINISHED/PASSED | 0/0/0 | `j9vzRSeUyVNVgTP` |
| Issuer | mdoc | `oid4vci-1_0-issuer-fail-invalid-client-attestation-pop-signature` | V3 / V2 | FINISHED/PASSED | 0/0/0 | `VzNnfP8nRMiPupx` |
| Issuer | mdoc | `oid4vci-1_0-issuer-fail-client-attestation-exp-in-past` | V3 / V2 | FINISHED/PASSED | 0/0/0 | `HBPFOOEzgRQdx5i` |
| Issuer | mdoc | `oid4vci-1_0-issuer-fail-client-attestation-no-sub` | V3 / V2 | FINISHED/PASSED | 0/0/0 | `6bBAHAgjpqItbsc` |
| Issuer | mdoc | `oid4vci-1_0-issuer-fail-client-attestation-pop-wrong-aud` | V3 / V2 | FINISHED/PASSED | 0/0/0 | `irv6fhgw3spwlXV` |
| Issuer | mdoc | `oid4vci-1_0-issuer-fail-mismatched-client-attestation-pop-key` | V3 / V2 | FINISHED/PASSED | 0/0/0 | `0bQVlideYAqBnZy` |
| Issuer | mdoc | `oid4vci-1_0-issuer-fail-missing-proof` | V3 / V2 | FINISHED/PASSED | 0/0/0 | `LIxqksAkw4hhKLW` |
| Issuer | mdoc | `oid4vci-1_0-issuer-fail-unknown-credential-configuration` | V3 / V5 | FINISHED/PASSED | 0/0/0 | `TnJFDlagfmGBUg0` |
| Issuer | mdoc | `oid4vci-1_0-issuer-fail-unknown-credential-identifier` | V3 / V2 | FINISHED/PASSED | 0/0/0 | `BpPOeaVdni25zYl` |
| Issuer | mdoc | `oid4vci-1_0-issuer-fail-on-access-token-in-query` | V3 / V2 | FINISHED/PASSED | 0/0/0 | `dB9HKJE0WLUVfS5` |
| Issuer | mdoc | `oid4vci-1_0-issuer-fail-unsupported-encryption-algorithm` | V3 / V5 | FINISHED/PASSED | 0/0/0 | `oku9d53ukUvGvMv` |
| Issuer | mdoc | `fapi2-security-profile-final-discovery-end-point-verification` | V3 / V6 | FINISHED/PASSED | 0/0/0 | `hdorBpce66TlK8t` |
| Issuer | mdoc | `fapi2-security-profile-final-ensure-authorization-request-without-state-success` | V3 / V2 | FINISHED/PASSED | 0/0/0 | `7RzfC2rBefNqfv4` |
| Issuer | mdoc | `fapi2-security-profile-final-access-token-type-header-case-sensitivity` | V3 / V2 | FINISHED/PASSED | 0/0/0 | `IyyrSJukziuJdKs` |
| Issuer | mdoc | `fapi2-security-profile-final-check-dpop-proof-nbf-exp` | V3 / V2 | FINISHED/PASSED | 0/0/0 | `xJg6PjWDtSP9FUq` |
| Issuer | mdoc | `fapi2-security-profile-final-ensure-dpopproof-with-iat-10seconds-before-succeeds` | V3 / V2 | FINISHED/PASSED | 0/0/0 | `vzHx3CsA8OUwTti` |
| Issuer | mdoc | `fapi2-security-profile-final-ensure-dpopproof-with-iat-10seconds-after-succeeds` | V3 / V2 | FINISHED/PASSED | 0/0/0 | `Sgm3orTWXBYqZmo` |
| Issuer | mdoc | `fapi2-security-profile-final-ensure-mismatched-dpop-jkt-fails` | V3 / V2 | FINISHED/PASSED | 0/0/0 | `TqhPCAkinVpV3Mc` |
| Issuer | mdoc | `fapi2-security-profile-final-ensure-token-endpoint-fails-with-mismatched-dpop-proof-jkt` | V3 / V2 | FINISHED/PASSED | 0/0/0 | `9hhVQXbcje1sTEh` |
| Issuer | mdoc | `fapi2-security-profile-final-ensure-token-endpoint-fails-with-mismatched-dpop-jkt` | V3 / V2 | FINISHED/PASSED | 0/0/0 | `YiyBnsSf9b86sWg` |
| Issuer | mdoc | `fapi2-security-profile-final-ensure-dpopproof-at-par-endpoint-binding-success` | V3 / V2 | FINISHED/PASSED | 0/0/0 | `tGz9EWOQfUf7alC` |
| Issuer | mdoc | `fapi2-security-profile-final-ensure-dpop-auth-code-binding-success` | V3 / V2 | FINISHED/PASSED | 0/0/0 | `2NcLi1fKf001FQh` |
| Issuer | mdoc | `fapi2-security-profile-final-ensure-authorization-request-with-long-state` | V3 / V2 | FINISHED/PASSED | 0/0/0 | `jjzpaKG4mlnDPgf` |
| Issuer | mdoc | `fapi2-security-profile-final-ensure-authorization-code-is-bound-to-client` | V3 / V2 | FINISHED/PASSED | 0/0/0 | `dNb4fVHOjsMJcoT` |
| Issuer | mdoc | `fapi2-security-profile-final-attempt-reuse-authorization-code-after-one-second` | V3 / V2 | FINISHED/PASSED | 0/0/0 | `tavi9BUNJYDjhF0` |
| Issuer | mdoc | `fapi2-security-profile-final-dpop-negative-tests` | V3 / V2 | FINISHED/PASSED | 0/0/0 | `V3joH3OM0Xxqta0` |
| Issuer | mdoc | `fapi2-security-profile-final-par-attempt-reuse-request_uri` | V3 / V2 | FINISHED/PASSED | 0/0/0 | `yCwIpOlgG8WHTAR` |
| Issuer | mdoc | `fapi2-security-profile-final-par-attempt-to-use-expired-request_uri` | V3 / V2 | FINISHED/PASSED | 0/0/0 | `ardUaxp6i8DkeRV` |
| Issuer | mdoc | `fapi2-security-profile-final-par-authorization-request-containing-request_uri-form-param` | V3 / V2 | FINISHED/PASSED | 0/0/0 | `opovlKwUociMjot` |
| Issuer | mdoc | `fapi2-security-profile-final-par-attempt-invalid-http-method` | V3 / V2 | FINISHED/PASSED | 0/0/0 | `IRYa8xD09YkaGQF` |
| Issuer | mdoc | `fapi2-security-profile-final-par-ensure-pkce-required` | V3 / V2 | FINISHED/PASSED | 0/0/0 | `ooZqifjpCfhGjab` |
| Issuer | mdoc | `fapi2-security-profile-final-ensure-pkce-code-verifier-required` | V3 / V2 | FINISHED/PASSED | 0/0/0 | `7eEz6dYRyFODE7k` |
| Issuer | mdoc | `fapi2-security-profile-final-incorrect-pkce-code-verifier-rejected` | V3 / V2 | FINISHED/PASSED | 0/0/0 | `CnJp5NYja4Bj69t` |
| Issuer | mdoc | `fapi2-security-profile-final-par-plain-pkce-rejected` | V3 / V2 | FINISHED/PASSED | 0/0/0 | `hrrHsUsTcwtZJkn` |
| Issuer | mdoc | `fapi2-security-profile-final-par-without-duplicate-parameters` | V3 / V2 | FINISHED/PASSED | 0/0/0 | `9fRhW9M5BiYVJ4h` |
| Wallet | dc+sd-jwt | `oid4vp-1final-wallet-request-uri-method-post` | V7 / V8 | FINISHED/PASSED | 0/0/0 | `SGD2Tujpbkv9SAZ` |
| Wallet | dc+sd-jwt | `oid4vp-1final-wallet-happy-flow` | V7 / V8 | FINISHED/PASSED | 0/0/0 | `o2Z8rI6VnLyjfLP` |
| Wallet | dc+sd-jwt | `oid4vp-1final-wallet-alternate-happy-flow` | V7 / V8 | FINISHED/PASSED | 0/0/0 | `xUTvyIvifruBJxk` |
| Wallet | dc+sd-jwt | `oid4vp-1final-wallet-ignores-unusable-encryption-key` | V7 / V8 | FINISHED/PASSED | 0/0/0 | `rm9iP3B03EEHGzP` |
| Wallet | dc+sd-jwt | `oid4vp-1final-wallet-fewer-claims-than-available` | V7 / V8 | FINISHED/PASSED | 0/0/0 | `8Rt77UXi58lAn1j` |
| Wallet | dc+sd-jwt | `oid4vp-1final-wallet-optional-credential-set` | V7 / V8 | FINISHED/PASSED | 0/0/0 | `ZgoK54MNdiBcI5B` |
| Wallet | dc+sd-jwt | `oid4vp-1final-wallet-no-claims-in-dcql-query` | V7 / V8 | FINISHED/PASSED | 0/0/0 | `3PCcW6wiqxpfiBb` |
| Wallet | dc+sd-jwt | `oid4vp-1final-wallet-negative-test-invalid-request-object-signature` | V7 / V8 | WAITING/null; host rejection, real Wallet screen evidence pending | 0/0/0 | `SwgfEqisx6HbaBV` |
| Wallet | dc+sd-jwt | `oid4vp-1final-wallet-negative-test-mismatched-client-id` | V7 / V8 | WAITING/null; host rejection, real Wallet screen evidence pending | 0/0/0 | `G36nfrUSm6ubPPS` |
| Wallet | dc+sd-jwt | `oid4vp-1final-wallet-negative-test-missing-nonce` | V7 / V8 | FINISHED/PASSED | 0/0/0 | `beMkVA8BtptCnTP` |
| Wallet | dc+sd-jwt | `oid4vp-1final-wallet-negative-test-redirect-uri-with-direct-post` | V7 / V8 | FINISHED/PASSED | 0/0/0 | `Bd5YZTjQkngqTSa` |
| Wallet | dc+sd-jwt | `oid4vp-1final-wallet-negative-test-unknown-transaction-data-type` | V7 / V8 | FINISHED/PASSED | 0/0/0 | `GBJf1LhK85e82aA` |
| Wallet | dc+sd-jwt | `oid4vp-1final-wallet-negative-test-required-non-matching-credential` | V7 / V8 | FINISHED/PASSED | 0/0/0 | `OlAmU3MxCy36v12` |
| Wallet | mso_mdoc | `oid4vp-1final-wallet-request-uri-method-post` | V9 / V10 | FINISHED/PASSED | 0/0/0 | `na7jAIGZnCQcIRF` |
| Wallet | mso_mdoc | `oid4vp-1final-wallet-happy-flow` | V9 / V10 | FINISHED/PASSED | 0/0/0 | `jKAkzDpHancW9mc` |
| Wallet | mso_mdoc | `oid4vp-1final-wallet-alternate-happy-flow` | V9 / V10 | FINISHED/PASSED | 0/0/0 | `fEVBGZDDXgra3Yp` |
| Wallet | mso_mdoc | `oid4vp-1final-wallet-ignores-unusable-encryption-key` | V9 / V10 | FINISHED/PASSED | 0/0/0 | `VIGdVvlEMPZbs3v` |
| Wallet | mso_mdoc | `oid4vp-1final-wallet-fewer-claims-than-available` | V9 / V10 | FINISHED/PASSED | 0/0/0 | `t69kmSJdvy6xlpF` |
| Wallet | mso_mdoc | `oid4vp-1final-wallet-optional-credential-set` | V9 / V10 | FINISHED/PASSED | 0/0/0 | `VHoQqTPvmnzdlAp` |
| Wallet | mso_mdoc | `oid4vp-1final-wallet-no-claims-in-dcql-query` | V9 / V10 | FINISHED/PASSED | 0/0/0 | `ENB6KhnRb5sbBBm` |
| Wallet | mso_mdoc | `oid4vp-1final-wallet-negative-test-invalid-request-object-signature` | V9 / V10 | WAITING/null; host rejection, real Wallet screen evidence pending | 0/0/0 | `2ckBIt3LOy1N3wN` |
| Wallet | mso_mdoc | `oid4vp-1final-wallet-negative-test-mismatched-client-id` | V9 / V10 | WAITING/null; host rejection, real Wallet screen evidence pending | 0/0/0 | `ko37ysMtErX0nIA` |
| Wallet | mso_mdoc | `oid4vp-1final-wallet-negative-test-missing-nonce` | V9 / V10 | FINISHED/PASSED | 0/0/0 | `EH12diyaKQHCAJT` |
| Wallet | mso_mdoc | `oid4vp-1final-wallet-negative-test-redirect-uri-with-direct-post` | V9 / V10 | FINISHED/PASSED | 0/0/0 | `gYKw8R3sH8ju8hG` |
| Wallet | mso_mdoc | `oid4vp-1final-wallet-negative-test-unknown-transaction-data-type` | V9 / V10 | FINISHED/PASSED | 0/0/0 | `dlywsep3LkfHjMF` |
| Wallet | mso_mdoc | `oid4vp-1final-wallet-negative-test-required-non-matching-credential` | V9 / V10 | FINISHED/PASSED | 0/0/0 | `tlEdl5wODPcofUv` |

## Not selected

These are omissions, not synthetic SKIPPED results.

- Issuer (each of `sd_jwt_vc and mdoc`): `oid4vci-1_0-issuer-metadata-test-signed`, `oid4vci-1_0-issuer-batch-issuance`, `fapi2-security-profile-final-happy-flow`, `fapi2-security-profile-final-user-rejects-authentication`, `fapi2-security-profile-final-ensure-different-state-inside-and-outside-request-object`, `fapi2-security-profile-final-state-only-outside-request-object-not-used`, `fapi2-security-profile-final-ensure-request-object-without-redirect-uri-fails`, `fapi2-security-profile-final-plain-fapi-tolerate-unregistered-redirect-uri`, `fapi2-security-profile-final-ensure-unsigned-authorization-request-without-using-par-fails`, `fapi2-security-profile-final-ensure-redirect-uri-in-authorization-request`, `fapi2-security-profile-final-ensure-response-type-code-idtoken-fails`, `fapi2-security-profile-final-ensure-response-type-token-fails`, `fapi2-security-profile-final-ensure-client-id-in-token-endpoint`, `fapi2-security-profile-final-ensure-holder-of-key-required`, `fapi2-security-profile-final-ensure-token-endpoint-fails-with-expired-auth-code`, `fapi2-security-profile-final-refresh-token`, `fapi2-security-profile-final-par-ensure-reused-request-uri-prior-to-auth-completion-succeeds`, `fapi2-security-profile-final-par-attempt-to-use-request_uri-for-different-client`.
- Wallet (each of `dc+sd-jwt and mso_mdoc`): `oid4vp-1final-wallet-all-mandatory-claims`, `oid4vp-1final-wallet-negative-test-wrong-expected-origins`, `oid4vp-1final-wallet-negative-test-invalid-client-id-prefix`, `oid4vp-1final-wallet-multisigned-one-invalid-signature`.

## Historical context and limits

The [preceding checkpoint record](haip-conformance-20261008.md) retains the earlier attempts. Its selected Issuer checkpoint on source `a5ff72f2264b72352d81c891ea9f8698030c7509` recorded 83/84 passes. A separate instrumented 84/84 transport diagnostic was not a qualification run and recorded 14 TLS errors; those events were sequence-correlated with version/cipher probes but were not attributed per connection. The transport root cause remains unknown. These historical observations are separate from the current 86 Issuer tuples and Wallet results above.

The notification module exercises the pinned suite’s issuance path that skips its Wallet notification step; it is not a notification-delivery test. Wallet host-only rejections are not counted as official passes. Real owner-passkey journeys, physical cards/devices, native Wallet UI and formal certification remain outside this evidence.

The offline Wallet check corrected only a report-side comparison of the full suite revision and abbreviated server revision. It reused the original private summaries and run files, preserved the original helper proof hash, and reran no tests. Source and build artifacts were unchanged.

The original execution receipt and corrected projections remain private. Their fingerprints bind the correction to the saved results:

| Evidence | SHA-256 |
| --- | --- |
| Original execution receipt | `d6977ef7454d42a872fe5b80fd568b2cda65b01d68e5e74361a595714e815d82` |
| Offline validation receipt | `7e2929a325ffbd16695ad985a340b1ba6cf20e8f4ecb0628f63c486e9c106166` |
| Redacted result projection | `9bc31e9ee5a74d37ece71ec393840b001c2b93f8859d4ca4bff5c8ae97663230` |
