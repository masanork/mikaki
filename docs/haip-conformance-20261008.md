# HAIP current-source checkpoint — 2026-10-08

This reruns existing selected official cases after the dependency and crypto changes in PR #162. **Issuer: 84/84 FINISHED/PASSED. Wallet: 22 official passes plus 4 host-only silent rejections with real Wallet error-screen evidence pending.** It adds no protocol implementation or case coverage and is not full HAIP conformance or certification. Earlier checkpoints remain historical results in [the implementation record](identity-card-issuance.md).

## Source and execution

- Tested clean source: `407f50e7a5593efe67d04584aa4e5aebc2231907`; tree: `c2763876135f1ad509244e798b5742237493c20f`.
- Deployed runtime source at qualification: `d7e92eb269f3072c71aacb536e9c4c5d1f1aef54`; the tested source differs only in `metrics/code-size.svg`, `metrics/dependency-inventory.md` and `metrics/history.json`. No public profile activation, sharing policy, trust key or real-data change was made.
- OIDF suite: `release-v5.3.1`, source `440eec8bac7b12b7389d7ca9cbc459b53507a443`, Issuer plan `oid4vci-1_0-issuer-haip-test-plan`, Wallet plan `oid4vp-1final-wallet-haip-test-plan`.
- Server image: `registry.gitlab.com/openid/conformance-suite@sha256:69495f453a920c262f66e5e72abd12501c33e05ce88051cddf300c00621a4d70`. The unchanged [Compose file](../local/conformance/haip-suite.compose.yml) pins server, nginx and Mongo images; the three container image digests matched those pins.
- Fresh project compilation used a copied Cargo cache. Worker, browser Wasm and native HAIP Wallet example were rebuilt from the tested source; the Wallet fixture also runs its existing locked/offline example build.

| Suite container       | Configured image                                                                                                             | Observed image ID                                                         |
| --------------------- | ---------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| mikaki-haip-server-1  | `registry.gitlab.com/openid/conformance-suite@sha256:69495f453a920c262f66e5e72abd12501c33e05ce88051cddf300c00621a4d70`       | `sha256:69495f453a920c262f66e5e72abd12501c33e05ce88051cddf300c00621a4d70` |
| mikaki-haip-nginx-1   | `registry.gitlab.com/openid/conformance-suite/nginx@sha256:6ea3f4b8854f1f3626c81350900962d9e5f86424791d8e72b378a26ee2f4c105` | `sha256:6ea3f4b8854f1f3626c81350900962d9e5f86424791d8e72b378a26ee2f4c105` |
| mikaki-haip-mongodb-1 | `mongo@sha256:b415b12f638e2685d06c58ab7fb5943577c50fadec6d9340ef67d21aeac72070`                                              | `sha256:b415b12f638e2685d06c58ab7fb5943577c50fadec6d9340ef67d21aeac72070` |

Preparation:

```sh
npm ci
npm run build:policy
npm run build:wasm
worker-build --release crates/worker
cargo build -p mikaki-identity --example haip_wallet --locked --offline
docker compose -p mikaki-haip -f local/conformance/haip-suite.compose.yml up -d
node local/conformance/haip-issuer.ts --positive
npm run test:identity-wallet-suite
```

Both commands exited zero. The Wallet command also passed the actual workerd issuance/presentation integration test. Its first invocation stopped at sandbox loopback permission failure before any official Wallet module ran; the authorized rerun succeeded. The original repository and unrelated suite on port 8443 were left untouched.

The fixture uses local workerd/D1, synthetic card evidence and live seeded SSO, disposable attestation/credential PKI, host Rust Wallet and a local TLS relay. Real owner passkey login, physical cards/devices, native Wallet UI, public Cloudflare TLS and production credential trust/revocation are outside this checkpoint. In-flight expiry modules used real lifetimes; neither database expiry nor suite clocks were changed.

## Build and evidence fingerprints

Raw configurations and logs stay in ignored private directories (0700), with JSON files at 0600. They contain disposable private keys and may contain tokens. This public record uses an allowlist of module names, public variants, states, counters and hashes; no keys, claims, IDs, URLs from private config, log messages or adapter-error text are copied.

| Built input / artifact                                | SHA-256                                                            |
| ----------------------------------------------------- | ------------------------------------------------------------------ |
| `crates/browser-wasm/pkg/mikaki_browser_wasm_bg.wasm` | `cbae3f1ab4af7c9bc658a52240f396324fcccce5baa68f46564b686cbb82df73` |
| `crates/worker/build/index.js`                        | `cfb86bb697b6ee10550097b4808311662376fd1a124f62aba012345f6fa9a057` |
| `crates/worker/build/index_bg.wasm`                   | `ca7dc70e9c05fa066a44a7bc56791d32017becea340dd4cf4b69d276bc337c2c` |
| `crates/worker/build/worker/shim.mjs`                 | `ac99177861405a6046923cbacabbd6adfa1853a56d0c679b9f5e09097c2f4728` |
| `target/debug/examples/haip_wallet`                   | `2d138f134e69a201d79d4d10741041aee2769b6e6deff898f60fc25c64841b0c` |
| `local/generated/worker-policy.json`                  | `d10e91025e987df030297a7d7a692494712a3a8ca17c97c6447efc79d2f9b013` |
| `package-lock.json`                                   | `11bcee9f071da0a3e6a24d328b2661485da247832a479d89cc8a4176d23b3ed4` |
| `Cargo.lock`                                          | `c59e0e9045cd766c2b7707aeb319aae8552c0e53afce87741fd66af0822dedcb` |

| Role / format      | Plan definition SHA-256                                            | Private config SHA-256                                             | Private summary SHA-256                                            |
| ------------------ | ------------------------------------------------------------------ | ------------------------------------------------------------------ | ------------------------------------------------------------------ |
| Issuer / sd_jwt_vc | `8b89d3397df209579c80c0573f85051fe97e005fecbfa2e0d3de9af5d07c185d` | `5d5588d01366de623c55e7b8da36f9c345dd8f6580db15e72ecda24f4285ac47` | `26d4b5bd3b5098342371b8b4a305e48146d5b46ddedd4662d8ec05a006635832` |
| Issuer / mdoc      | `8b89d3397df209579c80c0573f85051fe97e005fecbfa2e0d3de9af5d07c185d` | `b72f2997e7303caf200d498a4c62172879b73c6304a47274ebce3a2e3c66d5a2` | `26d4b5bd3b5098342371b8b4a305e48146d5b46ddedd4662d8ec05a006635832` |
| Wallet / dc+sd-jwt | `2587156947a361adfb670c5f924404b0b69390f580727fe531deb12d7bcec361` | `25442656807af564b8cafecc54c709f6538d2ad4eb25770387cf5695f8d47fcf` | `0f3daad2f2eb96ef56af8d2ea0e76099f4274a8643cafe01958d180f341769cf` |
| Wallet / mso_mdoc  | `2587156947a361adfb670c5f924404b0b69390f580727fe531deb12d7bcec361` | `114682c130ec2f41e9e48f53bd3a8a7caa7585fdfbdcb1597e62d388fe907e79` | `6431469f175d273bb1db915f5a802a868a2ce2cf82982667aeb70efe2fd20993` |

## Actual module variants

These are the official `info.variant` snapshots, including the plan-specific fixed variants; encrypted checkpoint selection does not turn every module into an encrypted-flow test. Each row below points to one complete public variant.

```json
{
  "V1": {
    "client_auth_type": "client_attestation",
    "credential_format": "sd_jwt_vc",
    "fapi_profile": "vci_haip",
    "grant_management": "disabled",
    "vci_authorization_code_flow_variant": "wallet_initiated"
  },
  "V2": {
    "authorization_request_type": "simple",
    "client_auth_type": "client_attestation",
    "credential_format": "sd_jwt_vc",
    "fapi_profile": "vci_haip",
    "fapi_request_method": "unsigned",
    "fapi_response_mode": "plain_response",
    "grant_management": "disabled",
    "openid": "plain_oauth",
    "sender_constrain": "dpop",
    "vci_authorization_code_flow_variant": "wallet_initiated",
    "vci_credential_encryption": "encrypted",
    "vci_grant_type": "authorization_code"
  },
  "V3": {
    "authorization_request_type": "simple",
    "client_auth_type": "client_attestation",
    "credential_format": "sd_jwt_vc",
    "fapi_profile": "vci_haip",
    "fapi_request_method": "unsigned",
    "fapi_response_mode": "plain_response",
    "grant_management": "disabled",
    "openid": "plain_oauth",
    "sender_constrain": "dpop",
    "vci_authorization_code_flow_variant": "wallet_initiated",
    "vci_credential_encryption": "plain",
    "vci_grant_type": "authorization_code"
  },
  "V4": {
    "authorization_request_type": "simple",
    "client_auth_type": "client_attestation",
    "credential_format": "sd_jwt_vc",
    "fapi_profile": "vci_haip",
    "fapi_request_method": "unsigned",
    "fapi_response_mode": "plain_response",
    "grant_management": "disabled",
    "openid": "plain_oauth",
    "sender_constrain": "dpop",
    "vci_authorization_code_flow_variant": "wallet_initiated"
  },
  "V5": {
    "client_auth_type": "client_attestation",
    "credential_format": "mdoc",
    "fapi_profile": "vci_haip",
    "grant_management": "disabled",
    "vci_authorization_code_flow_variant": "wallet_initiated"
  },
  "V6": {
    "authorization_request_type": "simple",
    "client_auth_type": "client_attestation",
    "credential_format": "mdoc",
    "fapi_profile": "vci_haip",
    "fapi_request_method": "unsigned",
    "fapi_response_mode": "plain_response",
    "grant_management": "disabled",
    "openid": "plain_oauth",
    "sender_constrain": "dpop",
    "vci_authorization_code_flow_variant": "wallet_initiated",
    "vci_credential_encryption": "encrypted",
    "vci_grant_type": "authorization_code"
  },
  "V7": {
    "authorization_request_type": "simple",
    "client_auth_type": "client_attestation",
    "credential_format": "mdoc",
    "fapi_profile": "vci_haip",
    "fapi_request_method": "unsigned",
    "fapi_response_mode": "plain_response",
    "grant_management": "disabled",
    "openid": "plain_oauth",
    "sender_constrain": "dpop",
    "vci_authorization_code_flow_variant": "wallet_initiated",
    "vci_credential_encryption": "plain",
    "vci_grant_type": "authorization_code"
  },
  "V8": {
    "authorization_request_type": "simple",
    "client_auth_type": "client_attestation",
    "credential_format": "mdoc",
    "fapi_profile": "vci_haip",
    "fapi_request_method": "unsigned",
    "fapi_response_mode": "plain_response",
    "grant_management": "disabled",
    "openid": "plain_oauth",
    "sender_constrain": "dpop",
    "vci_authorization_code_flow_variant": "wallet_initiated"
  },
  "V9": {
    "client_id_prefix": "x509_hash",
    "credential_format": "sd_jwt_vc",
    "credential_type": "custom",
    "request_method": "request_uri_signed",
    "response_mode": "direct_post.jwt",
    "vp_profile": "haip"
  },
  "V10": {
    "client_id_prefix": "x509_hash",
    "credential_format": "iso_mdl",
    "credential_type": "custom",
    "request_method": "request_uri_signed",
    "response_mode": "direct_post.jwt",
    "vp_profile": "haip"
  }
}
```

## Issuer module results

All counts are FAILURE / ERROR / WARNING from the retained official module log. A metadata or negative-module pass is not automatically evidence of successful credential receipt.

| Format    | Official module                                                                            | Variant | Status   | Result | F / E / W |
| --------- | ------------------------------------------------------------------------------------------ | ------- | -------- | ------ | --------- |
| sd_jwt_vc | `oid4vci-1_0-issuer-metadata-test`                                                         | V1      | FINISHED | PASSED | 0 / 0 / 0 |
| sd_jwt_vc | `oid4vci-1_0-issuer-happy-flow`                                                            | V2      | FINISHED | PASSED | 0 / 0 / 0 |
| sd_jwt_vc | `oid4vci-1_0-issuer-happy-flow-additional-requests`                                        | V3      | FINISHED | PASSED | 0 / 0 / 0 |
| sd_jwt_vc | `oid4vci-1_0-issuer-happy-flow-multiple-clients`                                           | V3      | FINISHED | PASSED | 0 / 0 / 0 |
| sd_jwt_vc | `oid4vci-1_0-issuer-fail-invalid-nonce`                                                    | V3      | FINISHED | PASSED | 0 / 0 / 0 |
| sd_jwt_vc | `oid4vci-1_0-issuer-fail-invalid-jwt-proof-signature`                                      | V3      | FINISHED | PASSED | 0 / 0 / 0 |
| sd_jwt_vc | `oid4vci-1_0-issuer-fail-invalid-key-attestation-signature`                                | V3      | FINISHED | PASSED | 0 / 0 / 0 |
| sd_jwt_vc | `oid4vci-1_0-issuer-fail-invalid-client-attestation-signature`                             | V3      | FINISHED | PASSED | 0 / 0 / 0 |
| sd_jwt_vc | `oid4vci-1_0-issuer-fail-invalid-client-attestation-pop-signature`                         | V3      | FINISHED | PASSED | 0 / 0 / 0 |
| sd_jwt_vc | `oid4vci-1_0-issuer-fail-client-attestation-exp-in-past`                                   | V3      | FINISHED | PASSED | 0 / 0 / 0 |
| sd_jwt_vc | `oid4vci-1_0-issuer-fail-client-attestation-no-sub`                                        | V3      | FINISHED | PASSED | 0 / 0 / 0 |
| sd_jwt_vc | `oid4vci-1_0-issuer-fail-client-attestation-pop-wrong-aud`                                 | V3      | FINISHED | PASSED | 0 / 0 / 0 |
| sd_jwt_vc | `oid4vci-1_0-issuer-fail-mismatched-client-attestation-pop-key`                            | V3      | FINISHED | PASSED | 0 / 0 / 0 |
| sd_jwt_vc | `oid4vci-1_0-issuer-fail-missing-proof`                                                    | V3      | FINISHED | PASSED | 0 / 0 / 0 |
| sd_jwt_vc | `oid4vci-1_0-issuer-fail-unknown-credential-configuration`                                 | V2      | FINISHED | PASSED | 0 / 0 / 0 |
| sd_jwt_vc | `oid4vci-1_0-issuer-fail-unknown-credential-identifier`                                    | V3      | FINISHED | PASSED | 0 / 0 / 0 |
| sd_jwt_vc | `oid4vci-1_0-issuer-fail-on-access-token-in-query`                                         | V3      | FINISHED | PASSED | 0 / 0 / 0 |
| sd_jwt_vc | `oid4vci-1_0-issuer-fail-unsupported-encryption-algorithm`                                 | V2      | FINISHED | PASSED | 0 / 0 / 0 |
| sd_jwt_vc | `fapi2-security-profile-final-discovery-end-point-verification`                            | V4      | FINISHED | PASSED | 0 / 0 / 0 |
| sd_jwt_vc | `fapi2-security-profile-final-ensure-authorization-request-without-state-success`          | V3      | FINISHED | PASSED | 0 / 0 / 0 |
| sd_jwt_vc | `fapi2-security-profile-final-access-token-type-header-case-sensitivity`                   | V3      | FINISHED | PASSED | 0 / 0 / 0 |
| sd_jwt_vc | `fapi2-security-profile-final-check-dpop-proof-nbf-exp`                                    | V3      | FINISHED | PASSED | 0 / 0 / 0 |
| sd_jwt_vc | `fapi2-security-profile-final-ensure-dpopproof-with-iat-10seconds-before-succeeds`         | V3      | FINISHED | PASSED | 0 / 0 / 0 |
| sd_jwt_vc | `fapi2-security-profile-final-ensure-dpopproof-with-iat-10seconds-after-succeeds`          | V3      | FINISHED | PASSED | 0 / 0 / 0 |
| sd_jwt_vc | `fapi2-security-profile-final-ensure-mismatched-dpop-jkt-fails`                            | V3      | FINISHED | PASSED | 0 / 0 / 0 |
| sd_jwt_vc | `fapi2-security-profile-final-ensure-token-endpoint-fails-with-mismatched-dpop-proof-jkt`  | V3      | FINISHED | PASSED | 0 / 0 / 0 |
| sd_jwt_vc | `fapi2-security-profile-final-ensure-token-endpoint-fails-with-mismatched-dpop-jkt`        | V3      | FINISHED | PASSED | 0 / 0 / 0 |
| sd_jwt_vc | `fapi2-security-profile-final-ensure-dpopproof-at-par-endpoint-binding-success`            | V3      | FINISHED | PASSED | 0 / 0 / 0 |
| sd_jwt_vc | `fapi2-security-profile-final-ensure-dpop-auth-code-binding-success`                       | V3      | FINISHED | PASSED | 0 / 0 / 0 |
| sd_jwt_vc | `fapi2-security-profile-final-ensure-authorization-request-with-long-state`                | V3      | FINISHED | PASSED | 0 / 0 / 0 |
| sd_jwt_vc | `fapi2-security-profile-final-ensure-authorization-code-is-bound-to-client`                | V3      | FINISHED | PASSED | 0 / 0 / 0 |
| sd_jwt_vc | `fapi2-security-profile-final-attempt-reuse-authorization-code-after-one-second`           | V3      | FINISHED | PASSED | 0 / 0 / 0 |
| sd_jwt_vc | `fapi2-security-profile-final-dpop-negative-tests`                                         | V3      | FINISHED | PASSED | 0 / 0 / 0 |
| sd_jwt_vc | `fapi2-security-profile-final-par-attempt-reuse-request_uri`                               | V3      | FINISHED | PASSED | 0 / 0 / 0 |
| sd_jwt_vc | `fapi2-security-profile-final-par-attempt-to-use-expired-request_uri`                      | V3      | FINISHED | PASSED | 0 / 0 / 0 |
| sd_jwt_vc | `fapi2-security-profile-final-par-authorization-request-containing-request_uri-form-param` | V3      | FINISHED | PASSED | 0 / 0 / 0 |
| sd_jwt_vc | `fapi2-security-profile-final-par-attempt-invalid-http-method`                             | V3      | FINISHED | PASSED | 0 / 0 / 0 |
| sd_jwt_vc | `fapi2-security-profile-final-par-ensure-pkce-required`                                    | V3      | FINISHED | PASSED | 0 / 0 / 0 |
| sd_jwt_vc | `fapi2-security-profile-final-ensure-pkce-code-verifier-required`                          | V3      | FINISHED | PASSED | 0 / 0 / 0 |
| sd_jwt_vc | `fapi2-security-profile-final-incorrect-pkce-code-verifier-rejected`                       | V3      | FINISHED | PASSED | 0 / 0 / 0 |
| sd_jwt_vc | `fapi2-security-profile-final-par-plain-pkce-rejected`                                     | V3      | FINISHED | PASSED | 0 / 0 / 0 |
| sd_jwt_vc | `fapi2-security-profile-final-par-without-duplicate-parameters`                            | V3      | FINISHED | PASSED | 0 / 0 / 0 |
| mdoc      | `oid4vci-1_0-issuer-metadata-test`                                                         | V5      | FINISHED | PASSED | 0 / 0 / 0 |
| mdoc      | `oid4vci-1_0-issuer-happy-flow`                                                            | V6      | FINISHED | PASSED | 0 / 0 / 0 |
| mdoc      | `oid4vci-1_0-issuer-happy-flow-additional-requests`                                        | V7      | FINISHED | PASSED | 0 / 0 / 0 |
| mdoc      | `oid4vci-1_0-issuer-happy-flow-multiple-clients`                                           | V7      | FINISHED | PASSED | 0 / 0 / 0 |
| mdoc      | `oid4vci-1_0-issuer-fail-invalid-nonce`                                                    | V7      | FINISHED | PASSED | 0 / 0 / 0 |
| mdoc      | `oid4vci-1_0-issuer-fail-invalid-jwt-proof-signature`                                      | V7      | FINISHED | PASSED | 0 / 0 / 0 |
| mdoc      | `oid4vci-1_0-issuer-fail-invalid-key-attestation-signature`                                | V7      | FINISHED | PASSED | 0 / 0 / 0 |
| mdoc      | `oid4vci-1_0-issuer-fail-invalid-client-attestation-signature`                             | V7      | FINISHED | PASSED | 0 / 0 / 0 |
| mdoc      | `oid4vci-1_0-issuer-fail-invalid-client-attestation-pop-signature`                         | V7      | FINISHED | PASSED | 0 / 0 / 0 |
| mdoc      | `oid4vci-1_0-issuer-fail-client-attestation-exp-in-past`                                   | V7      | FINISHED | PASSED | 0 / 0 / 0 |
| mdoc      | `oid4vci-1_0-issuer-fail-client-attestation-no-sub`                                        | V7      | FINISHED | PASSED | 0 / 0 / 0 |
| mdoc      | `oid4vci-1_0-issuer-fail-client-attestation-pop-wrong-aud`                                 | V7      | FINISHED | PASSED | 0 / 0 / 0 |
| mdoc      | `oid4vci-1_0-issuer-fail-mismatched-client-attestation-pop-key`                            | V7      | FINISHED | PASSED | 0 / 0 / 0 |
| mdoc      | `oid4vci-1_0-issuer-fail-missing-proof`                                                    | V7      | FINISHED | PASSED | 0 / 0 / 0 |
| mdoc      | `oid4vci-1_0-issuer-fail-unknown-credential-configuration`                                 | V6      | FINISHED | PASSED | 0 / 0 / 0 |
| mdoc      | `oid4vci-1_0-issuer-fail-unknown-credential-identifier`                                    | V7      | FINISHED | PASSED | 0 / 0 / 0 |
| mdoc      | `oid4vci-1_0-issuer-fail-on-access-token-in-query`                                         | V7      | FINISHED | PASSED | 0 / 0 / 0 |
| mdoc      | `oid4vci-1_0-issuer-fail-unsupported-encryption-algorithm`                                 | V6      | FINISHED | PASSED | 0 / 0 / 0 |
| mdoc      | `fapi2-security-profile-final-discovery-end-point-verification`                            | V8      | FINISHED | PASSED | 0 / 0 / 0 |
| mdoc      | `fapi2-security-profile-final-ensure-authorization-request-without-state-success`          | V7      | FINISHED | PASSED | 0 / 0 / 0 |
| mdoc      | `fapi2-security-profile-final-access-token-type-header-case-sensitivity`                   | V7      | FINISHED | PASSED | 0 / 0 / 0 |
| mdoc      | `fapi2-security-profile-final-check-dpop-proof-nbf-exp`                                    | V7      | FINISHED | PASSED | 0 / 0 / 0 |
| mdoc      | `fapi2-security-profile-final-ensure-dpopproof-with-iat-10seconds-before-succeeds`         | V7      | FINISHED | PASSED | 0 / 0 / 0 |
| mdoc      | `fapi2-security-profile-final-ensure-dpopproof-with-iat-10seconds-after-succeeds`          | V7      | FINISHED | PASSED | 0 / 0 / 0 |
| mdoc      | `fapi2-security-profile-final-ensure-mismatched-dpop-jkt-fails`                            | V7      | FINISHED | PASSED | 0 / 0 / 0 |
| mdoc      | `fapi2-security-profile-final-ensure-token-endpoint-fails-with-mismatched-dpop-proof-jkt`  | V7      | FINISHED | PASSED | 0 / 0 / 0 |
| mdoc      | `fapi2-security-profile-final-ensure-token-endpoint-fails-with-mismatched-dpop-jkt`        | V7      | FINISHED | PASSED | 0 / 0 / 0 |
| mdoc      | `fapi2-security-profile-final-ensure-dpopproof-at-par-endpoint-binding-success`            | V7      | FINISHED | PASSED | 0 / 0 / 0 |
| mdoc      | `fapi2-security-profile-final-ensure-dpop-auth-code-binding-success`                       | V7      | FINISHED | PASSED | 0 / 0 / 0 |
| mdoc      | `fapi2-security-profile-final-ensure-authorization-request-with-long-state`                | V7      | FINISHED | PASSED | 0 / 0 / 0 |
| mdoc      | `fapi2-security-profile-final-ensure-authorization-code-is-bound-to-client`                | V7      | FINISHED | PASSED | 0 / 0 / 0 |
| mdoc      | `fapi2-security-profile-final-attempt-reuse-authorization-code-after-one-second`           | V7      | FINISHED | PASSED | 0 / 0 / 0 |
| mdoc      | `fapi2-security-profile-final-dpop-negative-tests`                                         | V7      | FINISHED | PASSED | 0 / 0 / 0 |
| mdoc      | `fapi2-security-profile-final-par-attempt-reuse-request_uri`                               | V7      | FINISHED | PASSED | 0 / 0 / 0 |
| mdoc      | `fapi2-security-profile-final-par-attempt-to-use-expired-request_uri`                      | V7      | FINISHED | PASSED | 0 / 0 / 0 |
| mdoc      | `fapi2-security-profile-final-par-authorization-request-containing-request_uri-form-param` | V7      | FINISHED | PASSED | 0 / 0 / 0 |
| mdoc      | `fapi2-security-profile-final-par-attempt-invalid-http-method`                             | V7      | FINISHED | PASSED | 0 / 0 / 0 |
| mdoc      | `fapi2-security-profile-final-par-ensure-pkce-required`                                    | V7      | FINISHED | PASSED | 0 / 0 / 0 |
| mdoc      | `fapi2-security-profile-final-ensure-pkce-code-verifier-required`                          | V7      | FINISHED | PASSED | 0 / 0 / 0 |
| mdoc      | `fapi2-security-profile-final-incorrect-pkce-code-verifier-rejected`                       | V7      | FINISHED | PASSED | 0 / 0 / 0 |
| mdoc      | `fapi2-security-profile-final-par-plain-pkce-rejected`                                     | V7      | FINISHED | PASSED | 0 / 0 / 0 |
| mdoc      | `fapi2-security-profile-final-par-without-duplicate-parameters`                            | V7      | FINISHED | PASSED | 0 / 0 / 0 |

## Wallet module results

The four WAITING/null snapshots are successful host rejection probes only. They sent no credential or response-endpoint request. The harness stopped those modules for cleanup; cancellation is not a conformance result or error-screen evidence. Authenticated protocol-error cases have actual FINISHED/PASSED results. All retained official logs have zero FAILURE/ERROR/WARNING counts.

| Format    | Official module                                                       | Variant | Pre-cleanup status | Official result | Evidence                                 |
| --------- | --------------------------------------------------------------------- | ------- | ------------------ | --------------- | ---------------------------------------- |
| dc+sd-jwt | `oid4vp-1final-wallet-request-uri-method-post`                        | V9      | FINISHED           | PASSED          | Official pass                            |
| dc+sd-jwt | `oid4vp-1final-wallet-happy-flow`                                     | V9      | FINISHED           | PASSED          | Official pass                            |
| dc+sd-jwt | `oid4vp-1final-wallet-alternate-happy-flow`                           | V9      | FINISHED           | PASSED          | Official pass                            |
| dc+sd-jwt | `oid4vp-1final-wallet-ignores-unusable-encryption-key`                | V9      | FINISHED           | PASSED          | Official pass                            |
| dc+sd-jwt | `oid4vp-1final-wallet-fewer-claims-than-available`                    | V9      | FINISHED           | PASSED          | Official pass                            |
| dc+sd-jwt | `oid4vp-1final-wallet-optional-credential-set`                        | V9      | FINISHED           | PASSED          | Official pass                            |
| dc+sd-jwt | `oid4vp-1final-wallet-no-claims-in-dcql-query`                        | V9      | FINISHED           | PASSED          | Official pass                            |
| dc+sd-jwt | `oid4vp-1final-wallet-negative-test-invalid-request-object-signature` | V9      | WAITING            | null            | Host REJECTED; real error screen pending |
| dc+sd-jwt | `oid4vp-1final-wallet-negative-test-mismatched-client-id`             | V9      | WAITING            | null            | Host REJECTED; real error screen pending |
| dc+sd-jwt | `oid4vp-1final-wallet-negative-test-missing-nonce`                    | V9      | FINISHED           | PASSED          | Official pass                            |
| dc+sd-jwt | `oid4vp-1final-wallet-negative-test-redirect-uri-with-direct-post`    | V9      | FINISHED           | PASSED          | Official pass                            |
| dc+sd-jwt | `oid4vp-1final-wallet-negative-test-unknown-transaction-data-type`    | V9      | FINISHED           | PASSED          | Official pass                            |
| dc+sd-jwt | `oid4vp-1final-wallet-negative-test-required-non-matching-credential` | V9      | FINISHED           | PASSED          | Official pass                            |
| mso_mdoc  | `oid4vp-1final-wallet-request-uri-method-post`                        | V10     | FINISHED           | PASSED          | Official pass                            |
| mso_mdoc  | `oid4vp-1final-wallet-happy-flow`                                     | V10     | FINISHED           | PASSED          | Official pass                            |
| mso_mdoc  | `oid4vp-1final-wallet-alternate-happy-flow`                           | V10     | FINISHED           | PASSED          | Official pass                            |
| mso_mdoc  | `oid4vp-1final-wallet-ignores-unusable-encryption-key`                | V10     | FINISHED           | PASSED          | Official pass                            |
| mso_mdoc  | `oid4vp-1final-wallet-fewer-claims-than-available`                    | V10     | FINISHED           | PASSED          | Official pass                            |
| mso_mdoc  | `oid4vp-1final-wallet-optional-credential-set`                        | V10     | FINISHED           | PASSED          | Official pass                            |
| mso_mdoc  | `oid4vp-1final-wallet-no-claims-in-dcql-query`                        | V10     | FINISHED           | PASSED          | Official pass                            |
| mso_mdoc  | `oid4vp-1final-wallet-negative-test-invalid-request-object-signature` | V10     | WAITING            | null            | Host REJECTED; real error screen pending |
| mso_mdoc  | `oid4vp-1final-wallet-negative-test-mismatched-client-id`             | V10     | WAITING            | null            | Host REJECTED; real error screen pending |
| mso_mdoc  | `oid4vp-1final-wallet-negative-test-missing-nonce`                    | V10     | FINISHED           | PASSED          | Official pass                            |
| mso_mdoc  | `oid4vp-1final-wallet-negative-test-redirect-uri-with-direct-post`    | V10     | FINISHED           | PASSED          | Official pass                            |
| mso_mdoc  | `oid4vp-1final-wallet-negative-test-unknown-transaction-data-type`    | V10     | FINISHED           | PASSED          | Official pass                            |
| mso_mdoc  | `oid4vp-1final-wallet-negative-test-required-non-matching-credential` | V10     | FINISHED           | PASSED          | Official pass                            |

## Unexecuted scope and next steps

The pinned Issuer plan has 61 module entries: 42 selected per format and the following 19 unselected. None was marked PASSED, FAILED, SKIPPED or N/A by this run. Keep the existing [applicability inventory](identity-card-issuance.md#remaining-issuer-plan-applicability-inventory); unsupported or unadvertised features alone do not establish exemption.

- `oid4vci-1_0-issuer-metadata-test-signed` — NOT RUN.
- `oid4vci-1_0-issuer-happy-flow-skip-notification` — NOT RUN.
- `oid4vci-1_0-issuer-batch-issuance` — NOT RUN.
- `fapi2-security-profile-final-happy-flow` — NOT RUN.
- `fapi2-security-profile-final-user-rejects-authentication` — NOT RUN.
- `fapi2-security-profile-final-ensure-different-state-inside-and-outside-request-object` — NOT RUN.
- `fapi2-security-profile-final-state-only-outside-request-object-not-used` — NOT RUN.
- `fapi2-security-profile-final-ensure-request-object-without-redirect-uri-fails` — NOT RUN.
- `fapi2-security-profile-final-plain-fapi-tolerate-unregistered-redirect-uri` — NOT RUN.
- `fapi2-security-profile-final-ensure-unsigned-authorization-request-without-using-par-fails` — NOT RUN.
- `fapi2-security-profile-final-ensure-redirect-uri-in-authorization-request` — NOT RUN.
- `fapi2-security-profile-final-ensure-response-type-code-idtoken-fails` — NOT RUN.
- `fapi2-security-profile-final-ensure-response-type-token-fails` — NOT RUN.
- `fapi2-security-profile-final-ensure-client-id-in-token-endpoint` — NOT RUN.
- `fapi2-security-profile-final-ensure-holder-of-key-required` — NOT RUN.
- `fapi2-security-profile-final-ensure-token-endpoint-fails-with-expired-auth-code` — NOT RUN.
- `fapi2-security-profile-final-refresh-token` — NOT RUN.
- `fapi2-security-profile-final-par-ensure-reused-request-uri-prior-to-auth-completion-succeeds` — NOT RUN.
- `fapi2-security-profile-final-par-attempt-to-use-request_uri-for-different-client` — NOT RUN.

The Wallet plan has 17 entries, of which 13 were attempted per format. These four entries were NOT RUN in either format:

- `oid4vp-1final-wallet-all-mandatory-claims` — NOT RUN.
- `oid4vp-1final-wallet-negative-test-wrong-expected-origins` — NOT RUN.
- `oid4vp-1final-wallet-negative-test-invalid-client-id-prefix` — NOT RUN.
- `oid4vp-1final-wallet-multisigned-one-invalid-signature` — NOT RUN.

First examine and run the pinned unchanged notification-tolerance module for both Issuer formats, then the cross-client PAR `request_uri` case using the existing two disposable clients. Record conditional SKIP only if the suite actually produces it, with its applicability reason. Browser telemetry, Wallet error screens, other unexecuted cases and formal submission remain separate work. [Issue #119](https://github.com/masanork/mikaki/issues/119) remains OPEN; this checkpoint does not complete its full-scope or HAIP 1.1 requirements.
