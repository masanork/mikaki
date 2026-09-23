# Project status

This page distinguishes deployed behavior, local verification, and planned work. It reflects the evidence recorded on 2026-09-23; later changes need their own verification.

| Capability | Evidence | Limit |
| --- | --- | --- |
| Portable WebAuthn verifier | Native and Wasm adapters passed all 155 required tests in the recorded FIDO2 Server Conformance Tools 1.9.1 run. | No formal FIDO certification or general security assurance. See the [test record](../local/conformance/results-2026-09-22.md). |
| Local login slice | Disposable local Workers and D1 exercise invitation enrollment, discoverable passkey login, OIDC Code + PKCE, RP session creation, and logout. | A test harness, not a production deployment. See [local development](getting-started.md). |
| Rust OIDC Worker | Local workerd probes cover selected code exchange, UserInfo, replay, concurrency, and client authentication. | A probe is not full interoperability or production readiness. See [OIDC conformance](oidc-core-conformance.md). |
| OIDC conformance | A local OIDF Config OP plan passed. A local Basic OP plan finished with 21 passed, 8 skipped, 4 manual review, 2 warning, and 0 failed modules. | Manual review and warnings remain; there is no formal certification or hosted conformance deployment. |
| Normal-profile Worker | `https://mikaki.tossa.app` serves health, Discovery, JWKS, and deployed account, client, session, and Vault routes. | No registered production RP or account, authenticated Vault write, or production PRF unlock has been demonstrated. See [deployment](cloudflare-deployment.md). |
| Runtime policy | D1 contains an active versioned policy; selected Worker projections and a change CLI exist. | Not every example TOML field has a complete product loader or enforcement path. See [runtime configuration](runtime-configuration.md). |
| Vault | An owner-only R2 bucket, D1 migration, cleanup trigger, and page are deployed. | Depends on an existing SSO session and PRF-capable passkey; no production write/unlock evidence yet. |
| UserInfo recipient keys | A local D1 key directory, claim Worker verification route, staging/disable CLI, and audit checks are implemented or under test. | The OP service binding, Secrets Store provisioning, activation/rotation, grants, and claim sharing are not enabled. See the [key lifecycle contract](vault-recipient-key-lifecycle.md). |
| Post-quantum cryptography | Isolated ML-KEM/ML-DSA and Vault HPKE probes exercised native, Wasm, browser, known-answer, and interoperability paths under recorded conditions. | No post-quantum algorithm is enabled for product passkeys, OIDC signing, or Vault recipients. See the [rollout plan](pqc-rollout.md). |
| Supply-chain attestations | CI builds and attests a Worker archive, Rust SBOM, and source-based CBOM. | The currently deployed Worker was uploaded from a developer machine; CI attestations do not identify its running bytes. See [supply-chain evidence](supply-chain.md). |

## Release blockers

Before use by real users, register and exercise production RPs; complete account and administrator enrollment; verify passkeys and PRF with intended devices; validate callback, session, and logout behavior end to end; exercise operational recovery and monitoring; and resolve the relevant conformance and security review gates. The [deployment guide](cloudflare-deployment.md) records the environment-specific state.

Vault sharing, file storage APIs, conversation archiving, federation, and MCP access are described as proposals in the [roadmap](roadmap.md). Partial recipient-key work does not make UserInfo claim sharing available.
