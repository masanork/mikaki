# Documentation

The [README](../README.md) is the entry point. This index routes readers to the current implementation, operating instructions, design contracts, and future work. For what has actually been exercised, read [status](status.md) first. The [changelog](../CHANGELOG.md) records changes from 2026-09-23 onward.

## Current implementation and operations

| Need | Read |
| --- | --- |
| Run the disposable local flow | [Getting started](getting-started.md) and the detailed [local harness record](../local/README.md) |
| Integrate an RP | [RP integration](rp-integration.md), [client operations](rp-client-operations.md), and [managed session check](rp-session-check.md) |
| Enroll an account | [Account enrollment](account-enrollment.md) |
| Operate the Worker | [Cloudflare deployment](cloudflare-deployment.md) and [runtime configuration](runtime-configuration.md) |
| Review conformance evidence | [WebAuthn](../local/conformance/README.md) and [OIDC](oidc-core-conformance.md) |
| Review build evidence | [Supply chain](supply-chain.md) and [metrics](../metrics/README.md) |
| Work on the code | [Development guide](contributing.md) |

## Understand the system

Start with [architecture](architecture.md) for responsibilities and trust boundaries. The [ADRs](adr/README.md) preserve accepted choices in their original sequence. Topic documents describe contracts or rationale; an accepted design is not proof of a deployed feature.

| Topic | Contract and evidence |
| --- | --- |
| WebAuthn | [Ceremonies](webauthn-ceremony-contract.md), [attestation](webauthn-attestation.md), [extensions](webauthn-extensions.md), [diagnostics](webauthn-errors.md), [MDS operation](webauthn-mds-operation.md) |
| WebAuthn quality | [Fuzzing](webauthn-fuzzing.md), [device compatibility](webauthn-device-compatibility.md), [fit/gap backlog](webauthn-fit-gap-todo.md), [external review brief](webauthn-security-review.md) |
| OIDC | [Login UX](oidc-login.md), [transaction](oidc-login-flow.md), [identity and keys](oidc-identity-and-keys.md), [Access Token and UserInfo](oidc-access-token-and-userinfo.md), [store operations](oidc-store-contract.md), [operations](oidc-operations.md) |
| Account and policy | [Sessions and logout](session-lifecycle.md), [identifier policy](identifier-policy.md), [runtime configuration](runtime-configuration.md), [policy example](../config/runtime-policy.example.toml) |
| Vault | [Personal vault](personal-vault.md), [UserInfo claim-sharing proposal](vault-claim-sharing.md), [recipient-key lifecycle](vault-recipient-key-lifecycle.md) |

## Planned work and earlier design

The [roadmap](roadmap.md) distinguishes deployed components from intended capabilities. [PQC rollout](pqc-rollout.md) records isolated results and adoption gates; no PQC product algorithm is enabled. [Storage API](storage-api.md), [federated messaging](federated-messaging.md), and [crypto agility](crypto-agility.md) are design or future-work references.

The [implementation spec](implementation-spec.md) preserves the cross-cutting acceptance gates and future design. The [OIDC implementation-readiness plan](oidc-implementation-readiness.md) combines an implementation baseline with release gates. Check [status](status.md) and the relevant runbook for current deployment evidence. The [frontend and CI plan](frontend-and-ci.md) includes implemented choices and proposed quality targets.

## Documentation rules

- **Deployed** means present in a named environment, with the exercised behavior stated.
- **Locally verified** means a recorded test or probe passed under its stated conditions.
- **Accepted decision** records intended architecture or product policy; it does not imply implementation.
- **Proposal** and **future** describe work that has not passed a product activation gate.

The active versioned D1 policy is authoritative for deployed runtime values. The [TOML example](../config/runtime-policy.example.toml) is an editing/input example. SQL models and Python checks under `design/` and `scripts/` validate designs unless identified as production migrations or loaders.

Repository Markdown documentation is in English. The product UI still supports Japanese and English. Historical ADRs retain their sequence; topic documents present the current contract or a clearly marked proposal.
