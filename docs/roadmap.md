# Roadmap and design maturity

This page groups the project's intended stages. It is a direction of work, not a release promise. [Status](status.md) lists what has actually been verified or deployed.

| Stage | Intended outcome | Maturity |
| --- | --- | --- |
| Passkeys and OIDC | Shared account, WebAuthn login, managed RP integration, session lifecycle, and browser-side PRF key protection. | Core paths exist in local tests and parts of the Worker; production integration and release gates remain. |
| Personal vault | Encrypt data on the client; store ciphertext and wrapped keys in IndexedDB and R2; recover on another authorized device. | Owner-only storage components are deployed; production write and unlock are not verified. See [vault design](personal-vault.md). |
| Selective UserInfo claim sharing | Add a separate recipient-key directory, browser-side envelope, grant, and dedicated claim Worker. | Local directory, verification route, and staging/disable operations exist; activation, grants, and end-to-end sharing remain. See [claim sharing](vault-claim-sharing.md) and [key lifecycle](vault-recipient-key-lifecycle.md). |
| Conversation archive | Import conversations from participating applications with the user's authorization and provide cross-app access. | Future design. |
| Federated messaging | Start with one-to-one text delivery between two independently deployed instances, with DID-based identity and end-to-end encryption. | Future design; protocol and trust choices have gates. See [federation](federated-messaging.md). |
| Limited MCP access | Let a user delegate selected read access to an AI client with scope and expiry. | Future design; receiving a message does not authorize disclosure to AI. |

The [implementation spec](implementation-spec.md) contains the earlier staged design and acceptance gates. [Storage API](storage-api.md) and [Vault claim sharing](vault-claim-sharing.md) are proposals. [Crypto agility](crypto-agility.md) and [PQC rollout](pqc-rollout.md) describe migration conditions, not currently deployed algorithms or a committed rollout date.

New capabilities should have a concrete user need, state transitions, failure behavior, and verification plan before they add abstractions to the authentication core. A future container deployment would add an adapter around the same core; it is not part of the first release.
