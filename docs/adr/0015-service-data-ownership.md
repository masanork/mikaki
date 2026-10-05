# ADR 0015: OP-owned durable storage and bounded service capabilities

**Status:** Accepted, 2026-10-04. OP/Claims ownership is deployed and verified at the [2026-10-05 cutover](../production-reset-2026-10-05.md). The Agent boundary is locally qualified and enforced in its configuration; no hosted Agent was activated.

## Decision

The OP is the runtime owner of the shared D1 database and Vault R2 bucket. The Agent Worker and UserInfo recipient Worker use distinct named service entrypoints in that OP deployment. Neither downstream production configuration carries a D1 or R2 binding. The recipient secret remains exclusively in the UserInfo Worker. Deployment administrators retain their separate administrative permissions.

| Caller | OP entrypoint | Permitted operations |
| --- | --- | --- |
| Agent | `AgentStore` | Exact catalogued Agent domain statements, with bounded parameters and atomic batches |
| UserInfo recipient | `ClaimStore` | Recipient metadata, explicitly selected record-v2 name ciphertext and envelope, readiness, conditional disclosure audit |
| Public internet | Default Rust OP | Registered HTTP routes; named storage paths are unavailable |

The Agent cannot send SQL, alter OP sessions, credentials, OIDC codes/tokens, owner heads or runtime policy, or read arbitrary R2 keys. The catalog is generated from actual Agent product SQL, reviewed with that implementation, and checked in CI. Only `agent_*` mutations are accepted by the generator. Batches contain at most 64 statements and the request stream is bounded to 64 KiB. This remains a trusted Agent domain authority: possession of its binding authorizes the catalogued Agent operations. It is not an untrusted general database client.

The ClaimStore takes an access-token hash rather than an arbitrary account/object key. It selects the exact live code/session/scope, owner grant, RP release, head, envelope and recipient key using the same SQL contract as Rust claim delivery. Before plaintext can leave the recipient, a conditional audit repeats those predicates and the selected revision/digest/key. Revocation during decryption therefore fails closed. The OP returns ciphertext and public metadata; it never receives the recipient private seed.

## Atomicity and compatibility

Each Agent `DB.batch` becomes one OP D1 `batch`, including conditional guards and audit writes. It is never split into multiple fetches. Every invocation uses a primary D1 session; no stale read replica is used as authorization evidence. OP owner commits remain their existing Rust atomic transitions.

Both local and production Claim Worker configs use `CLAIM_STORE` and omit direct D1/R2 bindings. #121 removes the former local-test storage escape hatch and format-1 UserInfo decoder/authority. Missing service bindings fail closed. The record-v2 live-secret suite exercises the same service boundary and conditional audit with real local Secrets Store seeds. Historical format-1 heads or consent cannot authorize disclosure.

## Rollout and rollback

1. Back up and rehearse migrations, including existing encrypted heads. Build the Rust OP and `npm run build:op-authority`; the release inventory includes `worker/service.mjs` alongside the Rust shim/Wasm and verifies all member hashes.
2. Deploy the OP default handler plus named entrypoints first. Existing downstream code and bindings continue to function during this step. Qualify readiness and service operations against the exact OP version.
3. Deploy downstream clients with their named service bindings. Remove their D1/R2 bindings in the same reviewed version configuration. Qualify Agent concurrency/audit rollback and UserInfo success/revocation races before enabling any sharing policy.
4. For rollback, first restore a compatible downstream version and its reviewed binding configuration, then roll back the OP. Rolling back the OP first would remove required named entrypoints. Do not reverse migrations or restore revoked authorization state as a routine rollback.

The fresh baseline cutover discarded old participant state; no sharing grants or recipient authorization were restored. OP/Claims deployment is established by the source-attested promotion and active-version binding checks in the [cutover record](../production-reset-2026-10-05.md). Recipient/RP sharing policy and hosted Agent activation remain disabled. The production gate inspects the complete binding set and exact service entrypoints before activation; an extra capability or duplicate binding name must fail closed. Physical-device qualification and standards certification do not follow from these deployment or local contract results. See [architecture](../architecture.md) and [release and recovery](../release-and-recovery.md).
