# Native bearer refusal and mint closure

M6c closes one upload/readback credential obligation when its retained encrypted
bearer is concretely refused at the fixed repository's Git endpoint. It extends
[known-ID recovery](work-artifacts-mint-recovery.md): a control-plane revoke or
revoked inventory remains a prerequisite, rather than sufficient closure proof.
No mint, Git write, copy verification, workload grant or productive credential
release is added.

## Native proof and fixed egress

The [Native adapter](../crates/worker/src/work_effect/refusal.rs) validates the
attempt digest, immutable repository, token ID, purpose/scope, absolute expiry and
stored wrapping-key version. Only a matching revocation-pending encrypted row can
supply a bearer. Rust obtains the operator-provisioned key under the existing
floor/fingerprint checks and uses authenticated service custody to decrypt it.
Missing or substituted keys, missing custody and unframed ciphertext changes
cannot produce a refusal proof.

The credential travels only in an Authorization header to a named private
[refusal transport](../crates/work-effect-worker/mint-refusal-transport.ts).
Native derives the account/namespace/name URL from operator configuration and the
retained preparation. The transport holds physical Artifacts and a read-only
mint lookup; it accepts only that admitted operation's exact GET
`/info/refs?service=git-upload-pack`, with cleanup intent and retained control-plane
evidence. It checks repository ID, name, branch, remote, initial-operation
description and exact revoked-token metadata before and after the HTTP call.
Missing inventory requires the already retained ID-specific positive revoke
acknowledgement. It offers no mint, file read, write, deletion or returned raw
repository capability.

The [Git API](https://developers.cloudflare.com/artifacts/api/git-protocol/)
documents this smart HTTP remote and Bearer authentication; both read and write
tokens allow upload-pack reads. This local profile accepts only a concrete 403
after qualified revocation. It refuses redirects and uses a five-second timeout.
All remote response content is cancelled, and neither the bearer nor response
content reaches the coordinator or owner/workload output. Rust zeroizes owned
secret buffers; Authorization strings in the private transport/runtime have no
guaranteed memory erasure. The transport is inside the trusted secret-handling
boundary, not a general credential getter.

## Retain proof before closing Native

The private [closer](../crates/work-effect-worker/mint-closure.ts) accepts only an
opaque attempt ID. It holds the named Native effect adapter and
`WorkMintRefusalCheckpoint`, which exposes lookup and refusal retention only.
It has no physical Artifacts, plaintext, mint admission, cleanup-intent mutation
or OP-framing/admin binding. Public/default handlers return 404.

Native returns bounded refusal metadata and a domain-separated digest receipt.
The closer first saves exact proof in the independent SQLite ledger, then sends
the fixed `mint-close` action. Proof binds the observation and wrapping-key
version; its first receipt and observation time cannot be replaced. The ledger
becomes `closed` and retains its permanent namespace/name/purpose slot. Productive
custody, abandonment and revocation calls cannot reopen that state.

The receipt is a trusted Native/coordinator's observation record, not a provider
signature or independently verifiable attestation. Possession of the private
effect/closure capabilities remains a trust boundary; a public request cannot
submit a receipt or select a bearer/destination. Native synchronization rechecks
the exact stored observation/version and receipt binding before confirming
`refused`. Its existing framed atomic batch erases encrypted custody and releases
only that obligation's charged bytes. The retained attempt and independent
tombstone are not deleted or reclaimed.

Lost proof/closure acknowledgements and process restart reuse retained proof
without another HTTP probe. An audit abort or checkpoint freeze can leave
independent `closed` proof with `op_synchronized: false` and the charged Native
row still revocation-pending. No Native batch bypass is introduced. Later proof
synchronization needs no decryption key. Whole D1 restore cannot reopen the mint;
a restored reserved row remains unsynchronized without reconstructing a secret.

Control-plane cleanup without encrypted custody cannot prove bearer refusal.
An unobserved token, an expired/list-missing outcome without qualified evidence,
200, redirect, unavailable HTTP or substituted repository/inventory retains
uncertainty. Preparation verification, all-six-slot closure, productive fixed Git
upload/readback, workload release and owner copy/delegation composition remain
separate gates. No production flags/bindings, baseline migrations, protected
remote journals or real Artifacts resources/tokens are changed. New bindings are
synthetic-local only; no remote refusal qualification is claimed.

## Qualification

The [closure suite](../local/conformance/work-mint-closure.test.ts) exercises actual
Rust/Wasm, workerd, D1, private HTTP/RPC and persistent SQLite with synthetic
Artifacts/Git. It covers four role/purpose pairs, no ciphertext/charge after
confirmed Native closure, no preparation/grant promotion, missing custody/key,
substituted key and guarded SQL, failed/redirected HTTP, repository/token metadata
substitution, immutable proof, lost acknowledgements, audit rollback, freeze,
restart, whole primary restore, cancellation and cold/public/RPC/egress limits.
Focused cases are qualified; the combined main-integrated regression is recorded
in the [integration plan](work-delegation-implementation.md).
