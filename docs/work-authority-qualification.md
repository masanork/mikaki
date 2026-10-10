# Isolated Native/checkpoint qualification

The next remote gate uses a dedicated product OP/Native Worker and independent
SQLite checkpoint. The six protected Artifacts allocations remain attached to
their original journals. Their unknown admissions are never imported as new
authority, retried, or replaced. The production OP remains outside this lane.

`node scripts/prepare-work-authority.ts prepare ACCOUNT local/generated/OUTPUT`
prepares an offline packet from a clean commit. It builds the actual product
Rust/Wasm, without the `work-qualification` feature, and packages the named OP
facades, checkpoint bundle, fourteen frozen migrations and input inventory.
The Wasm must contain the selected commit. Each member has a byte count and
SHA-256, and the packaged schema is applied only to in-memory SQLite. Verification
uses `node scripts/prepare-work-authority.ts verify PACKET`.

The fixed account is `4b749427a0c80c547e726a42aff4b6fc`. Intended resources are
`mikaki-work-authority-qualification` (OP and D1),
`mikaki-work-checkpoint-qualification` (checkpoint Worker),
`mikaki-work-vault-qualification` (R2), and the dedicated logout Queue/DLQ named
in `plan.json`. No resource is created by preparation. Templates deliberately
retain unresolved D1 identity and browser origin, and are not deploy targets.
Public workers.dev and preview URLs are disabled. Productive composition,
copy execution, initial effects, mint and Git are disabled.

Before allocation and enrollment, resolve the isolated browser origin, separate
OP/checkpoint operator and recovery ownership, fresh resource identifiers and
signing-key custody. Verify provider resource identity and an empty dedicated
D1 against the frozen packet. Bootstrap the independent checkpoint and matching
primary marker once under quiescence. A lost result requires inspection of the
same identities; preparation never authorizes reset, restore, replacement
bootstrap, or import from the previous synthetic checkpoints.

Remote qualification must complete actual Passkey owner enrollment and PRF Vault
opening, register an artificial source under current owner/policy authority and
bind its private reader. Exercise source inspection and owner consent while
productive copy remains disabled. Verify current checkpoint/session authority,
account/credential/session/source/policy revocation, pending and frozen frames,
release floors and isolated D1 restore refusal. Synthetic SSO seeded by a local
test is not evidence of actual owner enrollment or consent.

Preparation is a local byte/schema inventory, not a signed release attestation,
deployment, enrolled authority, actual owner result, or remote recovery proof.
Retain partial packets and provider intents/outcomes separately. A complete
packet remains reviewable without granting any productive Artifacts effect.
