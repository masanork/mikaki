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

Before Worker deployment and enrollment, resolve the isolated browser origin, separate
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

## Capability and enrollment sequence

The OP receives only the named `WorkCheckpointService` capability; reserve
`WorkCheckpointAdmin` (bootstrap, release floor, irreversible freeze) for a
separately reviewed operator. Reserve `OpAuthorityAdmin` for the OP operator.
Neither operator capability is bound to the OP's public facade. Cloudflare's
[named service entrypoint documentation](https://developers.cloudflare.com/workers/runtime-apis/bindings/service-bindings/rpc/)
supports this separation. Separate storage does not establish independent
deployment/restore ownership: an actor able to replace both boundaries can
undermine it. This same-account qualification does not claim an independent
control-plane trust domain.

1. Inventory the proposed names, allocate dedicated empty resources and retain
   their actual IDs, versions and binding/module inventories against a reviewed
   packet digest. Resolve templates only into a new child deployment packet.
   The preparer supplies no deployment materializer or remote bootstrap transport.
   Closed storage allocation uses the separate once-only operator tool below.
2. Apply the frozen combined fourteen-file migration ledger to that empty D1.
   Refuse populated, production, partly migrated or restored targets. The first
   two files must match the reviewed Owner Vault digests; the subsequent twelve
   form the opt-in Work chain. The template's `migrations_dir` points to the
   frozen combined directory, per Cloudflare's
   [D1 migration configuration](https://developers.cloudflare.com/d1/reference/migrations/).
3. Keep primary writers, browser ingress and scheduled work quiescent during
   initial checkpoint enrollment. The OP template has an empty cron list;
   enable scheduled work only in the later reviewed environment. Choose
   one new epoch/tip at sequence zero. Bootstrap the independent DO once, then
   insert the exact matching primary marker once. These writes have no shared
   transaction: journal intent/observations before each boundary and require
   exact matching state without pending permits before enabling any writer.
   Lost replies authorize inspection of the same identities, never a new epoch
   or replacement bootstrap. Independent state must not be restored from D1.
4. Review the isolated HTTPS issuer and runtime policy before opening ingress.
   Use new signing/readiness secrets and an issuer-specific Passkey RP ID. An
   operator-issued bootstrap invitation creates no Work owner authority: the
   intended person must finish real Passkey enrollment, login and PRF Vault
   opening. Keep invitation, SSO and key material private. The historical
   enrollment note's pre-baseline migration number is not this environment's
   migration instruction.
5. Register small artificial code/context sources under the actual account,
   current policy and access revision. Select a read-only registered-source
   reader and fixed namespace/recipient/workload mapping. Registration and
   policy activation are authority mutations, not fixture SQL seeds. Qualify
   their remote operator transport and framed admission before composition is
   enabled. `WORK_PREPARATION_COMPOSE_ENABLED` remains false in this packet.
6. Exercise actual source selection, disclosure/preparation review, session-bound
   consent and withdrawal in the UI. Record checkpoint/audit changes and absence
   of provider/Git effects. Copy execution, effect, mint and Git-store flags
   remain false. No Artifacts binding, provider bearer, copy Workflow, Git
   transport or Work wrapping key is supplied.
7. Verify revocation and refusal cases listed above. Preserve receipts and use
   separately reviewed, predetermined cases for irreversible floor/freeze
   tests. A stopped or frozen authority is never reset or automatically replaced.

`USERINFO_CLAIMS`, OIDC clients and email delivery are outside this owner-authority
phase and need their own isolated configuration if the environment is extended.
The checkpoint template retains the SQLite migration configuration supported by
the pinned Wrangler. Module loading preserves the complete Rust shim/Wasm tree;
it does not point back to mutable workspace build files.

Inventory verification checks exact member names, symlinks, both configuration
templates, migration/schema and byte digests. It is not authenticity verification:
preserve a reviewed manifest digest outside the packet. Rewriting bytes and their
manifest cannot establish trusted provenance. See the
[checkpoint contract](work-authority-checkpoint.md) and
[implementation record](work-delegation-implementation.md).

`npm run test:work-authority-packet` runs the packet/schema rejection cases in
CI. `node scripts/qualify-work-authority-packet.ts PACKET [NEW_RECEIPT_FILE]` loads only the frozen
product modules and checkpoint in local workerd, applies the frozen migrations
to disposable local D1, and verifies empty authority, the actual enrollment
page, unauthenticated owner refusal, closed fixture/admin HTTP routes and the
uninitialized private checkpoint service. Its temporary issuer and D1 identity
are local test settings, never deployment inputs. This smoke check enrolls no
owner or checkpoint, and does not exercise a real person's Passkey ceremony.
The optional receipt is created exclusively and records the selected packet,
qualifier source and script digest; keep it outside the immutable packet.

## Once-only closed resource allocation

`node scripts/allocate-work-authority.ts inventory` performs two complete bounded
read inventories of D1, R2, Queues and the two proposed Worker identities. The
allocator pins the separately reviewed `authority-nMECMX` manifest digest
`5b06b4588934813995f965bf5e76da9c44d7e08c98045519192f888bdd2a02d3` and
verifies its frozen members before network access. `allocate` creates only the
fixed dedicated D1, R2 and logout Queue/DLQ. It deploys neither Worker, applies
no migrations, bootstraps no checkpoint and opens no browser ingress. Storage
may be reserved while origin/operator choices remain unresolved; those choices
still gate deployment and enrollment.

The tool requires a clean selected source. All linked Git checkouts use one
reservation in the common repository's ignored
`local/generated/work-authority-allocation/reservation.json`. Each provider
create is preceded by an exclusive private intent record; both record and parent
directory are synced before the request. Existing names are collisions, never
adopted. A lost reply or failed identity read stops the sequence, retaining every
record and reservation. A new checkout, absent list result or rerun cannot grant
another create slot. Inspect the same IDs; never remove the reservation, retry
creation, or replace the allocation. Read inventories do not reconcile an
unknown create into an acknowledged allocation.

Acknowledged resource names, IDs and creation times are read back and checked
against stable complete inventories. Authentication remains in the process's
`CLOUDFLARE_API_TOKEN` header; receipts contain no bearer or raw binding values.
`npm run test:work-authority-allocation` covers collision, lost/invisible replies,
durable journal failure, identity substitution, pagination and HTTP refusal.
New templates and any bootstrap plan must carry these retained identities into
a separately verified child packet, without editing the frozen parent packet.

The pinned Wrangler test harness does not retain the module-root configuration
for this unbundled generated Rust entrypoint. The local qualifier therefore uses
Miniflare's explicit module-root/module list, matching the frozen upload files.
Actual Wrangler `deploy --dry-run --env-file /dev/null` verifies additional
module discovery without uploading or changing remote bindings. A manual
same-origin enrollment redirect stays inside local workerd rather than being
followed by Node's network fetch.
