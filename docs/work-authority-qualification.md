# Isolated Native/checkpoint qualification

The next remote gate uses a dedicated product OP/Native Worker and independent
SQLite checkpoint. The six protected Artifacts allocations remain attached to
their original journals. Their unknown admissions are never imported as new
authority, retried, or replaced. The production OP remains outside this lane.

`node scripts/prepare-work-authority.ts prepare ACCOUNT local/generated/OUTPUT`
prepares an offline packet from a clean commit. It builds the actual product
Rust/Wasm, without the `work-qualification` feature, and packages the named OP
facades, checkpoint bundle, seventeen frozen migrations and input inventory.
The Wasm must contain the selected commit. Each member has a byte count and
SHA-256, and the packaged schema is applied only to in-memory SQLite. Verification
uses `node scripts/prepare-work-authority.ts verify PACKET`.

The current seventeen-file chain includes all five production owner migrations
and the twelve opt-in Work files, without renaming migrations that share a
numeric prefix. Retained fourteen-, fifteen- and sixteen-file packets keep their
original exact owner-migration prefix, plan, member inventory and source identity.
Verification pins each applicable migration's bytes and derives the matching
plan. Adding the login-review migration to an older packet, or removing a
required file from a current packet, is refused; an old packet is never silently
upgraded or substituted for current-source qualification.

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
   The preparer supplies no remote bootstrap transport. The offline child
   materializer below requires complete acknowledged allocation and reviewed
   origin, ownership and signing custody. Closed storage allocation uses the
   separate once-only operator tool below.
2. Apply the frozen combined fifteen-file migration ledger to that empty D1.
   Refuse populated, production, partly migrated or restored targets. The three
   production baseline files must match the reviewed Owner Vault and waiting-list
   digests; the twelve Work files form the opt-in Work chain. Both directories
   retain their original filenames, including separate `0003` files. The
   template's `migrations_dir` points to the
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

### Recovery of the audited DLQ and completion of the remaining Queue

`node scripts/complete-work-authority.ts inspect` reads the retained original
allocation, pinned DLQ audit receipt and fresh provider identities.
`complete` reserves one canonical `completion-v1` directory under the original
common-repository allocation root. Its numbered private records separately
retain the original unknown DLQ outcome, the positive `create_queue` audit
match and the one unattempted logout Queue create. The original 236 records,
reservation and partial seal remain unchanged.

This executor is fixed to the reviewed original allocation/reservation digests,
DLQ audit ID, Queue identity, name and request-time interval. It re-reads the
provider audit by ID and verifies the dedicated D1/R2/DLQ identities, unattached
Queues, absent main Queue and closed Worker identities before admission.
The shared completion directory and each record are synchronized before the
new create. A failed or completed reservation is retained across linked
checkouts. Lost replies consume the remaining Queue slot and require inspection
of the same identities; later lists cannot grant another create.

The deployment evidence reader validates both journals, includes their combined
digest and grants completion only after the new Queue acknowledgment, exact
readback and stable final inventory. Historical unknown admissions remain in
the original journal and are explicitly linked to the recovery proof. The
executor enables no Worker, browser ingress, migration, checkpoint bootstrap,
owner authority or productive Artifacts/Git capability. Origin, separate
operator/recovery ownership and signing-custody reviews still gate a deployment
child.

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

## Offline child deployment packet

`node scripts/work-authority-deployment.ts inspect [NEW_RECEIPT]` verifies the
fresh frozen bootstrap packet and reads the original common-repository allocation
reservation and consecutive numbered journal. It makes no provider calls. The
optional receipt is created exclusively under ignored `local/generated`, with
the inspector digest and an explicit retained-journal provenance label. This is
not a fresh provider inventory or an authorization to deploy.

The CLI pins the new `authority-zFCHDp` parent manifest
`101e4405e6eb3dfd40e50e46a1bdeaf6d8b886ec294f735b913864a943d53849`.
The allocator's older `authority-nMECMX` review and original reservation remain
unchanged. Creation intents, acknowledgments and exact identity readbacks must
occur once in the fixed D1/R2/DLQ/Queue order, ending with a complete allocation
and matching final report. Missing or lost acknowledgments remain consumed;
neither subsequent readback nor a final report upgrades them. An acknowledged
resource whose readback did not finish is retained as unverified. A stopped or
partial journal cannot produce a deployment child.

`prepare REVIEW REVIEW_SHA256 OUTPUT_PARENT` requires an externally retained
SHA-256 of a closed JSON review. The review pins the parent, complete allocation
evidence and reservation; names a canonical isolated HTTPS issuer; identifies
the OP/checkpoint operators and recovery owners; and references ownership and
signing-custody review digests. Cross-boundary operator/recovery identities must
be distinct. These identifiers are reviewed claims, not proof of separate
control-plane ownership; the same-account limitation is explicit. No secret,
private JWK, bearer, readiness token or owner material belongs in this review.
The exported `deploymentReviewSchema` defines its exact fields.

Preparation copies all parent members byte for byte into a new exclusive child,
then adds resolved `op/wrangler.json`, `checkpoint/wrangler.json`, and the local
`operator/wrangler.json`. Only the dedicated D1 ID, reviewed issuer and checkpoint
bootstrap packet pin are resolved. OP retains only `WorkCheckpointService`.
The operator connection has only dedicated D1 and `WorkCheckpointBootstrap`
remote bindings; it has no HTTP implementation or deployment command. Both
Worker configurations have empty routes, disabled workers.dev/preview URLs,
and the OP retains empty crons and all productive execution flags disabled.
The configuration fields follow the pinned schema and
[Wrangler configuration contract](https://developers.cloudflare.com/workers/wrangler/configuration/).

The child retains the original parent manifest, review bytes and complete private
journal evidence, plus its own manifest. `verify CHILD CHILD_SHA256` uses an
external child digest, checks exact membership/configurations and frozen parent
bytes, and works without the original parent directory. A rewritten child
inventory cannot substitute reviewed parent bytes. Completed and partial child
directories are never amended or reused. Qualification fixtures can pass an
explicit synthetic parent pin to the offline library; the CLI's pin is fixed.

Preparation deploys neither Worker, applies no migration, registers no Queue
consumer, installs no secret and grants no bootstrap/owner authority. Namespace,
version and object IDs and the bootstrap plan remain unresolved until verified
deployment observations exist. Before any remote write, the executor still needs
fresh resource/config/version observations, quiescence evidence and a shared
account/authority bootstrap reservation. The per-child bootstrap journal is not
that global reservation.

The retained DLQ unknown admission currently refuses this gate. Supporting its
eventual positive provider/operator reconciliation requires a separately reviewed
append-only protocol; this materializer does not rewrite or reinterpret the
stopped original journal. `npm run test:work-authority-deployment` covers six
local cases, including unknown replies, substitution, private capability
separation, review/origin/ownership refusal, exclusive immutable children,
portable verification, symlinks and journal membership. Synthetic fixture
receipts are not provider allocation or real owner evidence.

## Bounded initial operator protocol

`WorkCheckpointBootstrap` is the new initial-enrollment capability. Its named
RPC methods are only `inspect()` and `enroll(plan)`; their results are JSON strings
carrying data rather than RPC targets, and HTTP returns 404. OP still
receives only `WorkCheckpointService`. Floor/freeze administration remains a
separate capability. The closed plan pins the reviewed product packet,
allocation, ownership and quiescence reviews, account, primary D1 ID, checkpoint
namespace/version/object ID, and one sequence-zero epoch/tip at release floor
one. The checkpoint deployment must set `WORK_BOOTSTRAP_PACKET_SHA256` to the
reviewed packet digest. Missing/wrong pins, wrong object/scope, existing state or
effect ledgers, and any second enrollment are refused. Existing legacy initial
state cannot acquire new packet provenance. The plan and state commit together
using SQLite `transactionSync`, followed by `sync` before acknowledgment, per
the [storage API](https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/).

`scripts/work-authority-bootstrap.ts` supplies the bounded operator sequence,
read-only reconciliation and a private local operator connection configuration.
It derives primary schema and seed rows from the packet's exact frozen chain,
including the current waiting-list schema and its initial policy row.
Preflight compares the complete ordered migration ledger, lexical schema,
foreign keys and every application table against that initial state. Inserting
the single primary marker repeats schema, ledger and all row guards in the same
D1 batch; a changed guard rolls the batch back. Only known provider metadata is
excluded: `sqlite_*`, `_cf_KV`, `_cf_METADATA` and `d1_migrations`. The ledger is
checked separately. Query size and parameter count fit the documented
[D1 bounds](https://developers.cloudflare.com/d1/platform/limits/); predicates
use a balanced expression to fit the pinned runtime's expression-depth limit.

The canonical child packet owns one exclusive `bootstrap.jsonl`, with its file
and directory synchronized before crossing either write boundary. A completed
or partial journal refuses another run. The future remote executor must also
reserve the account/authority lane across child packets and linked checkouts;
the per-child helper alone is not that global reservation. If either result is
lost, `inspectBootstrap` observes the same identities without issuing either
write. An exact initial marker may be observed after a lost primary reply; an
absent marker does not authorize replay. Intermediate, legacy, dirty, pending,
raised-floor or frozen state never completes enrollment. Completion itself
enables no writer or browser ingress. RPC results are detached as bounded JSON
and explicitly disposed according to the
[RPC lifecycle](https://developers.cloudflare.com/workers/runtime-apis/rpc/lifecycle/).

This implementation is a library plus actual local D1/SQLite DO qualification,
not a qualified remote bootstrap executor. IDs/review digests supplied by a
caller are claims until matched to retained provider observations. The DO cannot
validate control-plane namespace/version ownership or prove quiescence from
those strings. A remote executor must verify deployed module/config/version
and primary resource identities, separate operator/recovery ownership, and the
retained allocation before invoking this sequence. The previous immutable
`authority-nMECMX` bundle has no new bootstrap entrypoint or packet pin; preserve
it and build/review a new packet rather than substituting its checkpoint bytes.

`npm run test:work-authority-bootstrap` is registered in CI. Its ten local cases
cover exact initial agreement, restart, closed private methods, both lost replies,
absence without replay, concurrent one-time enrollment, legacy-state refusal,
primary changes between preflight and insertion, and pending/floor/freeze
refusal. Disposable test IDs and local state are not provider allocation or real
owner enrollment evidence. No remote migration, authority bootstrap or ingress
opening is performed by this suite.
