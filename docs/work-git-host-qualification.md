# Isolated Git-host infrastructure qualification

Status: isolated Cloudflare deployment, cold/warm readiness and private R2 supply
verified on 2026-10-10. Inactivity restart remains unqualified; the original third
intent and resources are retained. Selected remote execution and resource results
are recorded in the implementation ledger. This precedes productive
[Git-host activation](work-git-host.md). It checks Container startup, private
ports, sealed R2 supply and inactivity restart, independently of copy authority.

## Target and capabilities

The selected account is `4b749427a0c80c547e726a42aff4b6fc`, matching the existing
mikaki account. Use **separate** Worker, Container application and R2 bucket,
all named `mikaki-work-git-host-qualification`. Its SQLite namespace contains
only infrastructure probe metadata, never productive Git admission records.
It is not the production `mikaki-auth` Worker or `mikaki-auth-vault` bucket.
The R2 inventory read on 2026-10-10 did not contain the qualification bucket.
Check inventory again before creation; a reused name does not establish ownership.

The [qualification Worker](../crates/work-git-host-worker/qualification.ts)
exports only a named private `WorkGitHostQualification.prepare()` RPC. It accepts
no arguments. Default/named HTTP handlers return 404; Workers.dev, preview URLs
and routes are disabled. There is no Git dispatch handler or provider binding.
Both `WORK_GIT_HOST_ENABLED=false` and `WORK_GIT_PROVISION_ENABLED=true` are
required. Container Internet access is disabled. The program runs the same
trusted Linux entry and shared startup/provisioning code as the productive host.

Before startup, an immutable SQLite frame pins the account, namespace, synthetic
authority, disclosure and registry. At most three probe attempts are synchronized
before I/O. Missing replies consume their slot, including across isolate restart.
Frame changes and a fourth invocation are refused. These probe slots are separate
from the productive host's four Git slots. Nothing in this probe creates a task,
repository, credential, grant or run, or qualifies Native authority remotely.

## Authentication selection

`wrangler whoami` selected the existing account using the environment API token.
However, `wrangler containers list` stopped in Wrangler's local scope check:
the saved OAuth scopes were `user:read`, `account:read`, `artifacts:write` and
`offline_access`, with no `containers:write`. This happened before a Containers
API request; it does not establish the environment token's Containers permissions.
No remote resource was allocated during that diagnostic.

An independent Containers API read with the existing environment API token
returned HTTP 200 and an empty application list. The installed CLI also succeeded
with `--profile mikaki-work-git-host-qualification`, which selects a separate
credential profile rather than the saved Artifacts-only OAuth scopes. The
environment token still supplies authentication. **No new OAuth grant is needed
for the selected token.** Use that profile consistently for the Containers and
deployment commands in this lane.

If a later operator chooses OAuth instead, the installed Wrangler 4.148.0 lists
the scopes below and adds `offline_access` itself. Retain existing Artifacts
access rather than replacing its scope with Containers alone:

```sh
npx wrangler login --scopes user:read account:read workers:write workers_scripts:write containers:write artifacts:write
```

This requires the account holder's OAuth consent. Do not paste tokens into chat
or commit credentials. Verify the **effective** identity with `wrangler whoami`:
an existing `CLOUDFLARE_API_TOKEN` takes precedence over OAuth for authentication.
If choosing OAuth, `env -u CLOUDFLARE_API_TOKEN npx wrangler ...` selects it for
that process without removing the stored environment token. All operations must
target the selected account. R2 bucket/object operations separately require R2
permissions; successful Workers authentication alone does not establish them.
See [Workers authorization](https://developers.cloudflare.com/workers/authorization/workers/)
and [API token permissions](https://developers.cloudflare.com/fundamentals/api/reference/permissions/).

## Frozen preparation and deployment

From a clean committed checkout, prepare a packet under an ignored directory:

```sh
npm run prepare:work-git-host-qualification -- 4b749427a0c80c547e726a42aff4b6fc local/generated/work-git-host-qualification
```

The [preparer](../scripts/prepare-work-git-host-qualification.ts) uses the actual
local Rust/Wasm Native fixture to export a disclosure of artificial code/context.
Its SSO, source registration and checkpoint identity are **synthetic local facts**.
This is not an export from an enrolled remote Native/checkpoint deployment.
Only selected content and reachable task history enter the sealed source packs.
No real personal/Vault content or Artifacts credential is used.

The packet retains the Native record, sealed registry/packs, code-only Linux
image context, a bundled qualification Worker and a closed `target.json` receipt.
Worker/program/Dockerfile/registry hashes and clean source commit are fixed.
Generated `wrangler.json` references packet bytes, so later workspace changes
cannot change that packaged Worker or image. Source and Worker files are local
until explicitly uploaded/deployed. The output command reports the packet path.

After authentication and fresh resource inventory checks:

1. Confirm the qualification Worker/Container names are unused or belong to the
   exact retained qualification. Never adopt an unrelated existing namespace.
2. Create the dedicated private R2 bucket if its absence is confirmed. Check that
   public access and custom domains are disabled. Do not use the Vault bucket.
3. Upload only `registry.json`, `task.pack` and `snapshot.pack` to
   `registry/<registry_sha256>/<filename>`. Independently retain upload hashes;
   do not overwrite an uncertain or mismatching existing package.
4. Run `wrangler deploy --dry-run --containers-rollout none --config <packet>/wrangler.json`
   with an absolute ignored output directory. Separately build the packet's image
   for `linux/amd64`; verify its program/Dockerfile hashes against `target.json`.
5. Deploy the selected qualification Worker and code-only image. Retain the
   Worker version, Container application/namespace IDs and immutable image
   reference from provider metadata. Verify account, private routes, bindings
   and image against the selected packet before invoking the probe.

These steps allocate only infrastructure test resources. Deployment does not
enable the productive copy Workflow or adopt any protected Artifacts repository.
The [example configuration](../crates/work-git-host-worker/wrangler.qualification.example.jsonc)
and actual generated packet are reviewable before any remote action.

## Private probe and receipts

The [runner](../scripts/qualify-work-git-host.ts) uses Wrangler's authenticated
[remote service binding](https://developers.cloudflare.com/workers/local-development/#remote-bindings)
through [`getPlatformProxy`](https://developers.cloudflare.com/workers/wrangler/api/#getplatformproxy).
It opens no public probe endpoint and binds only the selected qualification
Worker's named entrypoint. It verifies packet hashes and requires a separately
selected account-scoped, digest-pinned Cloudflare image reference:

```sh
npm run qualify:work-git-host -- <packet> registry.cloudflare.com/4b749427a0c80c547e726a42aff4b6fc/<image>@sha256:<digest>
```

An exclusive, synchronized `infrastructure-run.jsonl` retains selection, intent,
closed responses, validated observations and final outcome. Calls have no retry
and a five-minute client deadline. The three-step sequence is cold start, warm
readiness, then readiness after disconnecting the authenticated proxy and waiting
225 seconds. A fresh proxy carries the third call. The returned pin/image/ordinal
must match; the third call must report a new start. A valid but mismatching closed
response is retained before expectation checks. Invalid shapes are recorded only
as refusal metadata, without persisting arbitrary fields or strings. An unexpected
response, missing reply or retained previous invocation stops qualification.
Never reset slots, change authority names or generate replacement packets to
retry an uncertain call.

The configured 60-second
[Container inactivity timeout](https://developers.cloudflare.com/containers/api/durable-object-container/#setinactivitytimeout)
starts after its Durable Object becomes inactive, not after the last RPC.
[DO lifecycle](https://developers.cloudflare.com/durable-objects/concepts/durable-object-lifecycle/)
documents 70–140 seconds before eviction for an idle, non-hibernateable object;
pending I/O can extend its lifetime. The 225-second window covers that documented
idle interval plus the Container grace with a margin, but it does **not** establish
that the Container has stopped. A warm third response still fails qualification.
Disconnecting removes this client's live session from the measurement; it does
not independently prove that the session caused the original failure.

Results include elapsed time, actual startup image, Internet-disabled status and
zero Git dispatches. They do not establish source erasure, real Git egress,
provider credential handling on Cloudflare, production capacity or copy authority.
Actual owner-authorized source registration, enrolled authority, productive Git
exchange/readback and credential cleanup retain their separate gates. The six
protected development repositories/journals remain unchanged.

Local RPC/SQLite/restart tests execute the actual qualification classes. Shared
startup tests use real local R2 and Linux bootstrap with an explicitly synthetic
Container capability. The Docker lane runs the Linux entry. These local results
do not establish remote scheduling/private service routing; final selected
source and counts belong in the [implementation ledger](work-delegation-implementation.md).

## First retained remote run

The packet `local/generated/work-git-host-qualification/git-registry-g1ACm0`
identifies clean source `0b47be3a58cc705701848c18cce6bff33b362a1d`. Its actual Native
and OP fixture bundles were rebuilt from that source before the final local
qualification and materialization; production Native/UI match integrated `5cf4616`.
Three private R2 objects were uploaded once and independently downloaded with
byte-for-byte equality. The deployed Worker has no public targets. Provider
metadata verified the exact account, namespace, Container image and private R2
binding, with Internet and productive Git disabled.

The private RPC run measured cold readiness at **8,236 ms** and warm readiness at
**19 ms**, with matching registry, disclosure, image and attempt ordinal. These are
two observations of a small artificial fixture, not performance percentiles.
The original client waited 75 seconds with its proxy still open. Its third intent
is retained, followed by an unqualified outcome. The original client validated
before journaling the response, so the third result and failure cause cannot be
reconstructed from that journal. No third success is claimed or inferred.

Read-only provider inspection at `2026-10-10T05:27:20.226Z` found the same named
Durable Object and no active Container instance. A scoped telemetry query returned
no events. This establishes the later inactive state, not a successful stop/start
cycle during the third call. No fourth RPC, replacement packet, slot reset or
resource deletion was used. Keep `infrastructure-run.jsonl`, `remote-resources.json`,
`r2-readback.json`, `provider-metadata.json` and `runtime-diagnostic.json` together.

Client follow-up `40ad040074f710a20e92005935a8c19a70a44a38` adds connection release,
the corrected wait window and closed response-before-validation journaling.
Its **8/8** focused cases pass; it has not been rerun against the spent/uncertain
remote sequence and was not deployed as a replacement Worker. Before another
remote restart measurement, add retained inspection/outcome handling for the
existing qualification and define an independently bounded measurement that
preserves the original attempts. Productive activation also still requires the
enrolled Native authority and protected Artifacts allocation reconciliation.
