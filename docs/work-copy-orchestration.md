# Approved preparation to verified copy

Status: locally integrated; production flags, provisioning and migration remain
gated. This implements the copy portion of [ADR 0016](adr/0016-personal-context-and-workload-delegation.md),
after [owner composition](work-preparation-compose.md) and
[explicit copy approval](work-request-ui.md). Verification and credential
closure do not delegate work or start an agent.

## Private production staging

The thirteen companions have been provisioned privately from the signed runtime
for source `9ff6ebfe8ba1e1a2ac92831b50c6995b3b8de75e`. All thirteen deployed
module bodies were independently read through the provider content API and
matched the retained bundle bytes. Their settings and active-version bindings
matched the closed configuration, including 23 named service edges. Workers.dev,
preview URLs and cron triggers were disabled, with no custom domains. The
observation receipt SHA-256 is
`f0c4b869b655200c427f19359ebc8171439f740c911cfecfe47a4fb201c3a177`;
the configuration packet SHA-256 is
`b1894ec636d759d572be4def9e77cb9719a7fad8c34448522c05343e18035df3`.

The Git host uses the dedicated private `mikaki-work-git-sources` bucket and
the digest-pinned Cloudflare Registry image. Its Container uses a newly
provisioned SQLite DO namespace, with SSH disabled. No sealed source objects
were uploaded. The retained disclosure has expired and cannot authorize copying.
Existing qualification resources and protected Artifacts journals were not reused.

`WORK_COPY_BINDINGS_STAGED=true` selects the exact thirteen OP named edges,
including its existing authority checkpoint edge. Normal promotion requires
all separately provisioned companions to exist and all six OP copy/effect/mint/
Git/verification gates to remain explicitly false. Missing, additional or
retargeted Work capabilities refuse promotion. OP routes, storage, queues and
runtime secrets remain part of the existing qualified upload. The staging
selection cannot enable copy execution or provision companions automatically.

This is closed infrastructure staging, not full graph or productive qualification.
Any later productive rollout must independently match the current OP/checkpoint
and companion sources, versions, bytes and bindings; register and verify active
key custody; obtain a fresh Native disclosure and explicit current owner consent;
then qualify real provider copy, independent Git readback and credential closure.

## Durable identities and ownership

Rust WorkStore owns a retained `work_copy_job` for each preparation. Migration
0014 is in the separate opt-in ledger; it creates no jobs automatically. Native
queues a job and its audit in one covered primary transaction before notifying
the private Workflow starter. Every job keeps the reviewed digest and preparation
ID. The owner transport accepts only format version and reviewed digest, with
live SSO, same-origin, bounded strict JSON and current Native authority checks.
Approval remains bound to the original live SSO. A replacement login for the
same owner cannot adopt that approval or queue another job. Background
progression checks the approving session rather than
the currently open browser session.

The Workflow identity is always `copy-<preparation_id>`. Lost starter replies can
leave a queued outbox. An exact owner retry or the bounded scheduled drain
notifies the same instance. The starter never restarts an instance or allocates
a replacement identity. The example includes a minute cron, with execution
disabled by default. A queued response acknowledges storage, not execution.
If that instance is already complete, errored or terminated while a queue
remains, the notifier calls Native safety cleanup instead of restarting it.
The Workflow validates its own instance ID against the preparation ID before
calling Native. The [Workers API](https://developers.cloudflare.com/workflows/build/workers-api/)
defines those instance states; only Native can confirm copy completion.

The TypeScript Workflow contains transport and scheduling only. It cannot
choose a provider account, destination, token, repository, credential role or
Git command. Its sole productive service is the named Native `WorkCopyStore`.
The public OP and other named facades deny the raw copy administration RPC.
The Workflow and starter default HTTP entrypoints return 404.

## Native progression

| Ordinals | Native operation                                                                                                                 |
| -------- | -------------------------------------------------------------------------------------------------------------------------------- |
| 0, 1     | Dispatch the approved preparation, then create each fixed repository and close its initial credential.                           |
| 2–9      | Task upload and readback: mint, fixed Git exchange, known-ID revocation evidence, independent bearer refusal and Native closure. |
| 10–17    | Snapshot upload and readback with the same four operations.                                                                      |
| 18       | Compose independent evidence for both copies and all six closed credential slots; publish verified status.                       |

A covered compare-and-set records admission and audit before each physical
gate. Only its winner invokes that gate. The gate's independent, permanent
admission still protects against primary D1 or Workflow restoration. The Native
completion transaction repeats current authority and consent; the final phase
requires the actual verified preparation. Provider acknowledgements alone do
not certify copying or data-plane credential refusal.
Mint progression requires both encrypted Native custody and explicit OP
synchronization. Final verification requires a matching preparation ID and
verified gate response together with the actual Native verified record.
After a completed initial effect, withdrawal, a raised release floor, a changed
provider account, a missing wrapping key or expiry fences the next effect.

Each productive Workflow step has retries disabled and a bounded timeout.
This follows Cloudflare's requirement to make external effects idempotent and
retain progress through named steps; Workflow retry alone cannot provide
exactly-once provider behavior. See the official
[Workflow rules](https://developers.cloudflare.com/workflows/build/rules-of-workflows/)
and [retry/timeout configuration](https://developers.cloudflare.com/workflows/build/sleeping-and-retrying/).

## Unknown results and safety

A failed or already-inflight admission cannot resend Git, create a replacement
repository or mint another token. The job stops. A retained blocked record
cannot transition back to running, be deleted, or be reused as a fresh job.
Earlier completed steps are read-only on repetition. An operator cannot recover
by lowering the checkpoint, resetting an independent admission, or changing the
Workflow ID.

Safety cleanup uses only existing attempt IDs. Initial-effect reconciliation
and mint cancellation retain independent cleanup intent before provider I/O.
Explicit mint cancellation can fence an already custodied credential; the
ordinary unknown-result recovery endpoint still refuses productive custody.
Only a known observed token ID can be revoked. Unobserved tokens, failed
inventory or failed data-plane refusal retain the cleanup obligation. Empty
inventory, elapsed time or an expired state is insufficient proof.

Independent cleanup can proceed when productive Native authority is frozen.
Native synchronization may remain pending until its covered authority is
available; that does not certify closure or grant permission. Safety retries
cannot mint, copy or launch. Stop does not erase copies already created.

## Product UI

The preparation review links to a separately bundled authenticated
`/work/copy-review#<preparation_id>` after approval. A fresh acknowledgement is
required to start. The screen distinguishes not started, queued, running,
blocked/unknown and verified. Refresh reads Native status; it does not submit
another start. Stop requests safety cleanup of the existing job.
Withdrawing approval keeps the progress link available for the existing copy;
it never makes that job startable again.

The shared owner display lease clears local status and acknowledgement on
lock, hidden state or session replacement, and rejects late replies. Reopening
reads the retained job. The browser receives only bounded metadata, never
provider bearer material, custody envelopes or private token observations.
Copy verification explicitly leaves work delegation unperformed.

## Qualification and activation limits

Local tests run the product Rust/Wasm, primary D1, independent checkpoint and
effect journals, actual Cloudflare Workflow engine and real loopback Git smart
HTTP. Owner identities, provider IDs and secrets are synthetic. Browser tests
exercise Japanese/English, 375px layout, accessibility, explicit start,
read-only progress recovery and a start committed before a late locked response.
The integrated test also creates the preparation through the public composition
API, records separate approval, materializes its exact Native disclosure into
sealed Git packs and finishes both copies through the Workflow and HTTP host.
It verifies all six credential closures and absence of task/request/grant/run
authority. Session fixtures are seeded before checkpoint enrollment; expiry
tests wait for their actual deadline without changing protected SSO rows.

```sh
npm run test:work-copy-job
npm run check:work-copy
```

Activation needs the opt-in schema and checkpoint enrollment, an already active
wrapping key, fixed Artifacts account/namespace, all private gate bindings and
the registered trusted Git host. Composition calculates object identities; it
does not materialize or register repositories on that host. Deployment must
provision and independently qualify that materialization/registration path
before enabling owner execution. The [private Git host](work-git-host.md) now
materializes exact Native selections, supplies sealed packs through private R2
and includes a code-only Linux image plus a retained Container admission bridge.
Local qualification includes the sealed host path. It does not qualify remote
Cloudflare Container deployment or real Artifacts copying.

Both `WORK_COPY_EXECUTION_ENABLED` on Native and
`WORK_COPY_WORKFLOW_ENABLED` on the Workflow remain opt-in. The existing owner,
source and preparation review gates are also required for the UI. No production
bindings, issuer, launcher, baseline migration or protected remote journal is
changed by this integration. Qualified issuer/launcher delegation is a later
decision; this job creates no task, request, grant or run.
