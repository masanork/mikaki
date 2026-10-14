# Managed-work initial effect and maintenance

These private Workers implement the current-main [initial-effect contract](../../docs/work-artifacts-effect-gate.md).
No Wrangler deployment configuration or remote resource is enabled here.
The public/default handlers return 404; reviewed named bindings supply each
private capability.

- `worker.ts`: one admitted initial task/snapshot create, immediate token
  revocation, inventory checks and explicit Git bearer refusal before closure.
- `maintenance.ts`: physical Artifacts owner returning only fixed-repository
  metadata/token inventory and admitted ID revocation capabilities.
- `reconcile.ts`: safety-only recovery of admitted unknown creates, with no
  physical Artifacts binding, creation, mint, write, delete or workload release.
- `git.ts` / `git-transport.ts`: independently admitted fixed Git exchanges using
  encrypted Native custody and a separately provisioned private Git host. See
  the [Git contract and deployment limits](../../docs/work-artifacts-git-gate.md).
  At the first Native copy step, the existing named transport performs one
  bearer-free host preflight before repository creation or credential reservation.
  The host retains the admission and checks its pinned image and sealed source
  readiness. Failure or a lost reply blocks that copy without replay; an existing
  unknown host attempt cannot acquire another preflight. Readiness is infrastructure
  evidence and does not count as Git upload, readback or credential closure.
- `preparation.ts`: opaque composition trigger; Native validates the read-only
  independent evidence and six closed custody records before recording verified
  preparation. See the [composition contract](../../docs/work-preparation-evidence.md).

Run `npm run check:work-effects` and `npm run test:work-effects`. The latter uses
actual Rust/Wasm/workerd/RPC/DO with synthetic Artifacts/Git. The full local
authority/checkpoint/effect gate is `npm run test:work-delegation`.

Existing protected remote journals and unresolved allocations must be
reconciled against their original immutable IDs before any new remote trial.
Local qualification does not reset or certify those resources. Git-host deployment,
workload release, authenticated copy consent
and operator/recovery provenance retain separate gates.
