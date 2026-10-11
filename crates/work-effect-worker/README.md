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

Run `npm run check:work-effects` and `npm run test:work-effects`. The latter uses
actual Rust/Wasm/workerd/RPC/DO with synthetic Artifacts/Git. The full local
authority/checkpoint/effect gate is `npm run test:work-delegation`.

Existing protected remote journals and unresolved allocations must be
reconciled against their original immutable IDs before any new remote trial.
Local qualification does not reset or certify those resources. Upload/readback,
productive mint/release, authenticated copy consent and operator/recovery
provenance retain separate gates.
