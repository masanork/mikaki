# Private managed-work checkpoint

Local SQLite Durable Object and named service/admin entrypoints for the [authority checkpoint contract](../../docs/work-authority-checkpoint.md). There is no public API, product configuration or activated resource. OP work state, secrets and Git payloads remain in their assigned boundaries.

Run `npm run check:work-checkpoint` and `npm run test:work-checkpoint` from the repository root. The latter builds this Worker into the ignored qualification output and exercises its actual workerd/Durable Object state alongside Rust OP/D1. All bootstrap, fault and data-reader hooks are confined to that disposable local fixture.

`WorkPreparationEvidence` is a separate read-only binding for Native's
[preparation composer](../../docs/work-preparation-evidence.md). It projects only
six retained closed-effect/Git records; it exposes none of the checkpoint,
effect-admission or maintenance mutations.

Before integration, assign independent storage/operator/recovery ownership and one fixed scope per D1 authority. Bind `WorkCheckpointService` to the trusted OP and reserve `WorkCheckpointAdmin` for the separate operator boundary. Complete external effect/release enforcement, coverage of other OP authority mutations and signed release/recovery provenance. Never reinitialize or restore the checkpoint from stale D1 data.
