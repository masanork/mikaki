# Private managed-work checkpoint

Local SQLite Durable Object and named service/admin entrypoints for the [authority checkpoint contract](../../docs/work-authority-checkpoint.md). There is no public API, product configuration or activated resource. OP work state, secrets and Git payloads remain in their assigned boundaries.

Run `npm run check:work-checkpoint` and `npm run test:work-checkpoint` from the repository root. The latter builds this Worker into the ignored qualification output and exercises its actual workerd/Durable Object state alongside Rust OP/D1. All bootstrap, fault and data-reader hooks are confined to that disposable local fixture.

`WorkPreparationEvidence` is a separate read-only binding for Native's
[preparation composer](../../docs/work-preparation-evidence.md). It projects only
six retained closed-effect/Git records; it exposes none of the checkpoint,
effect-admission or maintenance mutations.

Keep checkpoint storage outside the primary D1 restore domain, with one fixed scope per D1 authority. Bind `WorkCheckpointService` to the trusted OP and reserve `WorkCheckpointAdmin` for the private operator capability. Separate human/control-plane ownership follows the [administration policy](../../docs/adr/0017-work-administration-policy.md); production permits a single operator without claiming protection against privileged changes to both stores. Complete external effect/release enforcement, coverage of other OP authority mutations and signed release/recovery provenance. Never reinitialize or restore the checkpoint from stale D1 data.

`WorkCheckpointBootstrap` narrows initial operator access to `inspect()` and
`enroll(plan)`. It exposes no framing, floor, freeze, effects or reset methods;
its HTTP entrypoint returns 404. Enrollment requires the deployment's
`WORK_BOOTSTRAP_PACKET_SHA256` pin and the exact fixed object's ID. The immutable
plan and initial state are written in one SQLite transaction and synchronized
before acknowledgment. Existing legacy state cannot be adopted into this ledger.
Inspection reports retained state even when frozen or pending, without advancing
it. Resource/version claims in the plan still require independent control-plane
inventory; the DO cannot verify those claims itself.

`npm run test:work-authority-bootstrap` exercises the bounded operator protocol
against disposable actual D1 and SQLite DO, including both lost replies and
independent restart. See the [isolated authority sequence](../../docs/work-authority-qualification.md).
