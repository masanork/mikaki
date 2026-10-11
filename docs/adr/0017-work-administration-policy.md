# Work checkpoint administration policy

Status: accepted, 2026-10-12. Supersedes the unconditional separate-operator
activation requirement for production Work. Historical isolated packets and
their unresolved admissions retain their original scope and evidence.

Work requires a checkpoint in its own SQLite Durable Object, outside the primary
D1 restore domain. OP receives only the service entrypoint. Initial enrollment,
floor changes and freezing remain private operator capabilities, without reset,
unfreeze or rebase. Missing, stale, pending or frozen checkpoint state still
refuses the covered mutation and release paths.

Human and control-plane separation are deployment policies. The production
[administration policy](../../scripts/work-administration-policy.ts) selects
`operator_separation: optional`, allowing one operator to administer both
resources. A deployment can select `required` and must then inventory distinct
operator identities and verify their actual deployment/restore permissions.
Different identity strings alone do not establish provider isolation.

Single-operator mode detects a primary D1 rollback while the checkpoint remains
current. It does not protect against a privileged operator changing or restoring
both resources, or modifying code/schema to bypass checks. These limits are
recorded in the adoption inventory. It never claims an independent reviewer or
independent control-plane ownership that has not been established.

The policy does not authorize stale epochs, bypass checkpoint checks, remint an
unknown operation, change owner consent, or release credentials and source
plaintext. Additive migration and populated enrollment still require exact
schema, bounded snapshots, verified quiescence, recorded one-shot attempts and
matching checkpoint/primary observations before opening writers.
