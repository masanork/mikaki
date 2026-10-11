# Work adoption into the existing production OP

Production activation is authorized for testing. The retained Work implementation
has reached main through PRs #178, #179, #181 and #182. Main source
`9bbe587aff3fc3458525c842a2696cbc86819c2c` passed the complete CI, signing,
OP/Docs deployment and public smoke run
[38177711148](https://github.com/masanork/mikaki/actions/runs/38177711148).

Read-only control-plane inspection on 2026-10-12 JST observes that exact source
at 100% traffic. The existing production D1 contains one account, one credential
and seven SSO sessions; its Owner ledger has the three current migrations.
It has no Work tables or checkpoint/source/copy binding. Existing accounts and
private allocation journals are retained. No Work activation has occurred.

## Additive schema and populated-primary qualification

[The schema pins](../scripts/production-work-schema.ts) fix all twelve existing
Work SQL files by name and SHA-256. Their separate `work_schema_migrations` table
records ordered IDs, filenames and digests. The Owner `d1_migrations` ledger
remains exactly three files, including the waiting list. Work's original 0003
numbering is never combined with the Owner Wrangler migration chain.

The [production deployment gate](../scripts/deploy-production.ts) accepts this
additional schema only when the reviewed configuration explicitly selects
`WORK_SCHEMA_ENABLED=true`. That selects the complete exact Owner plus Work
schema and separate ledger. Missing files, changed bytes, partial ledgers,
missing triggers and unknown schema objects still refuse promotion. Owner-only
deployment keeps its original exact schema check. Enabling a Work capability
without the schema selection refuses promotion. This change supplies no
production config flag, migration command or remote write.

The [populated-primary adapter](../scripts/production-work-adoption.ts) captures
the complete verified application schema and rows, with a maximum of 64 rows per
table and 1 MiB total. BLOBs retain their storage type. The initial checkpoint
tip binds this snapshot. Its plan fixes the current production account, D1 and
authority, and requires non-placeholder checkpoint identities. The adapter
clones the snapshot, requires every application table and the complete separate
ledger, and compiles the SQL guard before independent enrollment.

Marker insertion repeats schema, both ledgers, row counts and all captured
values in one guarded D1 transaction. It modifies no existing account, Passkey,
session, Vault, invitation or policy row. A failed preflight cannot admit SQL;
changed state after preflight rolls the entire insertion back. An attempted
insert is consumed before I/O, including a lost acknowledgment. Inspection can
observe a committed initial marker without replaying insertion.

The original [isolated bootstrap](../scripts/work-authority-bootstrap.ts)
continues to refuse the production target and requires its frozen empty-state
snapshot. The production adapter does not relabel populated production data as
an empty isolated allocation. It exposes no reset, automatic remote executor,
replacement resource allocation or Work effect admission.

## Remaining activation sequence

1. Resolve the independent checkpoint deployment/restore operator required by
   [the checkpoint contract](work-authority-checkpoint.md). Record actual
   resource, module, version and custody inventory; review digests alone do not
   establish independent ownership. The current token's roles are not readable
   from the available inspection and are not claimed to be independent.
2. Qualify a bounded migration executor and the exact staged production
   configuration. Apply the fixed additive chain with its own ledger, preserving
   existing Owner data. Verify the complete schema before enrolling anything.
3. Qualify and verify quiescence for public and named OP entrypoints, scheduled
   mail/GC writers and Queue delivery; an observed lack of requests is not a
   quiescence mechanism. Capture the actual populated snapshot under that fence.
4. Run the private, recorded one-shot independent/primary enrollment using the
   fixed snapshot and provider identities. Keep writers closed until matching
   initial markers are observed. Lost replies require inspection of the same
   identities and journals; they never authorize a reset or replacement epoch.
5. Promote the qualified OP with only `WorkCheckpointService` bound to it.
   Keep bootstrap/floor/freeze access in the operator boundary. Verify existing
   login, invitation, logout and Owner Vault behavior before opening Work.
6. Qualify framed registration of artificial test sources and the actual private
   Artifacts reader. Open source review and owner composition/consent first.
   Copy execution additionally needs the fixed Workflow, effect/mint/Git
   capabilities, credential custody and sealed host qualification. Actual owner
   consent remains a product action. Synthetic conformance facts do not replace
   remote source or productive Artifacts qualification.

After enrollment, an OP version missing the checkpoint binding cannot be a
functional rollback target. Schema alone never authorizes copying. Historical
unknown Artifacts/Queue outcomes remain unknown and charged; no new production
resource or test changes that retained evidence.
