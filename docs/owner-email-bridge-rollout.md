# Owner email schema bridge rollout

## Production status on 2026-11-10

The email bridge (#348), feature restoration (#349), Access readiness bridge (#350), and integrated Access code (#351) have been merged and deployed. Owner migrations 0009 through 0012 were applied one at a time; stage audits and authenticated readiness checks passed between stages. The read-only combined audit on 2026-11-10 observed 12 Owner, 12 Work and 3 Messaging migrations, 535 schema objects and no foreign-key violations. The active OP reported clean source `7b7c7b765ab6ad5943630f7ba77b21a3cf99bded` and version `d53511d6-4b92-42e6-9c19-77aab1afbd99`; [main deployment and production smoke](https://github.com/masanork/mikaki/actions/runs/42762985632) succeeded. These are point-in-time observations; recheck before an operational decision.

This does not establish Access activation, actual integrated Access client qualification, physical Passkey behavior, or complete production backup and recovery. Public discovery advertised only `openid` and `profile`, and the production configuration does not set the Access client ID. Historical D1 restore can lose later Work and Messaging writes and does not restore R2 or other external state; the external recovery fence described in [release and recovery](release-and-recovery.md) remains unimplemented.

## Historical bridge plan

At the time of this plan, #336 had reached main while the previous Worker remained deployed with the Owner ledger at 0008. That Worker reported not ready if either new migration was applied. The bridge temporarily removed the undeployed feature and its migration files while adding readiness support. It also retained the later #340 and #345 dependency changes, so it was not otherwise identical to the deployed source.

The intended sequence, after separate review and qualification, is:

1. Confirm the current deployed Worker, all three Owner/Work/Messaging schemas, the exact ledger, the source and artifact attestations, bindings, and a tested recovery procedure. The production Worker and database must still match the expected 0008 state.
2. Promote this bridge via the normal main release pipeline and verify the actual deployed version and an existing-account flow. Retain the bridge as the Worker fallback.
3. Apply the two reviewed #336 migrations only through a separately reviewed migration procedure, with ledger, schema and readiness checks after each. The exact SQL and hashes must match the reviewed feature source. Reassess current state and recovery before each write.
4. Restore the feature in a subsequent change, run its full release validation, and promote it only after both migrations and the full schema are verified. A Worker rollback to the original 0008 version is unsafe after migration; a D1 restore is a separate decision and can discard intervening writes.

This historical plan did not supply a migration runner or a complete backup and restore procedure. The final Access chain uses 0011 and 0012, rather than the competing names in the old Access drafts.

## Read-only schema audit

`node scripts/audit-email-bridge-schema.mjs --remote --stage 12` compares the production Owner, Work and Messaging ledgers, full schema and foreign keys with byte-pinned migration inputs. Its remote CLI requires an explicit expected stage from 8 through 12 and accepts only the reviewed production configuration. Select the actual expected ledger stage; the command never applies migrations. The 0009 and 0010 SQL files under `scripts/fixtures/owner-email-migrations` are byte-pinned review fixtures. The test `node --test scripts/audit-email-bridge-schema.test.mjs` exercises all five stages and rejects an unexpected schema and a wrong ledger.

The audit rechecks the Owner ledger at the end and rejects a changed ledger, but executes multiple separate reads, not an atomic snapshot, and does not fence writes or establish backup/recovery. A separately reviewed procedure must address quiescence, post-migration verification, unknown outcomes and recovery before applying any production migration.
