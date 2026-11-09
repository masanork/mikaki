# Owner email schema bridge rollout candidate

The feature in #336 has reached main, but the previous Worker remains deployed with the Owner ledger at 0008. That Worker reports not ready if either new migration is applied. This change temporarily removes the undeployed feature and its migration files while adding a readiness bridge. It also retains the later #340 and #345 dependency changes, so the candidate is not otherwise identical to the deployed source. The ordinary release pipeline remains unchanged; this is not permission to deploy or migrate production.

The intended sequence, after separate review and qualification, is:

1. Confirm the current deployed Worker, all three Owner/Work/Messaging schemas, the exact ledger, the source and artifact attestations, bindings, and a tested recovery procedure. The production Worker and database must still match the expected 0008 state.
2. Promote this bridge via the normal main release pipeline and verify the actual deployed version and an existing-account flow. Retain the bridge as the Worker fallback.
3. Apply the two reviewed #336 migrations only through a separately reviewed migration procedure, with ledger, schema and readiness checks after each. The exact SQL and hashes must match the reviewed feature source. Reassess current state and recovery before each write.
4. Restore the feature in a subsequent change, run its full release validation, and promote it only after both migrations and the full schema are verified. A Worker rollback to the original 0008 version is unsafe after migration; a D1 restore is a separate decision and can discard intervening writes.

No migration runner, backup, restore, or deployment approval is supplied by this change. The migration ordering and recovery procedure need their own executable, synthetic-environment rehearsal and review. The open Access drafts use different migration names and require reconciliation with whichever Owner chain is ultimately adopted.

## Read-only schema audit

`node scripts/audit-email-bridge-schema.mjs --remote --stage 8` compares the current production Owner, Work and Messaging ledgers, full schema and foreign keys with byte-pinned migration inputs. Its remote CLI requires an explicit expected stage (8, 9, or 10) and accepts only the reviewed production configuration. Use stage 9 or 10 only to inspect the corresponding already-applied ledger; the command never applies migrations. The 0009 and 0010 SQL files under `scripts/fixtures/owner-email-migrations` are byte-pinned review fixtures, not active migrations. The test `node --test scripts/audit-email-bridge-schema.test.mjs` exercises all three stages and rejects an unexpected schema and a wrong ledger.

The audit executes multiple separate reads, not an atomic snapshot, and does not fence writes or establish backup/recovery. A separately reviewed procedure must address quiescence, post-migration verification, unknown outcomes and recovery before applying any production migration.
