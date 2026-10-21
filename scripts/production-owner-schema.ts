/** Reviewed feature chain, separate from the immutable reset and Docs baseline gates. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { BASELINE_SCHEMA_QUERY, canonicalSchema, type SchemaRow } from './production-baseline.ts';
import { workAdoptionFences } from './production-work-fence.ts';
import {
  assertMessagingMigrationFiles,
  assertMessagingLedger,
  MESSAGING_LEDGER_SQL,
  type MessagingSchema,
} from './production-messaging-schema.ts';
import {
  assertWorkMigrationFiles,
  assertWorkLedger,
  WORK_LEDGER_SQL,
  type SqlMigration,
  type WorkLedgerRow,
} from './production-work-schema.ts';

export const OWNER_MIGRATIONS = [
  {
    name: '0001_owner_vault_initial.sql',
    sha256: 'bb7026540d8cb4516a9091eee0ea6b7a4618534a25b124f95a1aa32a9b84cce7',
  },
  {
    name: '0002_owner_key_wrap_operations.sql',
    sha256: 'd07bf3272960421a4d0516050508e5d5d8c97cf01b0e240884907dcd37344e2b',
  },
  {
    name: '0003_enrollment_waitlist.sql',
    sha256: '769f3cd22812ac3436656115074d0f9371eb6c3b91a19c376ebc21b337450b07',
  },
  {
    name: '0004_identity_age_requests.sql',
    sha256: '2eb1455067507ebe6bfc007a9ab2330b101522a7417729b2edf793f806b892b6',
  },
  {
    name: '0005_login_connection_review.sql',
    sha256: '679c00ff7ec7c0ec2693fbd145b17f358cb7eb973aaddae9b56797f670b6ef89',
  },
  {
    name: '0006_owner_login_wrap.sql',
    sha256: '5a991fbb3c7b7c531d52dba6ec00f8b635b852f8e504b3074fa5ba06bc6e5b6f',
  },
] as const;

export function assertProductionOwnerSchema(
  migrations: { name: string; sql: string }[],
  ledger: { name: string }[],
  schema: SchemaRow[],
  work?: { migrations: SqlMigration[]; ledger: WorkLedgerRow[]; adoptionFence?: boolean },
  messaging?: MessagingSchema,
) {
  const names = OWNER_MIGRATIONS.map(({ name }) => name);
  assert.deepEqual(
    migrations.map(({ name }) => name),
    names,
    'Unexpected owner migration files',
  );
  assert.deepEqual(
    ledger.map(({ name }) => name),
    names,
    'Production owner migration ledger differs',
  );
  const db = new DatabaseSync(':memory:');
  try {
    db.exec('PRAGMA foreign_keys=ON');
    for (const [index, migration] of migrations.entries()) {
      assert.equal(
        createHash('sha256').update(migration.sql).digest('hex'),
        OWNER_MIGRATIONS[index]!.sha256,
        'Owner migration bytes differ',
      );
      db.exec(migration.sql);
    }
    if (work) {
      assertWorkMigrationFiles(work.migrations);
      assertWorkLedger(work.ledger);
      db.exec(WORK_LEDGER_SQL);
      for (const migration of work.migrations) db.exec(migration.sql);
      if (work.adoptionFence)
        for (const fence of workAdoptionFences(
          db.prepare(BASELINE_SCHEMA_QUERY).all() as SchemaRow[],
        ))
          db.exec(fence.create);
    }
    if (messaging) {
      assert.ok(!work?.adoptionFence, 'Finish Work adoption before Chat schema changes');
      assertMessagingMigrationFiles(messaging.migrations);
      assertMessagingLedger(messaging.ledger, messaging.allowPartial);
      db.exec(MESSAGING_LEDGER_SQL);
      for (const migration of messaging.migrations.slice(0, messaging.ledger.length))
        db.exec(migration.sql);
    }
    assert.deepEqual(
      db.prepare('PRAGMA foreign_key_check').all(),
      [],
      'Owner schema foreign keys failed',
    );
    assert.deepEqual(
      canonicalSchema(schema),
      canonicalSchema(db.prepare(BASELINE_SCHEMA_QUERY).all() as SchemaRow[]),
      'Production owner schema differs from reviewed migrations',
    );
  } finally {
    db.close();
  }
}
