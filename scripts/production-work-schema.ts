/** Separate, byte-pinned additive ledger. Never part of the Owner Wrangler chain. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

export const WORK_MIGRATIONS = [
  {
    name: '0003_work_delegation.sql',
    sha256: '56118b6c9f1cf2670c72b1b4a3f1ee7de4fa00f25c380421436ab1e234725ffc',
  },
  {
    name: '0004_work_disclosure_budget.sql',
    sha256: '0c188f58cd5db7653044006d62dd53d81f76e15e5f030a06262111e53d6dd6d4',
  },
  {
    name: '0005_work_sources.sql',
    sha256: '5002f632dea0a46b381a7aaff959f2f38a14544ca24b476a1236a116c4a45e38',
  },
  {
    name: '0006_work_registered_disclosures.sql',
    sha256: '9528bb5fda6c52d6f4c068620a0ba529ab1fdd17e9621f41d1478242770aa908',
  },
  {
    name: '0007_work_preparation_intents.sql',
    sha256: '933de6fb79738763175083c8c25a2d2634ac720e2616d615bbb2e70bc4e6fe3f',
  },
  {
    name: '0008_work_prepared_authority.sql',
    sha256: '5a31651d893f6dc4e5ead6208208ec87978ea4e1a4d37037703d4d0b2f879be0',
  },
  {
    name: '0009_work_credential_custody.sql',
    sha256: 'b8a5d5a9012b414ea911425e5b6bf1ffc68bf4c87c3e642fcf11eff6eb548f9f',
  },
  {
    name: '0010_work_candidate_payload.sql',
    sha256: 'd25f923f5f1d9d5a2d28d0f9b426e5878b5b7132523358dfb2320a075802d347',
  },
  {
    name: '0011_work_authority_checkpoint.sql',
    sha256: 'abe85e95e436848f299c533667b2fb70fd24fcb6d5f12e941dcce2cad266bb2c',
  },
  {
    name: '0012_op_authority_frames.sql',
    sha256: 'b40db25473beafee999a22c81a1bbb82c1fa93ac4c48d4a5cfd14cd43efc9c2d',
  },
  {
    name: '0013_work_copy_consent.sql',
    sha256: '52ae231fa2ae9bec78e8c75a41e62b1cce6dc7b4b3b364218914453c9d48d4f4',
  },
  {
    name: '0014_work_copy_job.sql',
    sha256: '0500e537b0ec8aab2f483298ed3734c16a90db643c001e108f342d0a8a882da6',
  },
] as const;

export const WORK_LEDGER_SQL = `CREATE TABLE work_schema_migrations (
 id INTEGER PRIMARY KEY NOT NULL CHECK(id BETWEEN 1 AND 12),
 name TEXT NOT NULL UNIQUE,
 sha256 TEXT NOT NULL CHECK(length(sha256)=64 AND sha256 NOT GLOB '*[^a-f0-9]*')
) STRICT`;
export type WorkLedgerRow = { id: number; name: string; sha256: string };
export type SqlMigration = { name: string; sql: string };
export const workLedger = (): WorkLedgerRow[] =>
  WORK_MIGRATIONS.map(({ name, sha256 }, index) => ({ id: index + 1, name, sha256 }));

export function assertWorkMigrationFiles(migrations: SqlMigration[]) {
  assert.deepEqual(
    migrations.map(({ name }) => name),
    WORK_MIGRATIONS.map(({ name }) => name),
    'Unexpected Work migration files',
  );
  for (const [index, migration] of migrations.entries())
    assert.equal(
      createHash('sha256').update(migration.sql).digest('hex'),
      WORK_MIGRATIONS[index]!.sha256,
      'Work migration bytes differ',
    );
}

export function assertWorkLedger(ledger: WorkLedgerRow[]) {
  assert.deepEqual(ledger, workLedger(), 'Production Work migration ledger differs');
}
