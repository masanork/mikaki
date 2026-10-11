/** Existing OP data is captured, never reset or backfilled as Work authority. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import type { D1Database } from '@cloudflare/workers-types';
import {
  validateBootstrapPlan,
  type BootstrapPlan,
} from '../crates/work-checkpoint-worker/bootstrap.ts';
import { assertProductionOwnerSchema, OWNER_MIGRATIONS } from './production-owner-schema.ts';
import type { SqlMigration, WorkLedgerRow } from './production-work-schema.ts';
import {
  BOOTSTRAP_SCHEMA_QUERY,
  bootstrapRow,
  quiescentPrimaryStore,
  type PrimarySnapshot,
  type BootstrapRow,
  inspectBootstrapForScope,
  type BootstrapIO,
} from './work-authority-bootstrap.ts';
import type { SchemaRow } from './production-baseline.ts';
import { workAdoptionFences } from './production-work-fence.ts';

export const PRODUCTION_WORK_TARGET = {
  account: '4b749427a0c80c547e726a42aff4b6fc',
  database: 'd0258938-0d27-4110-8aa9-c82e20f3885b',
  authority: 'mikaki-auth-work-v1',
  checkpoint: 'mikaki-auth-work-checkpoint',
} as const;
const identifier = (value: string) => {
  assert.match(value, /^[a-zA-Z_][a-zA-Z_0-9]*$/, 'production_work_identifier_denied');
  return `"${value}"`;
};
const sorted = (rows: BootstrapRow[]) =>
  rows
    .map((row) =>
      JSON.stringify(
        Object.fromEntries(Object.entries(row).sort(([a], [b]) => a.localeCompare(b))),
      ),
    )
    .sort();

/** At most 64 rows per application table and 1 MiB total; larger targets refuse. */
export async function captureProductionWorkSnapshot(
  DB: D1Database,
  owner: SqlMigration[],
  work: SqlMigration[],
  options: { fenced?: boolean } = {},
): Promise<PrimarySnapshot> {
  return captureProductionSnapshot(DB, owner, work, options);
}

/** Size/shape preflight before closing production writers, with no Work schema required. */
export async function captureProductionOwnerSnapshot(DB: D1Database, owner: SqlMigration[]) {
  return captureProductionSnapshot(DB, owner);
}
async function captureProductionSnapshot(
  DB: D1Database,
  owner: SqlMigration[],
  work?: SqlMigration[],
  options: { fenced?: boolean } = {},
): Promise<PrimarySnapshot> {
  const schema = (await DB.prepare(BOOTSTRAP_SCHEMA_QUERY).all<SchemaRow>()).results;
  const ledger = (
    await DB.prepare('SELECT name FROM d1_migrations ORDER BY id').all<{ name: string }>()
  ).results;
  const workRows = work
    ? (
        await DB.prepare(
          'SELECT id,name,sha256 FROM work_schema_migrations ORDER BY id',
        ).all<WorkLedgerRow>()
      ).results
    : undefined;
  assertProductionOwnerSchema(
    owner,
    ledger,
    schema,
    work
      ? {
          migrations: work,
          ledger: workRows!,
          adoptionFence: options.fenced,
        }
      : undefined,
  );
  assert.equal(
    (await DB.prepare('PRAGMA foreign_key_check').all()).results.length,
    0,
    'production_work_foreign_keys',
  );
  const tables: PrimarySnapshot['tables'] = [];
  let bytes = Buffer.byteLength(JSON.stringify({ schema, migrations: ledger }));
  for (const { name, type } of schema) {
    if (type !== 'table') continue;
    // Bound value download before reading rows; control characters can expand
    // sixfold in JSON, and BLOBs are represented by hexadecimal text.
    const columns = (
      await DB.prepare(`PRAGMA table_info(${identifier(name)})`).all<{ name: string }>()
    ).results;
    assert.ok(columns.length > 0 && columns.length <= 100, 'production_work_columns_denied');
    const terms = columns.map(
      ({ name }) =>
        `(coalesce(length(CAST(${identifier(name)} AS BLOB)),0)*6+${name.length * 6 + 20})`,
    );
    const size = await DB.prepare(
      `SELECT count(*) AS n,coalesce(sum(bytes),0) AS bytes FROM
      (SELECT ${terms.join(' + ')} AS bytes FROM ${identifier(name)} LIMIT 65)`,
    ).first<{ n: number; bytes: number }>();
    assert.ok(size && size.n <= 64, 'production_work_snapshot_row_bound');
    assert.ok(size.bytes + bytes < 1_000_000, 'production_work_snapshot_byte_bound');
    const rows = (
      await DB.prepare(`SELECT * FROM ${identifier(name)} LIMIT 65`).all<Record<string, unknown>>()
    ).results.map(bootstrapRow);
    assert.ok(rows.length <= 64, 'production_work_snapshot_row_bound');
    assert.equal(
      new Set(sorted(rows)).size,
      rows.length,
      'production_work_snapshot_ambiguous_rows',
    );
    if (name === 'work_authority_checkpoint')
      assert.equal(rows.length, 0, 'production_work_already_enrolled');
    tables.push({ name, rows });
    bytes += Buffer.byteLength(JSON.stringify({ name, rows }));
    assert.ok(bytes < 1_000_000, 'production_work_snapshot_byte_bound');
  }
  const snapshot = { schema, tables, migrations: ledger.map(({ name }) => name) };
  assert.ok(
    Buffer.byteLength(JSON.stringify(snapshot)) < 1_000_000,
    'production_work_snapshot_byte_bound',
  );
  return snapshot;
}

/** Bind the initial tip to the entire reviewed snapshot, including typed BLOBs. */
export function productionWorkInitialTip(snapshot: PrimarySnapshot) {
  return createHash('sha256').update(JSON.stringify(snapshot)).digest('hex');
}

export function validateProductionBootstrapPlan(
  value: unknown,
  snapshot: PrimarySnapshot,
): asserts value is BootstrapPlan {
  validateBootstrapPlan(value);
  assert.equal(value.account_id, PRODUCTION_WORK_TARGET.account, 'production_work_account_denied');
  assert.equal(
    value.database_id,
    PRODUCTION_WORK_TARGET.database,
    'production_work_database_denied',
  );
  assert.equal(
    value.initial.authority,
    PRODUCTION_WORK_TARGET.authority,
    'production_work_scope_denied',
  );
  assert.equal(
    value.initial.tip,
    productionWorkInitialTip(snapshot),
    'production_work_snapshot_denied',
  );
  assert.notEqual(value.checkpoint_namespace_id, '0'.repeat(32), 'production_work_unallocated');
  assert.notEqual(value.checkpoint_object_id, '0'.repeat(64), 'production_work_unallocated');
  assert.notEqual(
    value.checkpoint_version_id,
    '00000000-0000-0000-0000-000000000000',
    'production_work_unallocated',
  );
  assert.deepEqual(
    snapshot.migrations,
    OWNER_MIGRATIONS.map(({ name }) => name),
    'production_work_owner_ledger_denied',
  );
}

/** Operator policy is separate; populated enrollment still requires verified quiescence. */
export function productionBootstrapStore(
  DB: D1Database,
  snapshot: PrimarySnapshot,
  owner: SqlMigration[],
  work: SqlMigration[],
  options: { fenced?: boolean } = {},
) {
  const expected = structuredClone(snapshot);
  const ledger = expected.tables.find(({ name }) => name === 'work_schema_migrations')?.rows;
  assert.ok(ledger, 'production_work_ledger_missing');
  assertProductionOwnerSchema(
    owner,
    expected.migrations.map((name) => ({ name })),
    expected.schema,
    { migrations: work, ledger: ledger as WorkLedgerRow[], adoptionFence: options.fenced },
  );
  assert.deepEqual(
    expected.tables.map(({ name }) => name),
    expected.schema.filter(({ type }) => type === 'table').map(({ name }) => name),
    'production_work_snapshot_tables_denied',
  );
  assert.equal(
    expected.tables.find(({ name }) => name === 'work_authority_checkpoint')?.rows.length,
    0,
    'production_work_already_enrolled',
  );
  assert.ok(
    expected.tables.every(({ rows }) => rows.length <= 64),
    'production_work_snapshot_row_bound',
  );
  assert.ok(
    Buffer.byteLength(JSON.stringify(expected)) < 1_000_000,
    'production_work_snapshot_byte_bound',
  );
  const validate = (value: unknown): asserts value is BootstrapPlan =>
    validateProductionBootstrapPlan(value, expected);
  return quiescentPrimaryStore(DB, expected, validate);
}

/** Open the same fenced primary only after an acknowledged matching initial enrollment. */
export async function releaseProductionWorkFence(
  DB: D1Database,
  snapshot: PrimarySnapshot,
  plan: BootstrapPlan,
  owner: SqlMigration[],
  work: SqlMigration[],
  checkpoint: BootstrapIO['checkpoint'],
) {
  const store = productionBootstrapStore(DB, snapshot, owner, work, { fenced: true });
  const validate = (value: unknown): asserts value is BootstrapPlan =>
    validateProductionBootstrapPlan(value, snapshot);
  const matched = await inspectBootstrapForScope(plan, { checkpoint, primary: store }, validate);
  assert.ok(matched.matching_initial, 'production_work_fence_checkpoint_not_matched');
  const observed = await store.inspect(plan);
  assert.ok(observed.initial_only && observed.marker, 'production_work_fence_not_enrolled');
  assert.deepEqual(observed.marker, plan.initial, 'production_work_fence_marker_changed');
  const schemaQuery = BOOTSTRAP_SCHEMA_QUERY.replace(/ ORDER BY type,name$/, '');
  const expected =
    "SELECT json_extract(value,'$.type'),json_extract(value,'$.name'),json_extract(value,'$.tbl_name'),json_extract(value,'$.sql') FROM json_each(?1)";
  // The initial marker is rechecked inside the same transaction as all trigger drops.
  const guard = `INSERT INTO atomic_guard(operation_id,passed) VALUES('production-work-fence-open-v1',CASE WHEN
    NOT EXISTS(${schemaQuery} EXCEPT ${expected}) AND NOT EXISTS(${expected} EXCEPT ${schemaQuery})
    AND EXISTS(SELECT 1 FROM work_authority_checkpoint WHERE authority=?2 AND epoch=?3 AND sequence=0 AND tip=?4)
    THEN 1 ELSE 0 END)`;
  await DB.batch([
    DB.prepare(guard).bind(
      JSON.stringify(snapshot.schema),
      plan.initial.authority,
      plan.initial.epoch,
      plan.initial.tip,
    ),
    ...workAdoptionFences(snapshot.schema).map(({ drop }) => DB.prepare(drop)),
    DB.prepare("DELETE FROM atomic_guard WHERE operation_id='production-work-fence-open-v1'"),
  ]);
}
