/** Byte-pinned, additive D1 transaction. No allocation, reset, enrollment or replay. */
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { unstable_splitSqlQuery as splitSqlQuery } from 'wrangler';
import type { D1Database } from '@cloudflare/workers-types';
import { assertProductionOwnerSchema, OWNER_MIGRATIONS } from './production-owner-schema.ts';
import { BASELINE_SCHEMA_QUERY, type SchemaRow } from './production-baseline.ts';
import {
  assertWorkMigrationFiles,
  WORK_LEDGER_SQL,
  workLedger,
  type SqlMigration,
  type WorkLedgerRow,
} from './production-work-schema.ts';
import { workAdoptionFences } from './production-work-fence.ts';
import {
  BOOTSTRAP_SCHEMA_QUERY,
  bootstrapRow,
  type PrimarySnapshot,
} from './work-authority-bootstrap.ts';

/** Compile the exact post-migration shape before fencing the live database. */
export function previewProductionWorkSnapshot(
  before: PrimarySnapshot,
  owner: SqlMigration[],
  work: SqlMigration[],
): PrimarySnapshot {
  assertProductionOwnerSchema(
    owner,
    before.migrations.map((name) => ({ name })),
    before.schema,
  );
  assert.deepEqual(
    before.tables.map(({ name }) => name),
    before.schema.filter(({ type }) => type === 'table').map(({ name }) => name),
  );
  const { queries } = productionWorkMigrationQueries(owner, work);
  const db = new DatabaseSync(':memory:');
  try {
    for (const migration of owner) db.exec(migration.sql);
    for (const sql of queries) db.exec(sql);
    const schema = db.prepare(BOOTSTRAP_SCHEMA_QUERY).all() as SchemaRow[];
    return {
      schema,
      migrations: structuredClone(before.migrations),
      tables: schema
        .filter(({ type }) => type === 'table')
        .map(({ name }) => ({
          name,
          rows: structuredClone(
            before.tables.find((table) => table.name === name)?.rows ??
              db.prepare(`SELECT * FROM "${name}"`).all().map(bootstrapRow),
          ),
        })),
    };
  } finally {
    db.close();
  }
}

export function productionWorkMigrationQueries(owner: SqlMigration[], work: SqlMigration[]) {
  assertWorkMigrationFiles(work);
  const db = new DatabaseSync(':memory:');
  try {
    for (const migration of owner) db.exec(migration.sql);
    const before = db.prepare(BASELINE_SCHEMA_QUERY).all() as SchemaRow[];
    assertProductionOwnerSchema(
      owner,
      OWNER_MIGRATIONS.map(({ name }) => ({ name })),
      before,
    );
    db.exec(WORK_LEDGER_SQL);
    for (const migration of work) db.exec(migration.sql);
    const schema = db.prepare(BASELINE_SCHEMA_QUERY).all() as SchemaRow[];
    const fences = workAdoptionFences(schema);
    const queries = [
      WORK_LEDGER_SQL,
      ...work.flatMap(({ sql }) => splitSqlQuery(sql)),
      ...workLedger().map(
        ({ id, name, sha256 }) =>
          `INSERT INTO work_schema_migrations VALUES(${id},'${name}','${sha256}')`,
      ),
      ...fences.map(({ create }) => create),
    ];
    assert.ok(queries.length < 1000 && queries.every((sql) => Buffer.byteLength(sql) < 100_000));
    return { queries, fences };
  } finally {
    db.close();
  }
}

/** All accepted rollout states are exact; partial schema/fences are never accepted. */
export function assertProductionWorkRolloutSchema(
  owner: SqlMigration[],
  work: SqlMigration[],
  ledger: { name: string }[],
  schema: SchemaRow[],
  workRows: WorkLedgerRow[] | null,
) {
  if (workRows === null) {
    assertProductionOwnerSchema(owner, ledger, schema);
    return 'owner' as const;
  }
  const fenced = schema.some(({ name }) => name.startsWith('work_adoption_fence_'));
  assertProductionOwnerSchema(owner, ledger, schema, {
    migrations: work,
    ledger: workRows,
    adoptionFence: fenced,
  });
  return fenced ? ('work-fenced' as const) : ('work' as const);
}

export function productionWorkMigrationStore(
  DB: D1Database,
  owner: SqlMigration[],
  work: SqlMigration[],
) {
  const { queries } = productionWorkMigrationQueries(owner, work);
  let admission: { schema: SchemaRow[]; ledger: { name: string }[] } | null = null;
  let attempted = false;
  async function inspect() {
    const schema = (await DB.prepare(BOOTSTRAP_SCHEMA_QUERY).all<SchemaRow>()).results;
    const ledger = (
      await DB.prepare('SELECT name FROM d1_migrations ORDER BY id').all<{ name: string }>()
    ).results;
    const workRows = schema.some(({ name }) => name === 'work_schema_migrations')
      ? (
          await DB.prepare(
            'SELECT id,name,sha256 FROM work_schema_migrations ORDER BY id',
          ).all<WorkLedgerRow>()
        ).results
      : null;
    const phase = assertProductionWorkRolloutSchema(owner, work, ledger, schema, workRows);
    assert.equal((await DB.prepare('PRAGMA foreign_key_check').all()).results.length, 0);
    admission = phase === 'owner' && !attempted ? { schema, ledger } : null;
    return { phase };
  }
  /** Safety recovery before any checkpoint enrollment intent; caller records that fact durably. */
  async function openUnenrolledFence() {
    const phase = await inspect();
    assert.equal(phase.phase, 'work-fenced', 'Only the exact temporary fence can be opened');
    const schema = (await DB.prepare(BOOTSTRAP_SCHEMA_QUERY).all<SchemaRow>()).results;
    const observed =
      "SELECT json_extract(value,'$.type'),json_extract(value,'$.name'),json_extract(value,'$.tbl_name'),json_extract(value,'$.sql') FROM json_each(?1)";
    const schemaQuery = BOOTSTRAP_SCHEMA_QUERY.replace(/ ORDER BY type,name$/, '');
    await DB.batch([
      DB.prepare(
        `INSERT INTO atomic_guard(operation_id,passed) VALUES('production-work-unenrolled-open-v1',CASE WHEN
        NOT EXISTS(${schemaQuery} EXCEPT ${observed}) AND NOT EXISTS(${observed} EXCEPT ${schemaQuery})
        AND NOT EXISTS(SELECT 1 FROM work_authority_checkpoint) THEN 1 ELSE 0 END)`,
      ).bind(JSON.stringify(schema)),
      ...workAdoptionFences(schema).map(({ drop }) => DB.prepare(drop)),
      DB.prepare(
        "DELETE FROM atomic_guard WHERE operation_id='production-work-unenrolled-open-v1'",
      ),
    ]);
  }
  async function apply() {
    assert.ok(admission && !attempted, 'production_work_migration_not_admitted');
    attempted = true;
    const observed =
      "SELECT json_extract(value,'$.type'),json_extract(value,'$.name'),json_extract(value,'$.tbl_name'),json_extract(value,'$.sql') FROM json_each(?1)";
    const schemaQuery = BOOTSTRAP_SCHEMA_QUERY.replace(/ ORDER BY type,name$/, '');
    const guard = `INSERT INTO atomic_guard(operation_id,passed) VALUES('production-work-migration-v1',CASE WHEN
      NOT EXISTS(${schemaQuery} EXCEPT ${observed}) AND NOT EXISTS(${observed} EXCEPT ${schemaQuery})
      AND (SELECT json_group_array(name) FROM (SELECT name FROM d1_migrations ORDER BY id)) IS ?2
      THEN 1 ELSE 0 END)`;
    await DB.batch([
      DB.prepare(guard).bind(
        JSON.stringify(admission.schema),
        JSON.stringify(admission.ledger.map(({ name }) => name)),
      ),
      DB.prepare("DELETE FROM atomic_guard WHERE operation_id='production-work-migration-v1'"),
      ...queries.map((sql) => DB.prepare(sql)),
    ]);
  }
  return { inspect, apply, openUnenrolledFence };
}
