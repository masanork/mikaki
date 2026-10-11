/** Bounded quiescent enrollment. No remote allocator or automatic recovery/replay. */
import assert from 'node:assert/strict';
import { constants } from 'node:fs';
import { open, readdir, realpath } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { isDeepStrictEqual } from 'node:util';
import type { D1Database } from '@cloudflare/workers-types';
import {
  validateBootstrapPlan,
  bootstrapClosed,
  bootstrapHex,
} from '../crates/work-checkpoint-worker/bootstrap.ts';
import type {
  BootstrapPlan,
  BootstrapInspection,
} from '../crates/work-checkpoint-worker/bootstrap.ts';
import { BASELINE_SCHEMA_QUERY, canonicalSchema } from './production-baseline.ts';
import type { SchemaRow } from './production-baseline.ts';
import {
  AUTHORITY_ACCOUNT,
  AUTHORITY_TARGET,
  authoritySchema,
  packetFile,
  digest,
} from './work-authority-packet.ts';

export type BootstrapRow = Record<string, string | number | null | { blob_hex: string }>;
type Row = BootstrapRow;
// The pinned D1 runtime supplies this additional private metadata table.
// Exclude only known runtime objects, never arbitrary _cf_* application objects.
export const BOOTSTRAP_SCHEMA_QUERY = BASELINE_SCHEMA_QUERY.replace(
  'ORDER BY type,name',
  "AND name != '_cf_METADATA' AND tbl_name != '_cf_METADATA' ORDER BY type,name",
);
export type PrimarySnapshot = {
  schema: SchemaRow[];
  tables: { name: string; rows: Row[] }[];
  migrations: string[];
};
type Marker = { authority: string; epoch: string; sequence: number; tip: string };
export type PrimaryInspection = {
  marker: Marker | null;
  pristine: boolean;
  initial_only: boolean;
};
export function validateIsolatedBootstrapPlan(v: unknown): asserts v is BootstrapPlan {
  validateBootstrapPlan(v);
  assert.equal(v.account_id, AUTHORITY_ACCOUNT, 'authority_bootstrap_account_denied');
  assert.equal(v.initial.authority, AUTHORITY_TARGET.authority, 'authority_bootstrap_scope_denied');
  assert.notEqual(
    v.database_id,
    'd0258938-0d27-4110-8aa9-c82e20f3885b',
    'authority_bootstrap_production_denied',
  );
  assert.notEqual(
    v.database_id,
    '00000000-0000-0000-0000-000000000000',
    'authority_bootstrap_unallocated',
  );
  assert.notEqual(v.checkpoint_namespace_id, '0'.repeat(32), 'authority_bootstrap_unallocated');
  assert.notEqual(
    v.checkpoint_version_id,
    '00000000-0000-0000-0000-000000000000',
    'authority_bootstrap_unallocated',
  );
}
const quote = (name: string) => {
  assert.match(name, /^[a-zA-Z_][a-zA-Z_0-9]*$/, 'authority_bootstrap_schema_identifier_denied');
  return `"${name}"`;
};
const sortedRows = (rows: Row[]) =>
  rows
    .map((row) =>
      JSON.stringify(
        Object.fromEntries(Object.entries(row).sort(([a], [b]) => a.localeCompare(b))),
      ),
    )
    .sort();
const same = isDeepStrictEqual;
/** D1 projects BLOBs as byte arrays; keep their storage type distinct from text. */
export function bootstrapRow(row: Record<string, unknown>): Row {
  return Object.fromEntries(
    Object.entries(row).map(([name, value]) => {
      if (Array.isArray(value) || value instanceof Uint8Array) {
        assert.ok(
          Array.from(value).every((v) => Number.isInteger(v) && v >= 0 && v <= 255),
          'authority_bootstrap_blob_invalid',
        );
        return [name, { blob_hex: Buffer.from(value).toString('hex').toUpperCase() }];
      }
      assert.ok(
        value === null ||
          typeof value === 'string' ||
          (typeof value === 'number' &&
            Number.isFinite(value) &&
            (!Number.isInteger(value) || Number.isSafeInteger(value))),
        'authority_bootstrap_value_invalid',
      );
      return [name, value];
    }),
  );
}
// D1 limits expression depth to 100. A flat AND chain is left-deep in SQLite.
function conjunction(parts: string[]): string {
  if (parts.length === 1) return parts[0]!;
  const middle = Math.floor(parts.length / 2);
  return `(${conjunction(parts.slice(0, middle))} AND ${conjunction(parts.slice(middle))})`;
}

function primaryInsertQuery(expected: PrimarySnapshot) {
  const schemaQuery = BOOTSTRAP_SCHEMA_QUERY.replace(/ ORDER BY type,name$/, '');
  const observedSchema =
    "SELECT json_extract(value,'$.type'),json_extract(value,'$.name'),json_extract(value,'$.tbl_name'),json_extract(value,'$.sql') FROM json_each(?5,'$.schema')";
  const conditions = [
    `NOT EXISTS(${schemaQuery} EXCEPT ${observedSchema})`,
    `NOT EXISTS(${observedSchema} EXCEPT ${schemaQuery})`,
    `(SELECT json_group_array(name) FROM (SELECT name FROM d1_migrations ORDER BY id)) IS json_extract(?5,'$.migrations')`,
  ];
  for (const [index, table] of expected.tables.entries()) {
    conditions.push(`(SELECT count(*) FROM ${quote(table.name)})=${table.rows.length}`);
    // All fields participate; IS preserves NULL and hex retains BLOB storage type.
    for (const [rowIndex, row] of table.rows.entries())
      conditions.push(
        `EXISTS(SELECT 1 FROM ${quote(table.name)} WHERE ${Object.keys(row)
          .map((column) =>
            typeof row[column] === 'object' && row[column] !== null
              ? `(typeof(${quote(column)})='blob' AND hex(${quote(column)}) IS json_extract(?5,'$.tables[${index}].rows[${rowIndex}].${column}.blob_hex'))`
              : `${quote(column)} IS json_extract(?5,'$.tables[${index}].rows[${rowIndex}].${column}')`,
          )
          .join(' AND ')})`,
      );
  }
  const sql = `INSERT INTO work_authority_checkpoint(id,authority,epoch,sequence,tip) SELECT 1,?1,?2,?3,?4 WHERE ${conjunction(conditions)}`;
  assert.ok(
    Buffer.byteLength(sql) < 100_000 && Buffer.byteLength(JSON.stringify(expected)) < 1_000_000,
    'authority_bootstrap_query_too_large',
  );
  return sql;
}

/** Derive all initial seed values from the frozen SQL, never from operator-supplied SQL. */
export async function primaryBootstrapSnapshot(migrations: string): Promise<PrimarySnapshot> {
  await authoritySchema(migrations);
  const names = (await readdir(migrations)).sort();
  const db = new DatabaseSync(':memory:');
  try {
    db.exec('PRAGMA foreign_keys=ON');
    for (const name of names) db.exec((await packetFile(join(migrations, name))).toString('utf8'));
    const schema = db.prepare(BOOTSTRAP_SCHEMA_QUERY).all() as SchemaRow[];
    const tables = schema
      .filter((r) => r.type === 'table')
      .map(({ name }) => ({
        name,
        rows: db
          .prepare(`SELECT * FROM ${quote(name)}`)
          .all()
          .map(bootstrapRow),
      }));
    assert.ok(tables.every((t) => t.rows.length <= 16));
    return { schema, tables, migrations: names };
  } finally {
    db.close();
  }
}

/** Exact ledger/schema/seed checks. The insertion repeats guards atomically in D1. */
export function primaryBootstrapStore(DB: D1Database, expected: PrimarySnapshot) {
  return quiescentPrimaryStore(DB, expected, validateIsolatedBootstrapPlan);
}

/** Shared SQL guard; callers must supply a closed, fixed-target scope validator. */
export function quiescentPrimaryStore(
  DB: D1Database,
  expected: PrimarySnapshot,
  validatePlan: (value: unknown) => asserts value is BootstrapPlan,
) {
  // Refuse oversized guards before the independent enrollment can be attempted.
  const sql = primaryInsertQuery(expected);
  let schemaObservation: SchemaRow[] | null = null;
  let attempted = false;
  async function inspect(plan: BootstrapPlan): Promise<PrimaryInspection> {
    validatePlan(plan);
    const schema = (await DB.prepare(BOOTSTRAP_SCHEMA_QUERY).all<SchemaRow>()).results;
    assert.deepEqual(
      canonicalSchema(schema),
      canonicalSchema(expected.schema),
      'authority_bootstrap_schema_mismatch',
    );
    const names = (
      await DB.prepare('SELECT name FROM d1_migrations ORDER BY id').all<{ name: string }>()
    ).results;
    assert.deepEqual(
      names.map((r) => r.name),
      expected.migrations,
      'authority_bootstrap_migrations_mismatch',
    );
    assert.equal(
      (await DB.prepare('PRAGMA foreign_key_check').all()).results.length,
      0,
      'authority_bootstrap_foreign_keys',
    );
    let pristine = true;
    let initialOnly = true;
    let marker: Marker | null = null;
    // Bounded reads: one more than the known seed count detects populated targets.
    for (const table of expected.tables) {
      const rows = (
        await DB.prepare(
          `SELECT * FROM ${quote(table.name)} LIMIT ${table.rows.length + 2}`,
        ).all<Row>()
      ).results.map(bootstrapRow);
      if (table.name === 'work_authority_checkpoint') {
        assert.ok(rows.length <= 1, 'authority_bootstrap_marker_invalid');
        if (rows.length) {
          const { id, ...observed } = rows[0]!;
          assert.equal(id, 1);
          assert.ok(bootstrapClosed(observed, ['authority', 'epoch', 'sequence', 'tip']));
          assert.ok(
            typeof observed.authority === 'string' &&
              bootstrapHex(observed.epoch) &&
              bootstrapHex(observed.tip),
          );
          assert.ok(Number.isSafeInteger(observed.sequence) && Number(observed.sequence) >= 0);
          marker = observed as Marker;
          pristine = false;
          initialOnly &&= same(marker, plan.initial);
        }
      } else if (!same(sortedRows(rows), sortedRows(table.rows))) {
        pristine = false;
        initialOnly = false;
      }
    }
    schemaObservation = pristine ? schema : null;
    return { marker, pristine, initial_only: initialOnly && marker !== null };
  }
  async function insert(plan: BootstrapPlan) {
    validatePlan(plan);
    assert.ok(schemaObservation && !attempted, 'authority_bootstrap_primary_not_admitted');
    attempted = true; // Consumption precedes the SQL call, including a lost reply.
    const snapshot = JSON.stringify({
      schema: schemaObservation,
      tables: expected.tables,
      migrations: expected.migrations,
    });
    assert.ok(Buffer.byteLength(snapshot) < 1_000_000, 'authority_bootstrap_query_too_large');
    const guard = `bootstrap:${digest(Buffer.from(JSON.stringify(plan))).sha256}`;
    await DB.batch([
      DB.prepare(sql).bind(
        plan.initial.authority,
        plan.initial.epoch,
        0,
        plan.initial.tip,
        snapshot,
      ),
      DB.prepare(
        'INSERT INTO atomic_guard(operation_id,passed) VALUES(?,CASE WHEN changes()=1 THEN 1 ELSE 0 END)',
      ).bind(guard),
      DB.prepare('DELETE FROM atomic_guard WHERE operation_id=?').bind(guard),
    ]);
  }
  return { inspect, insert };
}

export type BootstrapIO = {
  checkpoint: { inspect(): Promise<unknown>; enroll(plan: BootstrapPlan): Promise<unknown> };
  primary: {
    inspect(plan: BootstrapPlan): Promise<PrimaryInspection>;
    insert(plan: BootstrapPlan): Promise<void>;
  };
  /** Must persist and sync each event before resolving. */
  record(event: Record<string, unknown>): Promise<void>;
};
/** Detach bounded JSON data and release RPC result/pipeline ownership explicitly. */
export async function bootstrapRpcData(rpc: Promise<unknown>) {
  let value: unknown;
  const dispose = (object: unknown) => {
    if (object && typeof object === 'object')
      (object as { [Symbol.dispose]?: () => void })[Symbol.dispose]?.();
  };
  try {
    value = await rpc;
    if (typeof value === 'string') {
      assert.ok(Buffer.byteLength(value) <= 8192, 'authority_bootstrap_rpc_too_large');
      return JSON.parse(value) as unknown;
    }
    if (value === null || typeof value !== 'object') return value;
    const json = JSON.stringify(value);
    assert.ok(Buffer.byteLength(json) <= 8192, 'authority_bootstrap_rpc_too_large');
    return JSON.parse(json) as unknown;
  } finally {
    dispose(value);
    dispose(rpc);
  }
}
function inspection(value: unknown, plan: BootstrapPlan): BootstrapInspection {
  assert.ok(
    bootstrapClosed(value, ['authority', 'object_id', 'enrollment', 'state', 'ledger_entries']),
    'authority_bootstrap_inspection_invalid',
  );
  assert.equal(value.authority, plan.initial.authority, 'authority_bootstrap_scope_mismatch');
  assert.equal(value.object_id, plan.checkpoint_object_id, 'authority_bootstrap_object_mismatch');
  assert.ok(Number.isSafeInteger(value.ledger_entries) && Number(value.ledger_entries) >= 0);
  if (value.enrollment !== null) validateBootstrapPlan(value.enrollment);
  if (value.state !== null) {
    assert.ok(
      bootstrapClosed(value.state, ['checkpoint', 'pending', 'last', 'release_floor', 'frozen']),
    );
    assert.ok(bootstrapClosed(value.state.checkpoint, ['authority', 'epoch', 'sequence', 'tip']));
    assert.ok(
      typeof value.state.frozen === 'boolean' && Number.isSafeInteger(value.state.release_floor),
    );
  }
  return value as BootstrapInspection;
}
function initialized(value: BootstrapInspection, plan: BootstrapPlan) {
  return (
    same(value.enrollment, plan) &&
    value.ledger_entries === 0 &&
    value.state !== null &&
    same(value.state.checkpoint, plan.initial) &&
    value.state.pending === null &&
    value.state.last === null &&
    value.state.release_floor === 1 &&
    value.state.frozen === false
  );
}
/** Read-only reconciliation reports facts; it never resumes either write. */
export async function inspectBootstrap(
  plan: BootstrapPlan,
  io: Pick<BootstrapIO, 'checkpoint' | 'primary'>,
) {
  validateIsolatedBootstrapPlan(plan);
  const cp = inspection(await bootstrapRpcData(io.checkpoint.inspect()), plan);
  const primary = await io.primary.inspect(plan);
  return {
    checkpoint: cp,
    primary,
    matching_initial:
      initialized(cp, plan) && primary.initial_only && same(primary.marker, plan.initial),
  };
}
/** Fresh one-shot sequence. Caller must own one exclusive journal tied to this plan. */
export async function bootstrapAuthority(plan: BootstrapPlan, io: BootstrapIO) {
  validateIsolatedBootstrapPlan(plan);
  let phase = 'preflight';
  await io.record({ event: 'selected', plan });
  try {
    const before = await inspectBootstrap(plan, io);
    assert.ok(
      before.checkpoint.enrollment === null &&
        before.checkpoint.state === null &&
        before.checkpoint.ledger_entries === 0 &&
        before.primary.pristine,
      'authority_bootstrap_not_pristine',
    );
    await io.record({
      event: 'preflight',
      outcome: 'pristine',
      object_id: before.checkpoint.object_id,
    });
    phase = 'checkpoint-write-unknown';
    await io.record({ event: 'checkpoint-intent' });
    const ack = inspection(await bootstrapRpcData(io.checkpoint.enroll(plan)), plan);
    assert.ok(initialized(ack, plan), 'authority_bootstrap_checkpoint_ack_invalid');
    await io.record({ event: 'checkpoint-acknowledged' });
    const between = await inspectBootstrap(plan, io);
    assert.ok(
      initialized(between.checkpoint, plan) && between.primary.pristine,
      'authority_bootstrap_intermediate_mismatch',
    );
    phase = 'primary-write-unknown';
    await io.record({ event: 'primary-intent' });
    await io.primary.insert(plan);
    await io.record({ event: 'primary-acknowledged' });
    phase = 'verification-incomplete';
    const after = await inspectBootstrap(plan, io);
    assert.ok(after.matching_initial, 'authority_bootstrap_final_mismatch');
    await io.record({ event: 'complete', matching_initial: true, writers_enabled: false });
    return after;
  } catch {
    await io.record({
      event: 'stopped',
      outcome: phase,
      recovery: 'inspect-same-identities-no-write-replay',
    });
    throw new Error(`authority_bootstrap_${phase}`);
  }
}

/** Canonical child-packet journal. Existing/partial runs refuse before any RPC. */
export async function bootstrapAuthorityJournal(
  plan: BootstrapPlan,
  childDirectory: string,
  io: Omit<BootstrapIO, 'record'>,
) {
  validateIsolatedBootstrapPlan(plan);
  assert.equal(
    await realpath(childDirectory),
    resolve(childDirectory),
    'authority_bootstrap_symlink_denied',
  );
  const parent = await open(
    childDirectory,
    constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
  );
  let journal;
  try {
    journal = await open(join(childDirectory, 'bootstrap.jsonl'), 'wx', 0o600);
    await parent.sync();
    return await bootstrapAuthority(plan, {
      ...io,
      async record(event) {
        await journal!.writeFile(JSON.stringify(event) + '\n');
        await journal!.sync();
      },
    });
  } finally {
    await journal?.close();
    await parent.close();
  }
}

/** Private local operator connection only; this is not a deployed HTTP Worker. */
export function bootstrapOperatorConfig(plan: BootstrapPlan) {
  validateIsolatedBootstrapPlan(plan);
  return authorityBootstrapOperatorConfig(plan.database_id);
}

/** Prepare the private connection before deployed DO/version identities exist. */
export function authorityBootstrapOperatorConfig(databaseId: string) {
  assert.match(databaseId, /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/);
  assert.ok(
    !['d0258938-0d27-4110-8aa9-c82e20f3885b', '00000000-0000-0000-0000-000000000000'].includes(
      databaseId,
    ),
    'authority_bootstrap_database_denied',
  );
  return {
    name: 'mikaki-work-authority-local-bootstrap',
    account_id: AUTHORITY_ACCOUNT,
    // UTC runtime date; JST is already October 11. The pinned runtime rejects future dates.
    compatibility_date: '2026-10-10',
    workers_dev: false,
    preview_urls: false,
    d1_databases: [
      {
        binding: 'DB',
        database_name: AUTHORITY_TARGET.database,
        database_id: databaseId,
        remote: true,
      },
    ],
    services: [
      {
        binding: 'CHECKPOINT_BOOTSTRAP',
        service: AUTHORITY_TARGET.checkpoint,
        entrypoint: 'WorkCheckpointBootstrap',
        remote: true,
      },
    ],
  };
}
