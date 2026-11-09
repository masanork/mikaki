/** Read-only schema audit for the exact #336 Owner migration prefixes. */
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { BASELINE_SCHEMA_QUERY, canonicalSchema } from './production-baseline.ts';
import { OWNER_MIGRATIONS } from './production-owner-schema.ts';
import {
  WORK_LEDGER_SQL,
  WORK_MIGRATIONS,
  assertWorkLedger,
  assertWorkMigrationFiles,
} from './production-work-schema.ts';
import {
  MESSAGING_LEDGER_SQL,
  MESSAGING_MIGRATIONS,
  assertMessagingLedger,
  assertMessagingMigrationFiles,
} from './production-messaging-schema.ts';
import { inspectProductionMessaging } from './production-messaging-audit.ts';

const upgrades = [
  {
    name: '0009_client_secret_rotation.sql',
    sha256: '09a1eda70e62c96188b194496f20218aead168825d7b0e5ad2e207fe2b19e875',
  },
  {
    name: '0010_verified_email.sql',
    sha256: '430e7cdb5d0f83c1078ec902f57000b79315551132f0a06de4cb0f52d0d3f4a1',
  },
];
const load = (root, dir, list) =>
  list.map(({ name, sha256 }) => {
    const sql = readFileSync(join(root, dir, name), 'utf8');
    assert.equal(
      createHash('sha256').update(sql).digest('hex'),
      sha256,
      `migration bytes differ: ${name}`,
    );
    return { name, sql };
  });
export async function auditBridgeSchema({ root, feature, stage, query }) {
  assert.ok([8, 9, 10].includes(stage), 'stage must be 8, 9 or 10');
  const base = load(root, 'crates/worker/migrations', OWNER_MIGRATIONS);
  const added = load(feature, 'scripts/fixtures/owner-email-migrations', upgrades);
  const owner = [...base, ...added.slice(0, stage - 8)];
  const work = load(root, 'crates/worker/work-migrations', WORK_MIGRATIONS);
  const messaging = load(root, 'crates/worker/messaging-migrations', MESSAGING_MIGRATIONS);
  assertWorkMigrationFiles(work);
  assertMessagingMigrationFiles(messaging);
  const expectedLedger = owner.map(({ name }, i) => ({ id: i + 1, name }));
  assert.deepEqual(
    await query('SELECT id,name FROM d1_migrations ORDER BY id'),
    expectedLedger,
    'Owner ledger differs',
  );
  assertWorkLedger(await query('SELECT id,name,sha256 FROM work_schema_migrations ORDER BY id'));
  assertMessagingLedger(await query('SELECT id,name FROM messaging_schema_migrations ORDER BY id'));
  const actual = await query(BASELINE_SCHEMA_QUERY);
  const chat = await inspectProductionMessaging(root, actual, query);
  assert.ok(chat, 'Messaging schema must be present');
  const db = new DatabaseSync(':memory:');
  try {
    db.exec('PRAGMA foreign_keys=ON');
    for (const migration of owner) db.exec(migration.sql);
    db.exec(WORK_LEDGER_SQL);
    for (const migration of work) db.exec(migration.sql);
    db.exec(MESSAGING_LEDGER_SQL);
    for (const migration of messaging) db.exec(migration.sql);
    assert.deepEqual(
      canonicalSchema(actual),
      canonicalSchema(db.prepare(BASELINE_SCHEMA_QUERY).all()),
      'Combined schema differs',
    );
    assert.deepEqual(await query('PRAGMA foreign_key_check'), [], 'Foreign keys failed');
    assert.deepEqual(
      await query('SELECT id,name FROM d1_migrations ORDER BY id'),
      expectedLedger,
      'Owner ledger changed during audit',
    );
    return {
      stage,
      owner_migrations: owner.length,
      work_migrations: work.length,
      messaging_migrations: messaging.length,
      schema_objects: actual.length,
      mutations: false,
    };
  } finally {
    db.close();
  }
}

export function assertProductionConfig(bytes) {
  assert.equal(
    createHash('sha256').update(bytes).digest('hex'),
    '9e09409199081c3165a3d3f21205f13f289dc0a5da62d3779cec9c3649612e1a',
    'Production target config differs',
  );
}

export function parseAuditArgs(args) {
  assert.equal(args.length, 3, 'Expected --remote --stage 8|9|10');
  assert.equal(args[0], '--remote', 'Expected --remote');
  assert.equal(args[1], '--stage', 'Expected --stage');
  assert.ok(['8', '9', '10'].includes(args[2]), 'Stage must be 8, 9 or 10');
  return Number(args[2]);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const stage = parseAuditArgs(process.argv.slice(2));
  const root = process.cwd(),
    feature = root;
  assertProductionConfig(readFileSync(join(root, 'crates/worker/wrangler.production.jsonc')));
  const query = async (sql) => {
    const output = execFileSync(
      join(root, 'node_modules/.bin/wrangler'),
      [
        'd1',
        'execute',
        'DB',
        '--remote',
        '--config',
        'crates/worker/wrangler.production.jsonc',
        '--command',
        sql,
        '--json',
      ],
      { cwd: root, encoding: 'utf8', maxBuffer: 4 * 1024 * 1024 },
    );
    const result = JSON.parse(output);
    assert.equal(result.length, 1);
    assert.equal(result[0].success, true);
    return result[0].results;
  };
  console.log(JSON.stringify(await auditBridgeSchema({ root, feature, stage, query })));
}
