/** Exercise the installed Wrangler migration ledger and failure transaction on local D1 only. */
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { cpSync, mkdtempSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { checkProductionChatSchema } from './check-production-chat-schema.ts';
import { MESSAGING_MIGRATION_CONFIG, MESSAGING_MIGRATIONS } from './production-messaging-schema.ts';
import { BASELINE_SCHEMA_QUERY } from './production-baseline.ts';

const root = process.cwd();
const cli = resolve('node_modules/wrangler/bin/wrangler.js');
const ownerConfig = 'crates/worker/wrangler.production.jsonc';

function fixture() {
  const directory = mkdtempSync(join(tmpdir(), 'mikaki-chat-d1-'));
  const worker = join(directory, 'crates/worker');
  mkdirSync(worker, { recursive: true });
  for (const path of [
    ownerConfig,
    MESSAGING_MIGRATION_CONFIG,
    'crates/worker/migrations',
    'crates/worker/messaging-migrations',
  ])
    cpSync(path, join(directory, path), { recursive: true });
  const command = (operation: string[], config = MESSAGING_MIGRATION_CONFIG) =>
    execFileSync(
      process.execPath,
      [
        cli,
        'd1',
        ...operation,
        '--local',
        '--persist-to',
        join(directory, 'state'),
        '--config',
        join(directory, config),
      ],
      {
        cwd: directory,
        encoding: 'utf8',
        timeout: 60_000,
        maxBuffer: 4 * 1024 * 1024,
        stdio: ['ignore', 'pipe', 'pipe'],
        env: {
          ...process.env,
          CI: 'true',
          WRANGLER_SEND_METRICS: 'false',
          WRANGLER_LOG_PATH: join(directory, 'logs'),
        },
      },
    );
  const execute = (sql: string) =>
    JSON.parse(command(['execute', 'mikaki-auth-owner', '--command', sql, '--json']));
  const query = async (sql: string) => {
    const result = execute(sql);
    assert.equal(result.length, 1);
    assert.equal(result[0].success, true);
    return result[0].results;
  };
  try {
    command(['migrations', 'apply', 'mikaki-auth-owner'], ownerConfig);
    execute(
      "INSERT INTO account_security VALUES('existing-owner',3,1); INSERT INTO credential VALUES('existing-passkey','existing-owner',1)",
    );
    return {
      directory,
      command,
      execute,
      query,
      close: () => rmSync(directory, { recursive: true, force: true }),
    };
  } catch (error) {
    rmSync(directory, { recursive: true, force: true });
    throw error;
  }
}

test('real Wrangler applies Chat to its own ledger and preserves the Owner chain and passkey', async () => {
  const f = fixture();
  try {
    const before = await checkProductionChatSchema(root, f.query, true);
    assert.equal(before.applied, 0);
    const credentials = await f.query('SELECT * FROM credential');
    const ownerLedger = await f.query('SELECT * FROM d1_migrations ORDER BY id');
    f.command(['migrations', 'apply', 'mikaki-auth-owner']);
    const result = await checkProductionChatSchema(root, f.query, true);
    assert.equal(result.complete, true);
    assert.deepEqual(await f.query('SELECT * FROM credential'), credentials);
    assert.deepEqual(await f.query('SELECT * FROM d1_migrations ORDER BY id'), ownerLedger);
    assert.deepEqual(
      await f.query('SELECT name FROM messaging_schema_migrations ORDER BY id'),
      MESSAGING_MIGRATIONS.map(({ name }) => ({ name })),
    );
    assert.match(
      f.command(['migrations', 'list', 'mikaki-auth-owner'], ownerConfig),
      /No migrations to apply/,
    );
  } finally {
    f.close();
  }
});

test('real Wrangler refuses an existing second device and leaves failed migration DDL/ledger unapplied', async () => {
  const f = fixture();
  try {
    // First deploy only 0001, then restore the complete reviewed directory before preflight.
    const pending = MESSAGING_MIGRATIONS.slice(1).map(({ name }) =>
      join(f.directory, 'crates/worker/messaging-migrations', name),
    );
    for (const path of pending) rmSync(path);
    f.command(['migrations', 'apply', 'mikaki-auth-owner']);
    for (const { name } of MESSAGING_MIGRATIONS.slice(1))
      cpSync(
        'crates/worker/messaging-migrations/' + name,
        join(f.directory, 'crates/worker/messaging-migrations', name),
      );
    f.execute(`INSERT INTO messaging_account VALUES('existing-owner','11111111-1111-4111-8111-111111111111');
      INSERT INTO messaging_device_head VALUES('11111111-1111-4111-8111-111111111111','device-a',1,1);
      INSERT INTO messaging_device_head VALUES('11111111-1111-4111-8111-111111111111','device-b',1,1)`);
    const heads = await f.query('SELECT * FROM messaging_device_head ORDER BY device_id');
    const credentials = await f.query('SELECT * FROM credential');
    const schema = await f.query(BASELINE_SCHEMA_QUERY);
    await assert.rejects(checkProductionChatSchema(root, f.query, true), /multiple Chat devices/);
    assert.throws(() => f.command(['migrations', 'apply', 'mikaki-auth-owner']));
    assert.deepEqual(await f.query(BASELINE_SCHEMA_QUERY), schema);
    assert.deepEqual(await f.query('SELECT name FROM messaging_schema_migrations ORDER BY id'), [
      { name: '0001_messaging.sql' },
    ]);
    assert.deepEqual(
      await f.query('SELECT * FROM messaging_device_head ORDER BY device_id'),
      heads,
    );
    assert.deepEqual(await f.query('SELECT * FROM credential'), credentials);
  } finally {
    f.close();
  }
});
