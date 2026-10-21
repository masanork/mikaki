/** Explicitly local or remote, always read-only. This command never applies migrations. */
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync, readdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { BASELINE_SCHEMA_QUERY, canonicalSchema, type SchemaRow } from './production-baseline.ts';
import { assertProductionOwnerSchema } from './production-owner-schema.ts';
import { inspectProductionMessaging, type SchemaQuery } from './production-messaging-audit.ts';
import {
  assertMessagingMigrationConfig,
  MESSAGING_MIGRATION_CONFIG,
  MESSAGING_MIGRATIONS,
} from './production-messaging-schema.ts';
import type { WorkLedgerRow } from './production-work-schema.ts';

export async function checkProductionChatSchema(root: string, query: SchemaQuery, local = false) {
  const rows = (await query(BASELINE_SCHEMA_QUERY)) as SchemaRow[];
  // workerd's local persistence adds this platform table. Remote audit has no exception.
  const metadata = rows.filter(
    ({ name, tbl_name }) => name === '_cf_METADATA' || tbl_name === '_cf_METADATA',
  );
  if (local && metadata.length)
    assert.deepEqual(
      canonicalSchema(metadata),
      canonicalSchema([
        {
          type: 'table',
          name: '_cf_METADATA',
          tbl_name: '_cf_METADATA',
          sql: 'CREATE TABLE _cf_METADATA (key INTEGER PRIMARY KEY, value BLOB)',
        },
      ]),
      'Unexpected local D1 metadata schema',
    );
  const schema = local ? rows.filter((row) => !metadata.includes(row)) : rows;
  const ownerLedger = (await query('SELECT name FROM d1_migrations ORDER BY id')) as {
    name: string;
  }[];
  const load = (directory: string) =>
    readdirSync(join(root, directory))
      .filter((name) => name.endsWith('.sql'))
      .sort((a, b) => a.localeCompare(b))
      .map((name) => ({ name, sql: readFileSync(join(root, directory, name), 'utf8') }));
  const work = schema.some(({ name }) => name === 'work_schema_migrations')
    ? {
        migrations: load('crates/worker/work-migrations'),
        ledger: (await query(
          'SELECT id,name,sha256 FROM work_schema_migrations ORDER BY id',
        )) as WorkLedgerRow[],
      }
    : undefined;
  const messaging = await inspectProductionMessaging(root, schema, query, true);
  assertProductionOwnerSchema(
    load('crates/worker/migrations'),
    ownerLedger,
    schema,
    work,
    messaging,
  );
  assert.deepEqual(await query('PRAGMA foreign_key_check'), [], 'Live foreign keys failed');
  return {
    schema: 'mikaki-chat-schema-check-v1',
    applied: messaging?.ledger.length ?? 0,
    complete: messaging?.ledger.length === MESSAGING_MIGRATIONS.length,
    mutations: false,
  };
}

export function chatSchemaArguments(args: string[]) {
  assert.ok(
    args.length === 1 && (args[0] === '--local' || args[0] === '--remote'),
    'Usage: check-production-chat-schema.ts --local|--remote',
  );
  return args[0];
}

async function main() {
  const mode = chatSchemaArguments(process.argv.slice(2));
  const root = fileURLToPath(new URL('../', import.meta.url));
  assertMessagingMigrationConfig(
    JSON.parse(readFileSync(join(root, MESSAGING_MIGRATION_CONFIG), 'utf8')),
    JSON.parse(readFileSync(join(root, 'crates/worker/wrangler.production.jsonc'), 'utf8')),
  );
  const query: SchemaQuery = async (sql) => {
    const results = JSON.parse(
      execFileSync(
        join(root, 'node_modules/.bin/wrangler'),
        [
          'd1',
          'execute',
          'mikaki-auth-owner',
          mode,
          '--config',
          MESSAGING_MIGRATION_CONFIG,
          '--command',
          sql,
          '--json',
        ],
        {
          cwd: root,
          encoding: 'utf8',
          timeout: 120_000,
          maxBuffer: 4 * 1024 * 1024,
          stdio: ['ignore', 'pipe', 'pipe'],
        },
      ),
    );
    assert.equal(results.length, 1, 'Expected one read-only query result');
    assert.equal(results[0].success, true);
    return results[0].results;
  };
  console.log(JSON.stringify(await checkProductionChatSchema(root, query, mode === '--local')));
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url))
  main().catch((error: unknown) => {
    console.error(error instanceof Error ? error.message : 'Chat schema check failed');
    process.exitCode = 1;
  });
