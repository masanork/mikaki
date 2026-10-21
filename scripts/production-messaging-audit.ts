/** Read-only probes shared by ordinary promotion and the opt-in Chat preflight. */
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import type { SchemaRow } from './production-baseline.ts';
import {
  assertMessagingMigrationConfig,
  assertMessagingMigrationFiles,
  assertMessagingLedger,
  MESSAGING_LEDGER,
  MESSAGING_MIGRATION_CONFIG,
  MESSAGING_MIGRATION_DIRECTORY,
  type MessagingLedgerRow,
  type MessagingSchema,
} from './production-messaging-schema.ts';

export type SchemaQuery = (sql: string) => Promise<Record<string, unknown>[]>;

export async function inspectProductionMessaging(
  root: string,
  schema: SchemaRow[],
  query: SchemaQuery,
  allowPartial = false,
): Promise<MessagingSchema | undefined> {
  const config = JSON.parse(readFileSync(join(root, MESSAGING_MIGRATION_CONFIG), 'utf8'));
  const owner = JSON.parse(
    readFileSync(join(root, 'crates/worker/wrangler.production.jsonc'), 'utf8'),
  );
  assertMessagingMigrationConfig(config, owner);
  if (!schema.some(({ name }) => name === MESSAGING_LEDGER)) {
    assert.ok(
      !schema.some(({ name }) => name.startsWith('messaging_')),
      'Chat objects without their separate ledger require reconciliation',
    );
    return undefined;
  }
  const directory = join(root, MESSAGING_MIGRATION_DIRECTORY);
  const migrations = readdirSync(directory)
    .sort((a, b) => a.localeCompare(b))
    .map((name) => ({ name, sql: readFileSync(join(directory, name), 'utf8') }));
  assertMessagingMigrationFiles(migrations);
  const ledger = (await query(
    'SELECT id,name FROM messaging_schema_migrations ORDER BY id',
  )) as MessagingLedgerRow[];
  assertMessagingLedger(ledger, allowPartial);
  if (ledger.length >= 1)
    assert.deepEqual(
      await query(
        'SELECT count(*) AS n FROM (SELECT account_id FROM messaging_device_head GROUP BY account_id HAVING count(*)>1)',
      ),
      [{ n: 0 }],
      'Existing multiple Chat devices require reconciliation; no devices were removed',
    );
  if (ledger.length >= 2)
    assert.deepEqual(
      await query('SELECT id,version FROM messaging_beta_schema ORDER BY id'),
      [{ id: 1, version: 1 }],
      'Chat beta schema marker differs',
    );
  if (ledger.length >= 3)
    assert.deepEqual(
      await query(
        'SELECT id,source_per_minute,deployment_per_minute FROM messaging_resource_policy ORDER BY id',
      ),
      [{ id: 1, source_per_minute: 600, deployment_per_minute: 2400 }],
      'Chat ingress policy differs from the reviewed migration',
    );
  assert.deepEqual(await query('PRAGMA foreign_key_check'), [], 'Live Chat foreign keys failed');
  return { migrations, ledger, allowPartial };
}
