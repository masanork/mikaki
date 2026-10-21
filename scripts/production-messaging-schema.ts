/** Reviewed Chat chain. Its Wrangler ledger never shares the Owner migration namespace. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import type { SqlMigration } from './production-work-schema.ts';

export const MESSAGING_MIGRATION_CONFIG = 'crates/worker/wrangler.messaging-migrations.jsonc';
export const MESSAGING_MIGRATION_DIRECTORY = 'crates/worker/messaging-migrations';
export const MESSAGING_LEDGER = 'messaging_schema_migrations';
export const MESSAGING_MIGRATIONS = [
  {
    name: '0001_messaging.sql',
    sha256: '3ede5f13fd3339872f1a616d400203c4f16b8a3b7e169c2a63569800d830c130',
  },
  {
    name: '0002_beta_profile.sql',
    sha256: '16a2e7e55140abdf8cd45f347abcac2ae64cd187816686cb4aaed119d64fbe00',
  },
  {
    name: '0003_ingress_budget.sql',
    sha256: '6bacfaf3d381a090b6b0b87230722794c0622b22ab84be4b1fd98cd16199566d',
  },
] as const;

/** Matches the installed Wrangler ledger DDL, including the quoted table name. */
export const MESSAGING_LEDGER_SQL = `CREATE TABLE "messaging_schema_migrations"(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT UNIQUE,
  applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
)`;
export type MessagingLedgerRow = { id: number; name: string };
export type MessagingSchema = {
  migrations: SqlMigration[];
  ledger: MessagingLedgerRow[];
  allowPartial?: boolean;
};

export function assertMessagingMigrationFiles(migrations: SqlMigration[]) {
  assert.deepEqual(
    migrations.map(({ name }) => name),
    MESSAGING_MIGRATIONS.map(({ name }) => name),
    'Unexpected Chat migration files',
  );
  for (const [index, migration] of migrations.entries())
    assert.equal(
      createHash('sha256').update(migration.sql).digest('hex'),
      MESSAGING_MIGRATIONS[index]!.sha256,
      'Chat migration bytes differ',
    );
}

export function assertMessagingLedger(ledger: MessagingLedgerRow[], allowPartial = false) {
  assert.ok(ledger.length <= MESSAGING_MIGRATIONS.length, 'Unexpected Chat ledger length');
  const expected = MESSAGING_MIGRATIONS.map(({ name }, index) => ({ id: index + 1, name }));
  assert.deepEqual(
    ledger,
    allowPartial ? expected.slice(0, ledger.length) : expected,
    'Production Chat migration ledger differs',
  );
}

type DatabaseConfig = {
  binding: string;
  database_name: string;
  database_id: string;
  migrations_dir: string;
  migrations_table?: string;
};
type OwnerConfig = { account_id: string; d1_databases: DatabaseConfig[] };

/** Bind migration operations to the reviewed Owner DB, with no deployable Worker fields. */
export function assertMessagingMigrationConfig(config: unknown, owner: OwnerConfig) {
  assert.match(owner.account_id, /^[a-f0-9]{32}$/);
  const database = owner.d1_databases.find(({ binding }) => binding === 'DB');
  assert.ok(database, 'Owner DB binding is missing');
  assert.equal(database.migrations_dir, 'migrations');
  assert.ok(!database.migrations_table || database.migrations_table === 'd1_migrations');
  assert.deepEqual(
    config,
    {
      name: 'mikaki-chat-schema',
      account_id: owner.account_id,
      compatibility_date: '2026-10-21',
      d1_databases: [
        {
          binding: 'DB',
          database_name: database.database_name,
          database_id: database.database_id,
          migrations_dir: 'messaging-migrations',
          migrations_table: MESSAGING_LEDGER,
        },
      ],
    },
    'Chat migration target/config differs from the reviewed Owner database',
  );
}
