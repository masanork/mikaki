/** Issue #121 preparation. Reads checked-in configuration and rehearses schema
 * creation in disposable SQLite only; never contacts or mutates Cloudflare. */
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';
import ts from '@typescript/typescript6';

type Migration = { name: string; sha256: string; sql: string };
type SchemaObject = { type: string; name: string; tbl_name: string; sql: string };
type WorkerConfig = {
  name: string;
  account_id?: string;
  routes?: { pattern: string; custom_domain?: boolean }[];
  d1_databases?: {
    binding: string;
    database_name: string;
    database_id: string;
    migrations_dir?: string;
    migrations_table?: string;
  }[];
  r2_buckets?: { binding: string; bucket_name: string }[];
  services?: { binding: string; service: string; entrypoint?: string }[];
  secrets?: { required?: string[] };
  secrets_store_secrets?: { binding: string; store_id: string; secret_name: string }[];
  triggers?: { crons?: string[] };
};
export const BASELINE_NAME = '0001_owner_vault_initial.sql';
export const IDENTITY_TABLES = [
  'identity_claim_release',
  'identity_document',
  'identity_transaction',
  'identity_wallet_grant',
  'identity_wallet_par',
  'identity_wallet_attestation_replay',
  'identity_nonce',
  'identity_attester_challenge',
] as const;
export const LEGACY_TABLE =
  /^(?:vault_attribute_(?:head|mutation|recipient_envelope|grant|share_audit)|vault_share_policy|vault_share_atomic_guard|vault_gc_cursor|vault_oauth_(?:consent|grant|code_context|token_context)|vault_passkey_transfer_audit)$/;
const sha256 = (value: string) => createHash('sha256').update(value).digest('hex');

export function readMigrations(directory: string): Migration[] {
  const names = readdirSync(directory)
    .filter((name) => name.endsWith('.sql'))
    .sort();
  if (!names.length || names.some((name) => !/^\d{4}_[A-Za-z0-9_-]+\.sql$/.test(name)))
    throw new Error('Invalid migration filenames');
  if (new Set(names.map((name) => name.slice(0, 4))).size !== names.length)
    throw new Error('Duplicate migration number');
  return names.map((name) => {
    const sql = readFileSync(join(directory, name), 'utf8');
    return { name, sha256: sha256(sql), sql };
  });
}

export function rehearseSchema(migrations: Migration[]) {
  const db = new DatabaseSync(':memory:');
  try {
    db.exec('PRAGMA foreign_keys=ON');
    for (const migration of migrations) {
      db.exec('BEGIN IMMEDIATE');
      try {
        db.exec(migration.sql);
        db.exec('COMMIT');
      } catch (error) {
        db.exec('ROLLBACK');
        throw new Error(`Migration rehearsal failed: ${migration.name}`, { cause: error });
      }
    }
    if (db.prepare('PRAGMA integrity_check').get()?.integrity_check !== 'ok')
      throw new Error('Schema integrity check failed');
    if (db.prepare('PRAGMA foreign_key_check').all().length)
      throw new Error('Schema foreign key check failed');
    const objects = db
      .prepare(
        "SELECT type,name,tbl_name,sql FROM sqlite_master WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%' ORDER BY type,name",
      )
      .all() as SchemaObject[];
    const tables = objects.filter((item) => item.type === 'table').map((item) => item.name);
    return {
      sha256: sha256(JSON.stringify(objects)),
      objects: objects.map(({ type, name, tbl_name }) => ({ type, name, table: tbl_name })),
      tables,
      legacy_tables: tables.filter((name) => LEGACY_TABLE.test(name)),
      legacy_dependencies: objects
        .filter((item) =>
          /\bvault_attribute_(?:head|mutation|recipient_envelope|grant|share_audit)\b|\bvault_share_policy\b|\bvault_share_atomic_guard\b|\bvault_gc_cursor\b|\bvault_oauth_(?:consent|grant|code_context|token_context)\b|\bvault_passkey_transfer_audit\b/.test(
            item.sql,
          ),
        )
        .map(({ type, name, tbl_name }) => ({ type, name, table: tbl_name })),
      missing_identity_tables: IDENTITY_TABLES.filter((name) => !tables.includes(name)),
    };
  } finally {
    db.close();
  }
}

/** A future reset executor must call this before sending baseline DDL. D1's
 * filename-only ledger cannot distinguish a rewritten 0001 from the old one.
 * Even an empty old ledger is existing application state, not a fresh target. */
export function assertFreshBaselineTarget(objects: { name: string }[]): void {
  const remaining = objects.filter(
    (item) => item.name !== 'sqlite_sequence' && item.name !== '_cf_KV',
  );
  if (remaining.length) throw new Error('Baseline requires a fresh database with no old ledger');
}

function config(root: string, relative: string): WorkerConfig {
  const parsed = ts.parseConfigFileTextToJson(relative, readFileSync(join(root, relative), 'utf8'));
  const result: unknown = parsed.config;
  if (parsed.error || !result || typeof result !== 'object')
    throw new Error(`Invalid Worker configuration: ${relative}`);
  const value = result as WorkerConfig;
  if (typeof value.name !== 'string' || !value.name) throw new Error('Missing Worker name');
  return value;
}

export function createResetPlan(root: string) {
  const opPath = 'crates/worker/wrangler.production.jsonc';
  const claimPath = 'crates/userinfo-claim-worker/wrangler.production.jsonc';
  const demoPath = 'crates/helpdesk-rp/wrangler.demo.jsonc';
  const paths = [opPath, claimPath, demoPath];
  const configs = paths.map((path) => ({ path, value: config(root, path) }));
  const databases = configs.flatMap(({ path, value }) =>
    (value.d1_databases ?? []).map((db) => ({
      config: path,
      worker: value.name,
      account_id: value.account_id,
      binding: db.binding,
      name: db.database_name,
      id: db.database_id,
      ledger: db.migrations_table ?? 'd1_migrations',
      disposition: path === demoPath ? 'retire-after-client-revocation' : 'reset',
      migration_directory: resolve(root, dirname(path), db.migrations_dir ?? 'migrations'),
    })),
  );
  const schemas = databases.map((db) => {
    const migrations = readMigrations(db.migration_directory);
    const schema = rehearseSchema(migrations);
    return {
      database: db.name,
      migrations: migrations.map(({ name, sha256 }) => ({ name, sha256 })),
      ...schema,
      identity_profile_required: db.config === opPath,
      missing_identity_tables: db.config === opPath ? schema.missing_identity_tables : [],
    };
  });
  const opSchema = schemas.find((schema) => schema.database === databases[0]?.name);
  if (!opSchema) throw new Error('Missing OP schema');
  const blockers = [
    ...(opSchema.missing_identity_tables.length ? ['identity-not-integrated'] : []),
    ...(opSchema.legacy_tables.length || opSchema.legacy_dependencies.length
      ? ['legacy-vault-still-present']
      : []),
    ...(opSchema.migrations.length !== 1 || opSchema.migrations[0].name !== BASELINE_NAME
      ? ['baseline-not-consolidated']
      : []),
    'faq-production-registration-required',
    'live-resource-inventory-required',
    'reset-approval-required',
  ];
  return {
    schema_version: 1,
    issue: 121,
    mode: 'offline-review-only',
    source: {
      commit: execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim(),
      dirty: Boolean(
        execFileSync('git', ['status', '--porcelain'], { cwd: root, encoding: 'utf8' }).trim(),
      ),
    },
    blockers,
    configs: configs.map(({ path }) => ({
      path,
      sha256: sha256(readFileSync(join(root, path), 'utf8')),
    })),
    databases: databases.map(({ migration_directory, ...db }) => ({
      ...db,
      migration_directory: migration_directory.slice(root.length + 1),
    })),
    schemas,
    workers: configs.map(({ path, value }) => ({
      name: value.name,
      routes: value.routes ?? [],
      crons: value.triggers?.crons ?? [],
      services: value.services ?? [],
      disposition: path === demoPath ? 'retire' : 'preserve-and-redeploy',
    })),
    buckets: configs.flatMap(({ value }) =>
      (value.r2_buckets ?? []).map((bucket) => ({
        ...bucket,
        disposition: 'empty-all-objects-after-writers-stop',
      })),
    ),
    preserve_secret_names: configs.flatMap(({ path, value }) => [
      ...(value.secrets?.required ?? []).map((name) => ({
        worker: value.name,
        name,
        disposition: path === demoPath ? 'retire-with-demo-worker' : 'preserve',
      })),
      ...(value.secrets_store_secrets ?? []).map((secret) => ({
        worker: value.name,
        ...secret,
        disposition: 'preserve',
      })),
    ]),
    faq: {
      configured: false,
      product: 'mikaki Docs',
      origin: 'https://docs.mikaki.org',
      required: ['client_id', 'public_jwk', 'rp_database', 'private-key-secret-reference'],
    },
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 2) throw new Error('Usage: node scripts/plan-owner-vault-reset.ts');
  const plan = createResetPlan(fileURLToPath(new URL('../', import.meta.url)));
  process.stdout.write(`${JSON.stringify(plan, null, 2)}\n`);
  // A review plan with unresolved prerequisites must never look deploy-ready.
  if (plan.blockers.length) process.exitCode = 2;
}
