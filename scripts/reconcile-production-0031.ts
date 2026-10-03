/** One reviewed D1 migration only. No deploy, credentials, data export, or restore. */
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  appendFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';

export const APPROVED = {
  source: 'fd55932eee716c2c623cbbb45d1c8b68ec8c354e',
  migration: '0031_vault_owner_keys.sql',
  sha256: '310c0f20250e5088224ab99c0ee31a9f36f23ba9476d220f3000ec379206125c',
  config: 'crates/worker/wrangler.production.jsonc',
  config_sha256: '145772fc877d6442509deddd5e29e35308fa9f2a36644b44f63b64c44f6c1efd',
  account: '4b749427a0c80c547e726a42aff4b6fc',
  database: 'mikaki-auth',
  database_id: 'f9299d62-2dbf-4bae-ae49-8b75674572d4',
  wrangler: '4.144.0',
} as const;
export const CONFIRMATION = 'APPLY 0031 TO mikaki-auth';
export const LEDGER_SQL = 'SELECT id, name FROM d1_migrations ORDER BY id';
export const SCHEMA_SQL = `SELECT type, name, tbl_name, sql FROM sqlite_master
WHERE tbl_name IN ('d1_migrations', 'vault_owner_key_head', 'vault_owner_key_wrap')
OR name IN ('d1_migrations', 'vault_owner_key_head', 'vault_owner_key_wrap')
ORDER BY type, name`;
const ledgerDDL = `CREATE TABLE "d1_migrations"(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT UNIQUE,
  applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
);`;
type Row = Record<string, unknown>;
export type Run = (args: string[]) => string;
export type Inputs = { names: string[]; migration: string; before: Row[]; after: Row[] };
type State = { pending: string[]; schema_sha256: string; plan_sha256: string };
type Plan = {
  approved: typeof APPROVED;
  workflow_commit: string;
  run_id: string;
  run_attempt: string;
  captured_at: string;
  bookmark: string;
  state: State;
};
class GateError extends Error {}
function gate(ok: unknown, message: string): asserts ok {
  if (!ok) throw new GateError(message);
}
const digest = (value: string | Uint8Array) => createHash('sha256').update(value).digest('hex');
const equal = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);
function json(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    throw new GateError('Wrangler returned invalid JSON; stopping.');
  }
}
function record(value: unknown): value is Row {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
export function resultRows(text: string): Row[] {
  const value = json(text);
  gate(Array.isArray(value) && value.length === 1 && record(value[0]), 'Expected one D1 result.');
  gate(value[0].success === true && Array.isArray(value[0].results), 'D1 query did not succeed.');
  gate(value[0].results.every(record), 'Malformed D1 result rows.');
  return value[0].results;
}
function canonicalSchema(rows: Row[]) {
  return rows.map((row) => {
    gate(
      ['table', 'index', 'trigger', 'view'].includes(String(row.type)),
      'Unknown schema object type.',
    );
    gate(
      typeof row.name === 'string' && typeof row.tbl_name === 'string',
      'Malformed schema object.',
    );
    gate(row.sql === null || typeof row.sql === 'string', 'Malformed schema SQL.');
    // These reviewed definitions have no string literals with significant whitespace.
    // Only the ledger's optional identifier quoting and whitespace are normalized.
    const sql =
      row.sql === null
        ? null
        : (row.sql as string)
            .replace(/"d1_migrations"/g, 'd1_migrations')
            .replace(/\s+/g, '')
            .replace(/;$/, '');
    return { type: row.type, name: row.name, tbl_name: row.tbl_name, sql };
  });
}
export function expectedInputs(root: string): Inputs {
  const directory = join(root, 'crates/worker/migrations');
  const names = readdirSync(directory).sort();
  gate(
    names.length === 31 &&
      names.every(
        (name, index) =>
          name.startsWith(`${String(index + 1).padStart(4, '0')}_`) &&
          /^\d{4}_[a-z0-9_]+\.sql$/.test(name),
      ),
    'Expected exactly the reviewed 0001–0031 migration files.',
  );
  gate(names.at(-1) === APPROVED.migration, 'Unexpected last migration.');
  const migration = readFileSync(join(directory, APPROVED.migration), 'utf8');
  gate(digest(migration) === APPROVED.sha256, 'Reviewed migration hash differs.');
  const db = new DatabaseSync(':memory:');
  try {
    for (const name of names.slice(0, -1)) db.exec(readFileSync(join(directory, name), 'utf8'));
    db.exec(ledgerDDL);
    const before = db.prepare(SCHEMA_SQL).all();
    db.exec(migration);
    return { names, migration, before, after: db.prepare(SCHEMA_SQL).all() };
  } finally {
    db.close();
  }
}
export function inspectState(inputs: Inputs, ledger: Row[], schema: Row[]): State {
  gate(
    ledger.length === 30 || ledger.length === 31,
    'Ledger is not the reviewed 0001–0030/0031 prefix; stop for review.',
  );
  let previous = 0;
  for (const [index, row] of ledger.entries()) {
    gate(
      Number.isSafeInteger(row.id) && Number(row.id) > previous,
      'Invalid migration ledger order.',
    );
    gate(
      row.name === inputs.names[index],
      'Unexpected, missing, duplicate, or reordered migration; stop for review.',
    );
    previous = Number(row.id);
  }
  const pending = inputs.names.slice(ledger.length);
  const actual = canonicalSchema(schema);
  const expected = canonicalSchema(pending.length ? inputs.before : inputs.after);
  gate(
    equal(actual, expected),
    'Migration ledger/table state disagrees with reviewed schema; no automatic repair.',
  );
  const schema_sha256 = digest(JSON.stringify(actual));
  const plan_sha256 = digest(
    JSON.stringify({ approved: APPROVED, ledger, pending, schema_sha256 }),
  );
  return { pending, schema_sha256, plan_sha256 };
}
export function inspect(run: Run, inputs: Inputs): State {
  const query = (sql: string) =>
    resultRows(
      run([
        'd1',
        'execute',
        APPROVED.database,
        '--remote',
        '--config',
        APPROVED.config,
        '--json',
        '--command',
        sql,
      ]),
    );
  return inspectState(inputs, query(LEDGER_SQL), query(SCHEMA_SQL));
}
export function bookmarkAt(run: Run, timestamp: string): string {
  const value = json(
    run([
      'd1',
      'time-travel',
      'info',
      APPROVED.database,
      '--config',
      APPROVED.config,
      '--timestamp',
      timestamp,
      '--json',
    ]),
  );
  gate(
    record(value) &&
      typeof value.bookmark === 'string' &&
      /^[a-f0-9]{8}-[a-f0-9]{8}-[a-f0-9]{8}-[a-f0-9]{32}$/.test(value.bookmark),
    'Missing or malformed Time Travel bookmark.',
  );
  return value.bookmark;
}
export function applicationGate(
  state: State,
  approvedPlan: string | undefined,
  confirmation: string | undefined,
) {
  gate(
    confirmation === CONFIRMATION,
    'Explicit database/migration application confirmation is required.',
  );
  gate(
    /^[a-f0-9]{64}$/.test(approvedPlan ?? '') && approvedPlan === state.plan_sha256,
    'Fresh preflight does not match the reviewed plan digest.',
  );
  gate(
    equal(state.pending, [APPROVED.migration]),
    'Apply requires exactly 0031 pending; use plan to inspect an already-applied database.',
  );
}
export function applyOnly0031(run: Run, migration: string, temp: string) {
  gate(digest(migration) === APPROVED.sha256, 'Staged migration hash differs.');
  const directory = mkdtempSync(join(temp, 'mikaki-0031-'));
  try {
    mkdirSync(join(directory, 'migrations'));
    writeFileSync(join(directory, 'migrations', APPROVED.migration), migration, { mode: 0o600 });
    // Minimal derivative of the pinned production config: same account/DB/ledger,
    // with a directory containing only the approved SQL, even if the ledger races.
    const config = join(directory, 'wrangler.json');
    writeFileSync(
      config,
      JSON.stringify({
        account_id: APPROVED.account,
        d1_databases: [
          {
            binding: 'DB',
            database_name: APPROVED.database,
            database_id: APPROVED.database_id,
            migrations_dir: 'migrations',
            migrations_table: 'd1_migrations',
          },
        ],
      }),
      { mode: 0o600 },
    );
    // migrations apply supports neither --json nor --yes in pinned Wrangler.
    // CI=true + noninteractive stdin provides its documented confirmation behavior.
    run(['d1', 'migrations', 'apply', APPROVED.database, '--remote', '--config', config]);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}
function verifySource(root: string, implementation: string) {
  const git = (args: string[]) =>
    execFileSync('git', args, {
      cwd: root,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    }).trim();
  gate(
    git(['rev-parse', 'HEAD']) === APPROVED.source,
    'Source checkout is not the approved commit.',
  );
  gate(
    git(['status', '--porcelain', '--untracked-files=all']) === '',
    'Approved source checkout is dirty.',
  );
  const bytes = readFileSync(join(root, APPROVED.config));
  gate(digest(bytes) === APPROVED.config_sha256, 'Production config hash differs.');
  const config = JSON.parse(bytes.toString());
  gate(
    config.account_id === APPROVED.account &&
      config.d1_databases.length === 1 &&
      config.d1_databases[0].database_id === APPROVED.database_id &&
      config.d1_databases[0].database_name === APPROVED.database,
    'Production target differs.',
  );
  gate(
    JSON.parse(readFileSync(join(root, 'node_modules/wrangler/package.json'), 'utf8')).version ===
      APPROVED.wrangler,
    'Installed Wrangler is not pinned.',
  );
  // A later workflow revision must not conceal newer or modified migrations.
  const dir = 'crates/worker/migrations';
  const names = readdirSync(join(root, dir)).sort();
  gate(
    equal(names, readdirSync(join(implementation, dir)).sort()),
    'Workflow source has a different migration inventory; re-review required.',
  );
  for (const name of names)
    gate(
      readFileSync(join(root, dir, name)).equals(readFileSync(join(implementation, dir, name))),
      'Workflow source migration bytes differ; re-review required.',
    );
  gate(
    bytes.equals(readFileSync(join(implementation, APPROVED.config))),
    'Workflow source production configuration differs; re-review required.',
  );
}
function save(path: string, value: unknown) {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
}
async function main() {
  const implementation = fileURLToPath(new URL('../', import.meta.url));
  const root = join(implementation, 'reviewed-source');
  const mode = process.argv[2];
  gate(
    process.argv.length === 3 && (mode === 'plan' || mode === 'apply'),
    'Usage: reconcile-production-0031.ts plan|apply',
  );
  gate(
    process.env.GITHUB_EVENT_NAME === 'workflow_dispatch' &&
      process.env.GITHUB_REF === 'refs/heads/main' &&
      process.env.GITHUB_REPOSITORY === 'masanork/mikaki',
    'Only manual main-branch runs in masanork/mikaki are supported.',
  );
  gate(
    /^[a-f0-9]{40}$/.test(process.env.GITHUB_SHA ?? '') &&
      /^\d+$/.test(process.env.GITHUB_RUN_ID ?? '') &&
      /^\d+$/.test(process.env.GITHUB_RUN_ATTEMPT ?? ''),
    'Missing workflow identity.',
  );
  gate(
    process.env.CLOUDFLARE_API_TOKEN,
    'Existing production CLOUDFLARE_API_TOKEN is unavailable.',
  );
  verifySource(root, implementation);
  const inputs = expectedInputs(root);
  const temporary = mkdtempSync(join(process.env.RUNNER_TEMP ?? tmpdir(), 'mikaki-reconcile-'));
  const run: Run = (args) => {
    try {
      return execFileSync(join(root, 'node_modules/.bin/wrangler'), args, {
        cwd: root,
        encoding: 'utf8',
        timeout: 120_000,
        maxBuffer: 4 * 1024 * 1024,
        stdio: ['ignore', 'pipe', 'pipe'],
        env: {
          ...process.env,
          CI: 'true',
          CLOUDFLARE_ACCOUNT_ID: APPROVED.account,
          WRANGLER_SEND_METRICS: 'false',
          WRANGLER_LOG_PATH: join(temporary, 'wrangler.log'),
        },
      });
    } catch {
      throw new GateError(
        'Wrangler operation failed or timed out. Raw output is suppressed; inspect Cloudflare access/state before retrying.',
      );
    }
  };
  const artifacts = join(implementation, 'artifacts');
  mkdirSync(artifacts, { recursive: true });
  const planPath = join(artifacts, 'migration-0031-plan.json');
  const resultPath = join(artifacts, 'migration-0031-result.json');
  const identity = {
    workflow_commit: process.env.GITHUB_SHA!,
    run_id: process.env.GITHUB_RUN_ID!,
    run_attempt: process.env.GITHUB_RUN_ATTEMPT!,
  };
  try {
    if (mode === 'plan') {
      const state = inspect(run, inputs);
      if (process.env.RECONCILE_MODE === 'apply-0031')
        applicationGate(state, process.env.APPROVED_PLAN_SHA256, process.env.CONFIRM_APPLY);
      const captured_at = new Date().toISOString();
      const bookmark = bookmarkAt(run, captured_at);
      gate(
        bookmarkAt(run, captured_at) === bookmark,
        'Time Travel timestamp/bookmark readback disagrees.',
      );
      const plan: Plan = { approved: APPROVED, ...identity, captured_at, bookmark, state };
      save(planPath, plan);
      const summary = `0031 migration preflight (no database writes)\nSource: ${APPROVED.source}\nDatabase: ${APPROVED.database} (${APPROVED.database_id})\nPending: ${state.pending.join(', ') || 'none'}\nSchema: reviewed state matches\nPlan SHA-256: ${state.plan_sha256}\nBookmark timestamp: ${captured_at}\nBookmark (read back): ${bookmark}\nThis is a D1 recovery coordinate, not a complete Vault backup or a tested restore.\n`;
      console.log(summary);
      if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, summary);
      return;
    }
    gate(process.env.RECONCILE_MODE === 'apply-0031', 'Apply mode was not selected.');
    const plan = JSON.parse(readFileSync(planPath, 'utf8')) as Plan;
    gate(
      equal(plan.approved, APPROVED) &&
        plan.workflow_commit === identity.workflow_commit &&
        plan.run_id === identity.run_id &&
        plan.run_attempt === identity.run_attempt,
      'Preflight record belongs to a different source or run.',
    );
    gate(
      Date.now() - Date.parse(plan.captured_at) >= 0 &&
        Date.now() - Date.parse(plan.captured_at) < 120_000,
      'Recorded pre-migration bookmark is stale; prepare a fresh run.',
    );
    const state = inspect(run, inputs);
    applicationGate(state, process.env.APPROVED_PLAN_SHA256, process.env.CONFIRM_APPLY);
    gate(equal(state, plan.state), 'State changed after preflight; no application.');
    gate(
      bookmarkAt(run, plan.captured_at) === plan.bookmark,
      'Recorded bookmark readback disagrees.',
    );
    const result: Record<string, unknown> = {
      approved: APPROVED,
      ...identity,
      preflight: plan,
      outcome: 'application_attempted_outcome_unverified',
    };
    save(resultPath, result);
    // The workflow must successfully retain the preflight artifact before this step.
    applyOnly0031(run, inputs.migration, temporary);
    const after = inspect(run, inputs);
    gate(after.pending.length === 0, 'Post-application migrations remain pending.');
    result.outcome = 'applied_and_schema_verified';
    result.after = after;
    save(resultPath, result);
    const summary =
      '0031 applied; the full reviewed 0001–0031 ledger and both exact STRICT table definitions match. No migrations pending. No Worker was deployed.\n';
    console.log(summary);
    if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, summary);
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    await main();
  } catch (error) {
    console.error(
      error instanceof GateError
        ? error.message
        : 'Reconciliation stopped. No raw response or exception is printed; inspect the retained preflight/result before taking further action.',
    );
    process.exitCode = 1;
  }
}
