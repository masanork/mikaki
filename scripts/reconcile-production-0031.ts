/** Only reviewed D1 migrations 0033–0035. No deploy, credentials, data export, or restore. */
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
import {
  cloudflareMetadataGet,
  inspectWorkerInventory,
  InventoryError,
  type MetadataGet,
} from './production-worker-inventory.ts';

export const APPROVED = {
  source: 'af0b89963761b4ecda2adbf3ed7fb77bfda507d4',
  migrations: [
    {
      name: '0033_agent_record_sources.sql',
      sha256: '4afb23458731123b33ebf4902983d06bd66051c920342c320788075646dc5f35',
    },
    {
      name: '0034_vault_record_userinfo.sql',
      sha256: 'efe8977f8f84973115489673d183d31328122ee13ef0d4520a4730408127fe9f',
    },
    {
      name: '0035_agent_record_approvals.sql',
      sha256: '71af68c80be4aa4875788b46c562b2cde5ff424f8af4adce7f7fb3ac24e13644',
    },
  ],
  qualified_live: {
    source: '04b94d951465f5f5ab02a3c71eaa55bbfe117448',
    op: { name: 'mikaki-auth', version: 'c9138630-23fb-4652-abb4-3fbebbb95a4d' },
    claim: { name: 'mikaki-auth-claims', version: '870b0ae4-95f9-4694-bfae-15d8041be144' },
    deployment_run: '37092046315',
    deployment_artifact_sha256: 'e12863b268de701a934c913eaf845c3dbc747bc83289d7d58fe14b082ec9325f',
  },
  claim_config: 'crates/userinfo-claim-worker/wrangler.production.jsonc',
  claim_config_sha256: '6ef89b6ddbbc453fa2d5a0c79d3bfc946c287e90d45de47ac9a38a86cb0d4216',
  config: 'crates/worker/wrangler.production.jsonc',
  config_sha256: '145772fc877d6442509deddd5e29e35308fa9f2a36644b44f63b64c44f6c1efd',
  account: '4b749427a0c80c547e726a42aff4b6fc',
  database: 'mikaki-auth',
  database_id: 'f9299d62-2dbf-4bae-ae49-8b75674572d4',
  wrangler: '4.144.0',
} as const;
export const CONFIRMATION = 'APPLY 0033 THROUGH 0035 TO mikaki-auth';
export const LEDGER_SQL = 'SELECT id, name FROM d1_migrations ORDER BY id';
export const CURSOR_SQL = 'SELECT id FROM vault_owner_record_gc_cursor ORDER BY id';
export const POLICY_SQL =
  'SELECT id, enabled, grant_ttl_seconds, revision FROM vault_record_share_policy ORDER BY id';
export const DORMANT_POLICY = [{ id: 1, enabled: 0, grant_ttl_seconds: 604800, revision: 1 }];
export const COMPATIBILITY_TARGET = {
  account: APPROVED.account,
  database_id: APPROVED.database_id,
  qualified_source: APPROVED.qualified_live.source,
  op: APPROVED.qualified_live.op.name,
  claim: APPROVED.qualified_live.claim.name,
  versions: {
    op: APPROVED.qualified_live.op.version,
    claim: APPROVED.qualified_live.claim.version,
  },
};
const BASELINE = 32;
const LATEST = BASELINE + APPROVED.migrations.length;

// Include each changed table and the grant/revocation dependencies, not just owner tables.
// tbl_name includes every index/trigger attached to these tables, including unknown extras.
const schemaTables = [
  'd1_migrations',
  'account_security',
  'credential',
  'agent_recipient_key',
  'agent_grant',
  'agent_audit',
  'agent_proposal',
  'agent_draft',
  'agent_attribute_capability',
  'agent_attribute_proposal',
  'vault_attribute_head',
  'vault_owner_key_head',
  'vault_owner_key_wrap',
  'vault_owner_record_head',
  'vault_owner_record_mutation',
  'vault_owner_record_gc_cursor',
  'agent_attribute_commit',
  'agent_attribute_commit_guard',
  'vault_record_share_policy',
  'vault_record_recipient_envelope',
  'vault_record_grant',
  'vault_record_share_audit',
  'vault_record_share_guard',
  'vault_claim_release',
  'vault_claim_release_audit',
  'vault_claim_disclosure_audit',
  'vault_claim_release_policy',
  'vault_share_policy',
  'vault_recipient_key',
  'client',
  'app_connection',
  'vault_attribute_grant',
  'vault_attribute_recipient_envelope',
  'vault_attribute_mutation',
]
  .map((name) => `'${name}'`)
  .join(', ');
export const SCHEMA_SQL = `SELECT type, name, tbl_name, sql FROM sqlite_master
WHERE tbl_name IN (${schemaTables}) OR name IN (${schemaTables}) ORDER BY type, name`;
const ledgerDDL = `CREATE TABLE "d1_migrations"(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT UNIQUE,
  applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
);`;
type Row = Record<string, unknown>;
export type Run = (args: string[]) => string;
export type Inputs = {
  names: string[];
  migrations: Record<string, string>;
  schemas: Record<number, Row[]>;
};
type State = { pending: string[]; schema_sha256: string; plan_sha256: string };
type Plan = {
  approved: typeof APPROVED;
  workflow_commit: string;
  run_id: string;
  run_attempt: string;
  captured_at: string;
  bookmark: string;
  state: FullState;
};
type FullState = State & { compatibility: Awaited<ReturnType<typeof inspectWorkerInventory>> };
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
/** Conservative SQLite tokenization: ignore layout/comments, never bytes inside quotes.
 * Token boundaries remain explicit, so `IS NOT` cannot equal `ISNOT`, nor `- -` a comment.
 * This is not a semantic SQL rewriter: case, operators, numbers and quoted bytes stay exact.
 */
export function canonicalSql(sql: string): string[] {
  const tokens: string[] = [];
  let i = 0;
  while (i < sql.length) {
    const rest = sql.slice(i);
    const whitespace = /^[ \t\r\n\f]+/.exec(rest);
    if (whitespace) {
      i += whitespace[0].length;
      continue;
    }
    if (rest.startsWith('--')) {
      const end = sql.indexOf('\n', i + 2);
      i = end < 0 ? sql.length : end + 1;
      continue;
    }
    if (rest.startsWith('/*')) {
      const end = sql.indexOf('*/', i + 2);
      gate(end >= 0, 'Unterminated schema SQL comment.');
      i = end + 2;
      continue;
    }
    // SQLite blob literals are one token: X'AB' must differ from X 'AB'.
    const blob = /^[xX]'[0-9a-fA-F]*'/.exec(rest);
    if (blob) {
      tokens.push(blob[0]);
      i += blob[0].length;
      continue;
    }
    const quote = sql[i]!;
    if (["'", '"', '`', '['].includes(quote)) {
      const start = i++;
      const close = quote === '[' ? ']' : quote;
      let closed = false;
      while (i < sql.length) {
        if (sql[i++] !== close) continue;
        if (quote !== '[' && sql[i] === close) {
          i++;
          continue;
        }
        closed = true;
        break;
      }
      gate(closed, 'Unterminated schema SQL quote.');
      tokens.push(sql.slice(start, i));
      continue;
    }
    const token =
      /^(?:[A-Za-z_\u0080-\uffff][A-Za-z_0-9$\u0080-\uffff]*|0[xX][0-9a-fA-F](?:_?[0-9a-fA-F])*|(?:\d(?:_?\d)*(?:\.(?:\d(?:_?\d)*)?)?|\.\d(?:_?\d)*)(?:[eE][+-]?\d(?:_?\d)*)?|->>|->|<=|>=|!=|==|<>|\|\||<<|>>|[(),.;+*\/%<>=~&|!-])/.exec(
        rest,
      );
    gate(token, 'Unsupported schema SQL token.');
    tokens.push(token[0]);
    i += token[0].length;
  }
  if (tokens.at(-1) === ';') tokens.pop();
  return tokens;
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
    const sql = row.sql === null ? null : canonicalSql(row.sql as string);
    // Wrangler's ledger may quote only this table identifier. Never rewrite a literal.
    if (
      row.type === 'table' &&
      row.name === 'd1_migrations' &&
      row.tbl_name === 'd1_migrations' &&
      sql?.[0] === 'CREATE' &&
      sql[1] === 'TABLE' &&
      sql[2] === '"d1_migrations"'
    )
      sql[2] = 'd1_migrations';
    return { type: row.type, name: row.name, tbl_name: row.tbl_name, sql };
  });
}
export function expectedInputs(root: string): Inputs {
  const directory = join(root, 'crates/worker/migrations');
  const names = readdirSync(directory).sort();
  gate(
    names.length === LATEST &&
      names.every(
        (name, index) =>
          name.startsWith(`${String(index + 1).padStart(4, '0')}_`) &&
          /^\d{4}_[a-z0-9_]+\.sql$/.test(name),
      ),
    'Expected exactly the reviewed 0001–0035 migration files.',
  );
  gate(
    equal(
      names.slice(BASELINE),
      APPROVED.migrations.map((item) => item.name),
    ),
    'Unexpected approved migration suffix.',
  );
  const migrations: Record<string, string> = {};
  for (const item of APPROVED.migrations) {
    const sql = readFileSync(join(directory, item.name), 'utf8');
    gate(digest(sql) === item.sha256, 'Reviewed migration hash differs.');
    migrations[item.name] = sql;
  }
  const db = new DatabaseSync(':memory:');
  try {
    for (const name of names.slice(0, BASELINE))
      db.exec(readFileSync(join(directory, name), 'utf8'));
    db.exec(ledgerDDL);
    const schemas: Record<number, Row[]> = { [BASELINE]: db.prepare(SCHEMA_SQL).all() };
    for (const [index, item] of APPROVED.migrations.entries()) {
      db.exec(migrations[item.name]!);
      schemas[BASELINE + 1 + index] = db.prepare(SCHEMA_SQL).all();
    }
    return { names, migrations, schemas };
  } finally {
    db.close();
  }
}

export function inspectState(inputs: Inputs, ledger: Row[], schema: Row[]): State {
  gate(
    Number.isSafeInteger(ledger.length) && ledger.length >= BASELINE && ledger.length <= LATEST,
    'Ledger is not the reviewed 0001–0032/0033/0034/0035 prefix; stop for review.',
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
  const expected = canonicalSchema(inputs.schemas[ledger.length]!);
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
  const state = inspectState(inputs, query(LEDGER_SQL), query(SCHEMA_SQL));
  gate(
    equal(query(CURSOR_SQL), [{ id: 1 }]),
    '0032 GC cursor initialization differs; no automatic repair.',
  );
  if (LATEST - state.pending.length >= 34)
    gate(
      equal(query(POLICY_SQL), DORMANT_POLICY),
      '0034 record sharing policy is not the exact disabled initialization; stop for review.',
    );
  return state;
}
export async function inspectComplete(
  run: Run,
  inputs: Inputs,
  get: MetadataGet,
): Promise<FullState> {
  // Finish long metadata inspection before capturing a plan bookmark; repeat it on apply/post-check.
  const compatibility = await inspectWorkerInventory(get, COMPATIBILITY_TARGET);
  const state = inspect(run, inputs);
  return {
    ...state,
    compatibility,
    plan_sha256: digest(JSON.stringify({ database_plan_sha256: state.plan_sha256, compatibility })),
  };
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
    isApprovedSuffix(state.pending),
    'Apply requires a nonempty approved 0033–0035 suffix; use plan to inspect an already-applied database.',
  );
}
export function isApprovedSuffix(pending: string[]) {
  const names = APPROVED.migrations.map((item) => item.name);
  return (
    pending.length > 0 &&
    pending.length <= names.length &&
    equal(pending, names.slice(-pending.length))
  );
}
export function assertFreshBookmark(capturedAt: string, now = Date.now()) {
  const age = now - Date.parse(capturedAt);
  gate(
    Number.isFinite(age) && age >= 0 && age < 120_000,
    'Recorded pre-migration bookmark is stale; prepare a fresh run.',
  );
}
export function applyApprovedSuffix(
  run: Run,
  inputs: Inputs,
  pending: string[],
  temp: string,
  capturedAt: string,
) {
  gate(isApprovedSuffix(pending), 'Only the missing approved suffix may be staged.');
  for (const name of pending) {
    const approved = APPROVED.migrations.find((item) => item.name === name)!;
    gate(
      typeof inputs.migrations[name] === 'string' &&
        digest(inputs.migrations[name]!) === approved.sha256,
      'Staged migration hash differs.',
    );
  }
  const directory = mkdtempSync(join(temp, 'mikaki-0033-0035-'));
  try {
    mkdirSync(join(directory, 'migrations'));
    for (const name of pending)
      writeFileSync(join(directory, 'migrations', name), inputs.migrations[name]!, { mode: 0o600 });
    // Minimal derivative of the pinned production config: same account/DB/ledger,
    // with only the missing approved suffix, even if the ledger races.
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
    // Remote preflight/bookmark reads and local staging can consume the freshness window.
    // Recheck the original retained timestamp at the mutation boundary; never refresh it here.
    assertFreshBookmark(capturedAt);
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
  const claimBytes = readFileSync(join(root, APPROVED.claim_config));
  gate(
    digest(claimBytes) === APPROVED.claim_config_sha256 &&
      claimBytes.equals(readFileSync(join(implementation, APPROVED.claim_config))),
    'Claim production configuration differs; re-review required.',
  );
  const claimConfig = JSON.parse(claimBytes.toString());
  gate(
    config.name === APPROVED.qualified_live.op.name &&
      claimConfig.name === APPROVED.qualified_live.claim.name &&
      claimConfig.account_id === APPROVED.account &&
      claimConfig.d1_databases.length === 1 &&
      claimConfig.d1_databases[0].database_id === APPROVED.database_id,
    'Declared production Worker target differs.',
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
  const getMetadata = cloudflareMetadataGet(APPROVED.account, process.env.CLOUDFLARE_API_TOKEN!);
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
  const planPath = join(artifacts, 'migration-0033-0035-plan.json');
  const resultPath = join(artifacts, 'migration-0033-0035-result.json');
  const identity = {
    workflow_commit: process.env.GITHUB_SHA!,
    run_id: process.env.GITHUB_RUN_ID!,
    run_attempt: process.env.GITHUB_RUN_ATTEMPT!,
  };
  try {
    if (mode === 'plan') {
      const state = await inspectComplete(run, inputs, getMetadata);
      if (process.env.RECONCILE_MODE === 'apply-reviewed')
        applicationGate(state, process.env.APPROVED_PLAN_SHA256, process.env.CONFIRM_APPLY);
      const captured_at = new Date().toISOString();
      const bookmark = bookmarkAt(run, captured_at);
      gate(
        bookmarkAt(run, captured_at) === bookmark,
        'Time Travel timestamp/bookmark readback disagrees.',
      );
      const plan: Plan = { approved: APPROVED, ...identity, captured_at, bookmark, state };
      save(planPath, plan);
      const summary = `0033–0035 migration preflight (no database writes)\nSource: ${APPROVED.source}\nDatabase: ${APPROVED.database} (${APPROVED.database_id})\nPending: ${state.pending.join(', ') || 'none'}\nSchema: reviewed state matches\nCompatibility scope: ordinary account Workers only; Pages Functions and Workers for Platforms were not inventoried.\nPlan SHA-256: ${state.plan_sha256}\nBookmark timestamp: ${captured_at}\nBookmark (read back): ${bookmark}\nThis is a D1 recovery coordinate, not a complete Vault backup or a tested restore.\n`;
      console.log(summary);
      if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, summary);
      return;
    }
    gate(process.env.RECONCILE_MODE === 'apply-reviewed', 'Apply mode was not selected.');
    const plan = JSON.parse(readFileSync(planPath, 'utf8')) as Plan;
    gate(
      equal(plan.approved, APPROVED) &&
        plan.workflow_commit === identity.workflow_commit &&
        plan.run_id === identity.run_id &&
        plan.run_attempt === identity.run_attempt,
      'Preflight record belongs to a different source or run.',
    );
    assertFreshBookmark(plan.captured_at);
    const state = await inspectComplete(run, inputs, getMetadata);
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
      attempted_migrations: state.pending,
    };
    assertFreshBookmark(plan.captured_at);
    save(resultPath, result);
    // The workflow must successfully retain the preflight artifact before this step.
    applyApprovedSuffix(run, inputs, state.pending, temporary, plan.captured_at);
    const after = await inspectComplete(run, inputs, getMetadata);
    gate(after.pending.length === 0, 'Post-application migrations remain pending.');
    result.outcome = 'applied_and_schema_verified';
    result.after = after;
    save(resultPath, result);
    const summary =
      'Approved pending suffix applied; the full reviewed 0001–0035 ledger and exact table/index/trigger definitions match. No migrations pending. No Worker was deployed.\n';
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
      error instanceof GateError || error instanceof InventoryError
        ? error.message
        : 'Reconciliation stopped. No raw response or exception is printed; inspect the retained preflight/result before taking further action.',
    );
    process.exitCode = 1;
  }
}
