/** Read-only inventory of the six protected allocations and current OP bindings. */
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, open } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { z } from 'zod';
import { boundedHostFile } from './work-git-registry.ts';
import { ARTIFACTS_ACCOUNT, PROBE_NAMESPACE } from './work-artifacts-git.ts';

const root = fileURLToPath(new URL('../', import.meta.url));
const base = `/accounts/${ARTIFACTS_ACCOUNT}`;
const repos = `${base}/artifacts/namespaces/${PROBE_NAMESPACE}/repos`;
const id = z.string().regex(/^[a-z0-9]{16}$/);
const name = z.string().regex(/^wk-[a-f0-9]{32}-(?:code|snapshot)$/);
const hash = z.string().regex(/^[a-f0-9]{64}$/);
const time = z
  .string()
  .max(40)
  .refine((v) => Number.isFinite(Date.parse(v)));
const state = z.enum(['closed', 'outcome_unknown']);
const tokenSchema = z.strictObject({
  id,
  scope: z.enum(['read', 'write']),
  state: z.enum(['active', 'expired', 'revoked']),
  created_at: time,
  expires_at: time,
});
const repoSchema = z
  .strictObject({
    id,
    name: z.string().regex(/^[a-z0-9-]{1,128}$/),
    description: z.string().max(1024).nullable(),
    default_branch: z.string().regex(/^[A-Za-z0-9._/-]{1,128}$/),
    created_at: time,
    updated_at: time,
    last_push_at: time.nullable(),
    source: z.string().max(1024).nullable(),
    read_only: z.boolean(),
    remote: z.string().max(512),
  })
  .refine(
    (r) =>
      r.remote ===
      `https://${ARTIFACTS_ACCOUNT}.artifacts.cloudflare.net/git/${PROBE_NAMESPACE}/${r.name}.git`,
  )
  .transform(({ description: _description, source: _source, ...metadata }) => metadata);
const cursorInfo = z.strictObject({
  cursor: z.string().max(2048),
  per_page: z.number().int().min(1).max(200),
  count: z.number().int().min(0).max(200),
});
const offsetInfo = z.strictObject({
  page: z.number().int().min(1).max(8),
  per_page: z.literal(100),
  total_pages: z.number().int().min(0).max(8),
  count: z.number().int().min(0).max(100),
  total_count: z.number().int().min(0).max(800),
});
const envelope = z.object({
  success: z.literal(true),
  errors: z.array(z.unknown()).length(0),
  messages: z.array(z.unknown()),
  result: z.unknown(),
  result_info: z.unknown().optional(),
});
export const protectedJournals = [
  {
    directory: 'probe-09Ae4P',
    sha256: 'e943c005794b4688a50c2f458e892245613cb1924354b951bb2654a6aaff2246',
  },
  {
    directory: 'probe-jYdl3a',
    sha256: '080a5860dbb81219d4f6f4da835353a1a9c8bcc67bcd69415c692f3edb261aaa',
  },
  {
    directory: 'probe-zgwc8e',
    sha256: '77933508c30a07cd3dd74259e68a70f887c56d329bfed814471aebca8ad34f48',
  },
] as const;
const allocationSchema = z.strictObject({
  journal: z.enum(['probe-09Ae4P', 'probe-jYdl3a', 'probe-zgwc8e']),
  role: z.enum(['task', 'snapshot']),
  attempt_id: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
  name,
  repo_id: id,
  digest: hash,
  retained_state: state,
  observed_token_id: id.nullable(),
  cleanup_acknowledged: z.boolean(),
});
type Allocation = z.infer<typeof allocationSchema>;
export type ReadAPI = (path: string) => Promise<unknown>;
type RecordEvent = (value: unknown) => Promise<void>;
function result(value: unknown) {
  return envelope.parse(value);
}
export function journalAllocations(directory: Allocation['journal'], bytes: Buffer) {
  const pin = protectedJournals.find((j) => j.directory === directory);
  if (!pin || createHash('sha256').update(bytes).digest('hex') !== pin.sha256)
    throw new Error('protected_journal_changed');
  return projectJournalAllocations(directory, JSON.parse(bytes.toString()));
}
/** Project legacy facts for inspection only; the remote CLI additionally checks fixed file hashes. */
export function projectJournalAllocations(directory: Allocation['journal'], value: unknown) {
  const raw = z
    .object({ format_version: z.literal(1), task: z.unknown(), snapshot: z.unknown() })
    .parse(value);
  return (['task', 'snapshot'] as const).map((role) => {
    const planSchema = z.object({
      attempt_id: z.string(),
      name,
      namespace: z.literal(PROBE_NAMESPACE),
      digest: hash,
      effect: z.literal('repo.create'),
      role: z.literal(role),
      checkpoint: z.object({ authority: z.literal('synthetic-managed-work') }),
    });
    const slot = z
      .object({
        id: z.string(),
        plan: planSchema,
        result: z.object({ attempt_id: z.string(), state, repo_id: id }),
        ledger: z.object({
          plan: planSchema,
          state,
          repo_id: id,
          closure: z.object({ repo_id: id, token_id: id }).nullable(),
          token_observation: z.object({ repo_id: id, token_id: id }).optional(),
          cleanup: z
            .object({ repo_id: id, token_id: id, method: z.literal('revoke_acknowledged') })
            .optional(),
        }),
      })
      .parse(raw[role]);
    if (
      slot.id !== slot.plan.attempt_id ||
      slot.result.attempt_id !== slot.id ||
      slot.ledger.plan.attempt_id !== slot.id ||
      slot.result.repo_id !== slot.ledger.repo_id ||
      slot.result.state !== slot.ledger.state ||
      slot.plan.name !== slot.ledger.plan.name ||
      slot.plan.digest !== slot.ledger.plan.digest
    )
      throw new Error('protected_journal_identity_changed');
    for (const observation of [
      slot.ledger.closure,
      slot.ledger.token_observation,
      slot.ledger.cleanup,
    ])
      if (observation && observation.repo_id !== slot.ledger.repo_id)
        throw new Error('protected_journal_identity_changed');
    const observed =
      slot.ledger.closure?.token_id ?? slot.ledger.token_observation?.token_id ?? null;
    if (slot.ledger.cleanup && slot.ledger.cleanup.token_id !== observed)
      throw new Error('protected_journal_token_changed');
    return allocationSchema.parse({
      journal: directory,
      role,
      attempt_id: slot.id,
      name: slot.plan.name,
      repo_id: slot.ledger.repo_id,
      digest: slot.plan.digest,
      retained_state: slot.ledger.state,
      observed_token_id: observed,
      cleanup_acknowledged: Boolean(slot.ledger.cleanup),
    });
  });
}
export async function repositoryInventory(get: ReadAPI) {
  const found: z.infer<typeof repoSchema>[] = [],
    cursors = new Set<string>();
  let cursor = '';
  for (let page = 0; page < 4; page++) {
    const response = result(
      await get(`${repos}?limit=200${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`),
    );
    const entries = z.array(repoSchema).max(200).parse(response.result);
    const info = cursorInfo.parse(response.result_info);
    if (info.count !== entries.length || found.length + entries.length > 512)
      throw new Error('repository_inventory_incomplete');
    for (const entry of entries) {
      if (found.some((v) => v.id === entry.id || v.name === entry.name))
        throw new Error('repository_inventory_duplicate');
      found.push(entry);
    }
    if (!info.cursor) return found;
    if (cursors.has(info.cursor)) throw new Error('repository_cursor_repeated');
    cursors.add(info.cursor);
    cursor = info.cursor;
  }
  throw new Error('repository_inventory_incomplete');
}
export async function tokenInventory(get: ReadAPI, repoName: string) {
  name.parse(repoName);
  const found: z.infer<typeof tokenSchema>[] = [];
  let total: number | undefined, pages: number | undefined;
  for (let page = 1; page <= 8; page++) {
    const response = result(
      await get(`${repos}/${repoName}/tokens?state=all&per_page=100&page=${page}`),
    );
    const entries = z.array(tokenSchema).max(100).parse(response.result);
    const info = offsetInfo.parse(response.result_info);
    if (
      info.page !== page ||
      info.count !== entries.length ||
      Math.max(1, Math.ceil(info.total_count / 100)) !== Math.max(1, info.total_pages) ||
      (total !== undefined && total !== info.total_count) ||
      (pages !== undefined && pages !== info.total_pages)
    )
      throw new Error('token_inventory_incomplete');
    total = info.total_count;
    pages = info.total_pages;
    for (const entry of entries) {
      if (found.some((v) => v.id === entry.id)) throw new Error('token_inventory_duplicate');
      found.push(entry);
    }
    if (page >= pages) {
      if (found.length !== total) throw new Error('token_inventory_incomplete');
      return found;
    }
  }
  throw new Error('token_inventory_incomplete');
}
export async function inspectAllocations(input: Allocation[], get: ReadAPI, record: RecordEvent) {
  const allocations = z.array(allocationSchema).length(6).parse(input);
  if (
    new Set(allocations.map((a) => a.repo_id)).size !== 6 ||
    new Set(allocations.map((a) => a.name)).size !== 6 ||
    new Set(allocations.map((a) => a.attempt_id)).size !== 6 ||
    new Set(allocations.map((a) => `${a.journal}:${a.role}`)).size !== 6
  )
    throw new Error('protected_allocations_incomplete');
  const inventory = await repositoryInventory(get);
  await record({ event: 'repository_inventory', inventory });
  const observations = [];
  for (const allocation of allocations) {
    const listed = inventory.find((r) => r.id === allocation.repo_id);
    if (!listed || listed.name !== allocation.name)
      throw new Error('protected_repository_mismatch');
    const before = repoSchema.parse(result(await get(`${repos}/${allocation.name}`)).result);
    const expectedRemote = `https://${ARTIFACTS_ACCOUNT}.artifacts.cloudflare.net/git/${PROBE_NAMESPACE}/${allocation.name}.git`;
    if (
      before.id !== allocation.repo_id ||
      before.name !== allocation.name ||
      before.remote !== expectedRemote
    )
      throw new Error('protected_repository_mismatch');
    const tokens = await tokenInventory(get, allocation.name);
    const after = repoSchema.parse(result(await get(`${repos}/${allocation.name}`)).result);
    if (JSON.stringify(before) !== JSON.stringify(after))
      throw new Error('protected_repository_changed');
    const observation = {
      ...allocation,
      repository: before,
      tokens,
      active_tokens: tokens.filter((t) => t.state === 'active').length,
      observed_token: tokens.find((t) => t.id === allocation.observed_token_id) ?? null,
      closure_requalified: false,
      productive_adoption: false,
    };
    await record({ event: 'protected_allocation', observation });
    observations.push(observation);
  }
  const after = await repositoryInventory(get);
  if (JSON.stringify(inventory) !== JSON.stringify(after))
    throw new Error('repository_inventory_changed');
  return {
    inventory_count: inventory.length,
    allocations: observations,
    unknown_attempts: observations.filter((o) => o.retained_state === 'outcome_unknown').length,
  };
}
export function opBindingObservation(value: unknown) {
  const settings = z
    .object({
      bindings: z
        .array(
          z.object({
            name: z.string().regex(/^[A-Z0-9_]{1,128}$/),
            type: z.string().regex(/^[a-z0-9_]{1,64}$/),
          }),
        )
        .max(128),
    })
    .parse(result(value).result);
  const bindings = settings.bindings.map(({ name, type }) => ({ name, type }));
  if (new Set(bindings.map((b) => b.name)).size !== bindings.length)
    throw new Error('op_bindings_duplicate');
  return {
    worker: 'mikaki-auth',
    bindings,
    checkpoint_binding_present: bindings.some(
      (b) => b.name === 'WORK_AUTHORITY_CHECKPOINT' && b.type === 'service',
    ),
    work_bindings: bindings.filter((b) => b.name.startsWith('WORK_')),
    enrollment_qualified: false,
    authority_rpc_invoked: false,
  };
}
async function boundedJSON(response: Response) {
  const reader = response.body?.getReader();
  if (!reader) throw new Error('api_body_absent');
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > 256 * 1024) throw new Error('api_response_too_large');
      chunks.push(value);
    }
    return JSON.parse(Buffer.concat(chunks).toString());
  } finally {
    await reader.cancel();
  }
}
function oauth() {
  const env: NodeJS.ProcessEnv = { ...process.env, WRANGLER_SEND_METRICS: 'false' };
  delete env.CLOUDFLARE_API_TOKEN;
  delete env.CLOUDFLARE_API_KEY;
  delete env.WRANGLER_LOG;
  try {
    const auth = z.object({ type: z.literal('oauth'), token: z.string().min(1).max(8192) }).parse(
      JSON.parse(
        execFileSync(
          process.execPath,
          [
            'node_modules/wrangler/bin/wrangler.js',
            'auth',
            'token',
            '--json',
            '--config',
            'crates/worker/wrangler.production.jsonc',
            '--env-file',
            '/dev/null',
          ],
          {
            cwd: root,
            env,
            encoding: 'utf8',
            stdio: ['ignore', 'pipe', 'pipe'],
            timeout: 30000,
            maxBuffer: 32768,
          },
        ),
      ),
    );
    return auth.token;
  } catch {
    throw new Error('artifacts_oauth_unavailable');
  }
}
async function loadAllocations() {
  const allocations: Allocation[] = [];
  for (const pin of protectedJournals) {
    const bytes = await boundedHostFile(
      join(root, 'local/generated/work-artifacts-effect', pin.directory, 'journal.json'),
      65536,
    );
    allocations.push(...journalAllocations(pin.directory, bytes));
  }
  return allocations;
}
export async function inspectWorkArtifacts() {
  const source = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim();
  if (
    !/^[a-f0-9]{40}$/.test(source) ||
    execFileSync('git', ['status', '--porcelain'], { cwd: root, encoding: 'utf8' }).trim()
  )
    throw new Error('inspection_requires_clean_source');
  const allocations = await loadAllocations();
  const output = join(root, 'local/generated/work-artifacts-inspection');
  execFileSync('git', ['check-ignore', output], { cwd: root, stdio: 'pipe' });
  await mkdir(output, { recursive: true, mode: 0o700 });
  const directory = await mkdtemp(join(output, 'inspection-'));
  const journal = await open(join(directory, 'inspection.jsonl'), 'wx', 0o600);
  const record = async (value: unknown) => {
    await journal.write(JSON.stringify(value) + '\n');
    await journal.sync();
  };
  const started = new Date().toISOString();
  try {
    await record({
      event: 'selected',
      source_commit: source,
      started_at: started,
      account: ARTIFACTS_ACCOUNT,
      namespace: PROBE_NAMESPACE,
      protected_journals: protectedJournals,
      allocations,
      mode: 'read_only',
    });
    let artifactsToken: string | undefined;
    const workersToken = process.env.CLOUDFLARE_API_TOKEN;
    if (!workersToken) throw new Error('workers_api_token_unavailable');
    const allowedNames = new Set(allocations.map((a) => a.name));
    const get: ReadAPI = async (path) => {
      const url = new URL(`https://api.cloudflare.com/client/v4${path}`);
      const suffix = url.pathname.slice(repos.length);
      const parts = suffix.split('/');
      const artifact =
        url.pathname === repos ||
        (url.pathname.startsWith(`${repos}/`) &&
          allowedNames.has(parts[1]) &&
          (parts.length === 2 || (parts.length === 3 && parts[2] === 'tokens')));
      const worker = path === `${base}/workers/scripts/mikaki-auth/settings`;
      if ((!artifact && !worker) || url.origin !== 'https://api.cloudflare.com')
        throw new Error('inspection_target_denied');
      const token = artifact ? artifactsToken : workersToken;
      if (!token) throw new Error('inspection_authentication_unavailable');
      await record({ event: 'read_intent', method: 'GET', path });
      const response = await fetch(url, {
        method: 'GET',
        redirect: 'error',
        signal: AbortSignal.timeout(30000),
        headers: { Authorization: `Bearer ${token}` },
      });
      await record({ event: 'read_status', path, http_status: response.status });
      if (!response.ok) {
        await response.body?.cancel();
        throw new Error('inspection_read_refused');
      }
      return boundedJSON(response);
    };
    const op = opBindingObservation(await get(`${base}/workers/scripts/mikaki-auth/settings`));
    await record({ event: 'op_bindings', observation: op });
    artifactsToken = oauth();
    const repositories = await inspectAllocations(allocations, get, record);
    if (JSON.stringify(await loadAllocations()) !== JSON.stringify(allocations))
      throw new Error('protected_journal_changed');
    const report = {
      format_version: 1,
      source_commit: source,
      started_at: started,
      finished_at: new Date().toISOString(),
      mode: 'read_only',
      account: ARTIFACTS_ACCOUNT,
      namespace: PROBE_NAMESPACE,
      ...repositories,
      op,
      protected_journals_unchanged: true,
      git_calls: 0,
      provider_mutations: 0,
      production_activation: false,
    };
    const file = await open(join(directory, 'result.json'), 'wx', 0o600);
    try {
      await file.write(JSON.stringify(report, null, 2) + '\n');
      await file.sync();
    } finally {
      await file.close();
    }
    await record({ event: 'complete', result_file: 'result.json' });
    return {
      directory,
      inventory_count: report.inventory_count,
      protected_count: report.allocations.length,
      active_tokens: report.allocations.reduce((sum, a) => sum + a.active_tokens, 0),
      unknown_attempts: report.unknown_attempts,
      checkpoint_binding_present: op.checkpoint_binding_present,
      enrollment_qualified: false,
    };
  } catch {
    await record({
      event: 'stopped',
      outcome: 'inspection_incomplete',
      finished_at: new Date().toISOString(),
    });
    throw new Error(`Read-only inspection stopped; retained journal: ${directory}`);
  } finally {
    await journal.close();
  }
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length !== 2) throw new Error('usage: node scripts/inspect-work-artifacts.ts');
    console.log(JSON.stringify(await inspectWorkArtifacts(), null, 2));
  } catch (error) {
    console.error(
      error instanceof Error && error.message.startsWith('Read-only inspection stopped;')
        ? error.message
        : 'Read-only inspection refused; clean source and unchanged protected journals are required.',
    );
    process.exitCode = 1;
  }
}
