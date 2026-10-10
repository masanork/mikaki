/** Fixed, once-only allocation of the closed Native lane. Never deploys or enrolls. */
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { constants } from 'node:fs';
import { mkdir, mkdtemp, open, realpath } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { z } from 'zod';
import {
  AUTHORITY_ACCOUNT,
  AUTHORITY_TARGET,
  digest,
  packetFile,
  verifyAuthorityPacket,
} from './work-authority-packet.ts';

const root = fileURLToPath(new URL('../', import.meta.url));
const base = `/accounts/${AUTHORITY_ACCOUNT}`;
export const REVIEWED_AUTHORITY_MANIFEST =
  '5b06b4588934813995f965bf5e76da9c44d7e08c98045519192f888bdd2a02d3';
const selectedPacket = 'local/generated/work-authority-qualification/authority-nMECMX';
const allocationDirectory = 'local/generated/work-authority-allocation';
const uuid = z.string().uuid();
const providerId = z.string().regex(/^[a-f0-9]{32}$/);
const timestamp = z
  .string()
  .max(40)
  .refine((v) => Number.isFinite(Date.parse(v)));
const envelope = z.object({
  success: z.boolean().optional(),
  errors: z
    .array(z.object({ code: z.number().int() }))
    .max(16)
    .optional(),
  result: z.unknown().optional(),
  result_info: z.unknown().optional(),
});
const database = z.object({ uuid, name: z.string().max(128), created_at: timestamp });
const bucket = z.object({
  name: z.string().max(64),
  creation_date: timestamp,
  jurisdiction: z.literal('default').optional(),
});
const queue = z.object({
  queue_id: providerId,
  queue_name: z.string().max(128),
  created_on: timestamp,
  consumers: z.array(z.unknown()).max(128),
  producers: z.array(z.unknown()).max(128),
  consumers_total_count: z.number().int().nonnegative(),
  producers_total_count: z.number().int().nonnegative(),
});
export type AuthorityResource = 'database' | 'vault' | 'logout_dlq' | 'logout_queue';
const resources: readonly AuthorityResource[] = ['database', 'vault', 'logout_dlq', 'logout_queue'];
export type AllocationAPI = (
  method: 'GET' | 'POST',
  path: string,
  body?: unknown,
) => Promise<{ status: number; value: unknown }>;
export type AllocationRecord = (value: unknown) => Promise<void>;

function project(resource: AuthorityResource, value: unknown) {
  if (resource === 'database') {
    const d = database.parse(value);
    assert.notEqual(d.uuid, 'd0258938-0d27-4110-8aa9-c82e20f3885b', 'production_database_denied');
    assert.equal(d.name, AUTHORITY_TARGET.database, 'allocation_identity_changed');
    return { resource, name: d.name, id: d.uuid, created_at: d.created_at };
  }
  if (resource === 'vault') {
    const b = bucket.parse(value);
    assert.equal(b.name, AUTHORITY_TARGET.vault, 'allocation_identity_changed');
    return { resource, name: b.name, id: b.name, created_at: b.creation_date };
  }
  const q = queue.parse(value);
  assert.equal(q.queue_name, AUTHORITY_TARGET[resource], 'allocation_identity_changed');
  assert.equal(q.consumers_total_count, 0, 'allocation_queue_attached');
  assert.equal(q.producers_total_count, 0, 'allocation_queue_attached');
  assert.deepEqual(q.consumers, [], 'allocation_queue_attached');
  assert.deepEqual(q.producers, [], 'allocation_queue_attached');
  return { resource, name: q.queue_name, id: q.queue_id, created_at: q.created_on };
}
type Identity = ReturnType<typeof project>;
function success(response: Awaited<ReturnType<AllocationAPI>>) {
  const e = envelope.parse(response.value);
  assert.ok(
    response.status >= 200 && response.status < 300 && e.success !== false,
    'allocation_api_refused',
  );
  assert.equal(e.errors?.length ?? 0, 0, 'allocation_api_refused');
  return e;
}
function createRequest(resource: AuthorityResource) {
  if (resource === 'database')
    return { path: `${base}/d1/database`, body: { name: AUTHORITY_TARGET.database } };
  if (resource === 'vault')
    return { path: `${base}/r2/buckets`, body: { name: AUTHORITY_TARGET.vault } };
  return { path: `${base}/queues`, body: { queue_name: AUTHORITY_TARGET[resource] } };
}

/** Complete bounded pages; an existing name is a collision, never an adoption. */
export async function authorityResourceInventory(api: AllocationAPI) {
  const found: Identity[] = [];
  for (const kind of ['database', 'queues'] as const) {
    let complete = false;
    const seen = new Set<string>();
    for (let page = 1; page <= 8; page++) {
      const path =
        kind === 'database'
          ? `${base}/d1/database?per_page=100&page=${page}`
          : `${base}/queues?page=${page}`;
      const e = success(await api('GET', path));
      const rows = z
        .array(kind === 'database' ? database : queue)
        .max(100)
        .parse(e.result);
      for (const row of rows) {
        const id = 'uuid' in row ? row.uuid : row.queue_id;
        assert.ok(!seen.has(id), 'allocation_inventory_repeated');
        seen.add(id);
        const name = 'name' in row ? row.name : row.queue_name;
        for (const resource of resources)
          if (
            (kind === 'database') === (resource === 'database') &&
            resource !== 'vault' &&
            name === AUTHORITY_TARGET[resource]
          )
            found.push(project(resource, row));
      }
      if (!rows.length) {
        complete = true;
        break;
      }
    }
    assert.ok(complete, 'allocation_inventory_incomplete');
  }
  let cursor: string | undefined;
  let complete = false;
  const cursors = new Set<string>();
  const names = new Set<string>();
  for (let page = 1; page <= 8; page++) {
    const query = new URLSearchParams({ per_page: '100', order: 'name', direction: 'asc' });
    if (cursor) query.set('cursor', cursor);
    const e = success(await api('GET', `${base}/r2/buckets?${query}`));
    const rows = z.object({ buckets: z.array(bucket).max(100) }).parse(e.result).buckets;
    for (const row of rows) {
      assert.ok(!names.has(row.name), 'allocation_inventory_repeated');
      names.add(row.name);
      if (row.name === AUTHORITY_TARGET.vault) found.push(project('vault', row));
    }
    const info = z
      .object({ cursor: z.string().max(2048).nullable().optional() })
      .parse(e.result_info ?? {});
    if (!info.cursor) {
      assert.ok(rows.length < 100, 'allocation_inventory_incomplete');
      complete = true;
      break;
    }
    assert.ok(!cursors.has(info.cursor), 'allocation_inventory_repeated');
    cursors.add(info.cursor);
    cursor = info.cursor;
  }
  assert.ok(complete, 'allocation_inventory_incomplete');
  const workers = [];
  for (const name of [AUTHORITY_TARGET.op, AUTHORITY_TARGET.checkpoint]) {
    const response = await api('GET', `${base}/workers/scripts/${name}/settings`);
    const e = envelope.parse(response.value);
    if (
      response.status === 404 &&
      e.success === false &&
      e.errors?.length === 1 &&
      e.errors[0]!.code === 10007
    ) {
      workers.push({ name, present: false });
    } else {
      success(response);
      workers.push({ name, present: true });
    }
  }
  found.sort((a, b) => a.resource.localeCompare(b.resource));
  assert.equal(
    new Set(found.map((f) => f.resource)).size,
    found.length,
    'allocation_name_ambiguous',
  );
  return { resources: found, workers };
}

async function stableInventory(api: AllocationAPI) {
  const a = await authorityResourceInventory(api);
  assert.deepEqual(await authorityResourceInventory(api), a, 'allocation_inventory_changed');
  return a;
}
async function observe(api: AllocationAPI, identity: Identity) {
  const path =
    identity.resource === 'database'
      ? `${base}/d1/database/${identity.id}`
      : identity.resource === 'vault'
        ? `${base}/r2/buckets/${identity.id}`
        : `${base}/queues/${identity.id}`;
  const actual = project(identity.resource, success(await api('GET', path)).result);
  assert.deepEqual(actual, identity, 'allocation_identity_changed');
  return actual;
}

/** reserve() must be an exclusive durable account/lane reservation, never removed. */
export async function allocateAuthorityResources(
  api: AllocationAPI,
  record: AllocationRecord,
  reserve: () => Promise<void>,
) {
  const before = await stableInventory(api);
  assert.deepEqual(before.resources, [], 'allocation_name_already_exists');
  assert.ok(
    before.workers.every((w) => !w.present),
    'allocation_worker_already_exists',
  );
  await reserve();
  await record({ event: 'reserved', account_id: AUTHORITY_ACCOUNT, target: AUTHORITY_TARGET });
  assert.deepEqual(await stableInventory(api), before, 'allocation_inventory_changed');
  const allocated: Identity[] = [];
  for (const resource of resources) {
    const current = await stableInventory(api);
    assert.deepEqual(
      current.resources,
      [...allocated].sort((a, b) => a.resource.localeCompare(b.resource)),
      'allocation_inventory_changed',
    );
    assert.deepEqual(current.workers, before.workers, 'allocation_inventory_changed');
    const request = createRequest(resource);
    // Once this record is synced, a lost reply consumes the slot, including a process crash.
    await record({ event: 'create_intent', resource, method: 'POST', ...request });
    let identity: Identity;
    try {
      identity = project(resource, success(await api('POST', request.path, request.body)).result);
    } catch {
      await record({ event: 'create_outcome_unknown', resource });
      throw new Error('allocation_create_requires_inspection');
    }
    await record({ event: 'create_observed', identity });
    // Retain the acknowledged identity even if subsequent reads fail; never replace it.
    await observe(api, identity);
    await record({ event: 'identity_verified', identity });
    allocated.push(identity);
  }
  const after = await stableInventory(api);
  assert.deepEqual(
    after.resources,
    [...allocated].sort((a, b) => a.resource.localeCompare(b.resource)),
    'allocation_inventory_changed',
  );
  assert.deepEqual(after.workers, before.workers, 'allocation_inventory_changed');
  await record({ event: 'allocation_complete', resources: allocated });
  return {
    stage: 'resources-allocated-workers-not-deployed-authority-not-enrolled',
    account_id: AUTHORITY_ACCOUNT,
    resources: allocated,
    workers: after.workers,
    checkpoint_namespace_id: null,
    bootstrap_invoked: false,
    owner_enrolled: false,
    production_mutations: 0,
    artifacts_calls: 0,
    provider_creates: 4,
  };
}

/** Append-only exclusive records, fsync both file and parent before crossing a boundary. */
export async function allocationRecordWriter(directory: string) {
  let sequence = 0;
  const parent = await open(
    directory,
    constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
  );
  return {
    async record(value: unknown) {
      const file = await open(
        join(directory, `${String(sequence++).padStart(4, '0')}.json`),
        'wx',
        0o600,
      );
      try {
        await file.writeFile(
          JSON.stringify({ recorded_at: new Date().toISOString(), ...(value as object) }) + '\n',
        );
        await file.sync();
      } finally {
        await file.close();
      }
      await parent.sync();
    },
    async close() {
      await parent.close();
    },
  };
}

function source() {
  const commit = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim();
  assert.match(commit, /^[a-f0-9]{40}$/);
  assert.equal(
    execFileSync('git', ['status', '--porcelain'], { cwd: root, encoding: 'utf8' }).trim(),
    '',
    'allocation_requires_clean_source',
  );
  return commit;
}
async function boundedJSON(response: Response) {
  const reader = response.body?.getReader();
  assert.ok(reader, 'allocation_api_body_absent');
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.length;
      assert.ok(size <= 256 * 1024, 'allocation_api_body_too_large');
      chunks.push(value);
    }
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } finally {
    await reader.cancel();
  }
}
function allowedRead(path: string) {
  const url = new URL(`https://api.cloudflare.com/client/v4${path}`);
  const p = url.pathname.slice('/client/v4'.length);
  if (
    [AUTHORITY_TARGET.op, AUTHORITY_TARGET.checkpoint].some(
      (name) => path === `${base}/workers/scripts/${name}/settings`,
    )
  )
    return true;
  if (p === `${base}/d1/database` || p === `${base}/queues`) {
    const page = url.searchParams.get('page');
    if (!page || !/^[1-8]$/.test(page)) return false;
    return p.endsWith('/queues')
      ? url.search === `?page=${page}`
      : url.search === `?per_page=100&page=${page}`;
  }
  if (p === `${base}/r2/buckets`) {
    const q = url.searchParams;
    return (
      q.get('per_page') === '100' &&
      q.get('order') === 'name' &&
      q.get('direction') === 'asc' &&
      [...q.keys()].every((k) => ['per_page', 'order', 'direction', 'cursor'].includes(k)) &&
      [...q.keys()].length === new Set(q.keys()).size &&
      (q.get('cursor')?.length ?? 0) <= 2048
    );
  }
  return false;
}
export async function runAuthorityAllocation(mode: 'inventory' | 'allocate') {
  const selected = source();
  // All linked checkouts share one retained packet and reservation. A new worktree
  // must not become a new allocation budget after a lost reply in another checkout.
  const commonGit = execFileSync('git', ['rev-parse', '--git-common-dir'], {
    cwd: root,
    encoding: 'utf8',
  }).trim();
  const retainedRoot = dirname(await realpath(resolve(root, commonGit)));
  const packet = join(retainedRoot, selectedPacket);
  assert.equal(await realpath(packet), packet, 'allocation_packet_symlink_denied');
  const manifest = await packetFile(join(packet, 'manifest.json'), 65536);
  assert.equal(
    digest(manifest).sha256,
    REVIEWED_AUTHORITY_MANIFEST,
    'allocation_packet_review_changed',
  );
  const verified = await verifyAuthorityPacket(packet);
  const output = join(retainedRoot, allocationDirectory);
  execFileSync('git', ['check-ignore', output], { cwd: retainedRoot, stdio: 'pipe' });
  await mkdir(output, { recursive: true, mode: 0o700 });
  assert.equal(await realpath(output), output, 'allocation_output_symlink_denied');
  const directory = await mkdtemp(join(output, `${mode}-`));
  const writer = await allocationRecordWriter(directory);
  const ids = new Set<string>();
  const token = process.env.CLOUDFLARE_API_TOKEN;
  assert.ok(token, 'allocation_api_token_unavailable');
  const api: AllocationAPI = async (method, path, body) => {
    if (method === 'POST') {
      assert.equal(mode, 'allocate', 'allocation_read_only');
      assert.ok(
        resources.some((r) => {
          const request = createRequest(r);
          return path === request.path && JSON.stringify(body) === JSON.stringify(request.body);
        }),
        'allocation_mutation_denied',
      );
    } else {
      assert.ok(
        allowedRead(path) ||
          [...ids].some(
            (id) => path === `${base}/d1/database/${id}` || path === `${base}/queues/${id}`,
          ) ||
          path === `${base}/r2/buckets/${AUTHORITY_TARGET.vault}`,
        'allocation_read_denied',
      );
    }
    await writer.record({ event: 'request_intent', method, path });
    const response = await fetch(`https://api.cloudflare.com/client/v4${path}`, {
      method,
      redirect: 'error',
      signal: AbortSignal.timeout(30000),
      headers: {
        Authorization: `Bearer ${token}`,
        ...(method === 'POST' ? { 'Content-Type': 'application/json' } : {}),
      },
      ...(method === 'POST' ? { body: JSON.stringify(body) } : {}),
    });
    await writer.record({ event: 'http_status', method, path, status: response.status });
    const value: unknown = await boundedJSON(response);
    const parsed = envelope.safeParse(value);
    if (!parsed.success) {
      await writer.record({
        event: 'api_shape_invalid',
        method,
        path,
        fields: parsed.error.issues.map((issue) => ({ code: issue.code, path: issue.path })),
      });
      throw new Error('allocation_api_shape_invalid');
    }
    const status = parsed.data;
    await writer.record({
      event: 'api_status',
      method,
      path,
      success: status.success ?? null,
      error_codes: (status.errors ?? []).map((e) => e.code),
    });
    if (method === 'POST') {
      const r = resources.find(
        (r) => JSON.stringify(createRequest(r).body) === JSON.stringify(body),
      )!;
      const identity = project(r, success({ status: response.status, value }).result);
      ids.add(identity.id);
    }
    return { status: response.status, value };
  };
  try {
    await writer.record({
      event: 'selected',
      mode,
      source_commit: selected,
      allocator_sha256: digest(await packetFile(join(root, 'scripts/allocate-work-authority.ts')))
        .sha256,
      packet: selectedPacket,
      manifest_sha256: REVIEWED_AUTHORITY_MANIFEST,
      packet_source: verified.source,
      account_id: AUTHORITY_ACCOUNT,
    });
    const report =
      mode === 'inventory'
        ? await stableInventory(api)
        : await allocateAuthorityResources(api, writer.record, async () => {
            assert.equal(source(), selected, 'allocation_source_changed');
            assert.equal(
              digest(await packetFile(join(packet, 'manifest.json'))).sha256,
              REVIEWED_AUTHORITY_MANIFEST,
            );
            await verifyAuthorityPacket(packet);
            const reservation = await open(join(output, 'reservation.json'), 'wx', 0o600);
            try {
              await reservation.writeFile(
                JSON.stringify({
                  account_id: AUTHORITY_ACCOUNT,
                  target: AUTHORITY_TARGET,
                  packet: selectedPacket,
                  manifest_sha256: REVIEWED_AUTHORITY_MANIFEST,
                  source_commit: selected,
                  journal: directory.slice(retainedRoot.length + 1),
                }) + '\n',
              );
              await reservation.sync();
            } finally {
              await reservation.close();
            }
            const parent = await open(
              output,
              constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
            );
            try {
              await parent.sync();
            } finally {
              await parent.close();
            }
          });
    await writer.record({ event: 'report', mode, report });
    return { directory: directory.slice(retainedRoot.length + 1), mode, report };
  } catch {
    await writer.record({
      event: 'stopped',
      action: 'inspect-same-identities-without-retry-or-reset',
    });
    throw new Error(
      `authority_allocation_stopped; retained=${directory.slice(retainedRoot.length + 1)}`,
    );
  } finally {
    await writer.close();
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [mode, ...rest] = process.argv.slice(2);
  if (!rest.length && (mode === 'inventory' || mode === 'allocate')) {
    runAuthorityAllocation(mode)
      .then((value) => process.stdout.write(JSON.stringify(value, null, 2) + '\n'))
      .catch((error: unknown) => {
        process.stderr.write(
          error instanceof Error ? error.message + '\n' : 'authority_allocation_failed\n',
        );
        process.exitCode = 1;
      });
  } else {
    process.stderr.write('usage: allocate-work-authority.ts inventory|allocate\n');
    process.exitCode = 1;
  }
}
