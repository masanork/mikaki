import assert from 'node:assert/strict';
import { mkdtemp, readFile, readdir, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import {
  allocateAuthorityResources,
  allocationRecordWriter,
  authorityResourceInventory,
} from './allocate-work-authority.ts';
import type { AllocationAPI, AuthorityResource } from './allocate-work-authority.ts';
import { AUTHORITY_ACCOUNT, AUTHORITY_TARGET } from './work-authority-packet.ts';

const base = `/accounts/${AUTHORITY_ACCOUNT}`;
const time = '2026-10-11T00:00:00.000Z';
function resourceValue(resource: AuthorityResource) {
  if (resource === 'database')
    return {
      name: AUTHORITY_TARGET.database,
      uuid: '11111111-1111-4111-8111-111111111111',
      created_at: time,
    };
  if (resource === 'vault') return { name: AUTHORITY_TARGET.vault, creation_date: time };
  return {
    queue_name: AUTHORITY_TARGET[resource],
    queue_id: (resource === 'logout_queue' ? '2' : '3').repeat(32),
    created_on: time,
    consumers: [],
    producers: [],
    consumers_total_count: 0,
    producers_total_count: 0,
  };
}
function ok(result: unknown, result_info?: unknown) {
  return {
    status: 200,
    value: { success: true, errors: [], result, ...(result_info ? { result_info } : {}) },
  };
}
function provider() {
  const stored = new Map<AuthorityResource, ReturnType<typeof resourceValue>>();
  const creates: AuthorityResource[] = [];
  const calls: { method: string; path: string }[] = [];
  let lose: AuthorityResource | undefined;
  let substituted: AuthorityResource | undefined;
  const api: AllocationAPI = async (method, path, body) => {
    calls.push({ method, path });
    if (method === 'POST') {
      const b = body as { name?: string; queue_name?: string };
      const resource = (['database', 'vault', 'logout_dlq', 'logout_queue'] as const).find(
        (r) => AUTHORITY_TARGET[r] === (b.name ?? b.queue_name),
      );
      assert.ok(resource);
      assert.ok(!stored.has(resource), 'duplicate_create');
      const value = resourceValue(resource);
      stored.set(resource, value);
      creates.push(resource);
      if (lose === resource) throw new Error('lost_reply');
      if (substituted === resource)
        return ok({ ...value, name: 'mikaki-auth', queue_name: 'mikaki-logout-wakeups' });
      return ok(value);
    }
    if (path.includes('/workers/scripts/'))
      return {
        status: 404,
        value: { success: false, errors: [{ code: 10007 }] },
      };
    const url = new URL('https://api.cloudflare.com/client/v4' + path);
    const page = url.searchParams.get('page');
    if (url.pathname.endsWith('/d1/database'))
      return ok(page === '1' && stored.has('database') ? [stored.get('database')] : []);
    if (url.pathname.endsWith('/queues'))
      return ok(
        page === '1'
          ? [...stored.entries()].filter(([r]) => r.startsWith('logout_')).map(([, v]) => v)
          : [],
      );
    if (url.pathname.endsWith('/r2/buckets'))
      return ok({ buckets: stored.has('vault') ? [stored.get('vault')] : [] });
    for (const [resource, value] of stored) {
      const id =
        resource === 'database'
          ? (value as { uuid: string }).uuid
          : resource === 'vault'
            ? AUTHORITY_TARGET.vault
            : (value as { queue_id: string }).queue_id;
      if (path.endsWith('/' + id)) return ok(value);
    }
    throw new Error('unexpected_path');
  };
  return {
    api,
    stored,
    creates,
    calls,
    loseReply(resource: AuthorityResource) {
      lose = resource;
    },
    substitute(resource: AuthorityResource) {
      substituted = resource;
    },
  };
}
test('allocates four exact resources under one durable reservation without activating workers', async () => {
  const p = provider();
  const events: unknown[] = [];
  let reserved = false;
  const api: AllocationAPI = async (method, path, body) => {
    if (method === 'POST') {
      assert.equal(reserved, true);
      const last = events.at(-1) as { event: string; path: string };
      assert.equal(last.event, 'create_intent');
      assert.equal(last.path, path);
    }
    return p.api(method, path, body);
  };
  const report = await allocateAuthorityResources(
    api,
    async (event) => {
      events.push(event);
    },
    async () => {
      reserved = true;
    },
  );
  assert.deepEqual(p.creates, ['database', 'vault', 'logout_dlq', 'logout_queue']);
  assert.equal(report.owner_enrolled, false);
  assert.equal(report.bootstrap_invoked, false);
  assert.equal(report.production_mutations, 0);
  assert.equal(report.artifacts_calls, 0);
  assert.ok(report.workers.every((w) => !w.present));
  assert.ok(p.calls.every(({ path }) => path.startsWith(base)));
});
test('an existing fixed name is never adopted and creates nothing', async () => {
  const p = provider();
  p.stored.set('vault', resourceValue('vault'));
  let reserved = false;
  await assert.rejects(
    allocateAuthorityResources(
      p.api,
      async () => {},
      async () => {
        reserved = true;
      },
    ),
    /already_exists/,
  );
  assert.equal(reserved, false);
  assert.deepEqual(p.creates, []);
});
test('lost create reply consumes the reservation and prevents later resources and rerun', async () => {
  const p = provider();
  p.loseReply('database');
  const events: { event: string }[] = [];
  let reservations = 0;
  const reserve = async () => {
    assert.equal(reservations++, 0, 'reservation_exists');
  };
  await assert.rejects(
    allocateAuthorityResources(
      p.api,
      async (v) => {
        events.push(v as { event: string });
      },
      reserve,
    ),
    /requires_inspection/,
  );
  assert.deepEqual(p.creates, ['database']);
  assert.equal(events.at(-1)!.event, 'create_outcome_unknown');
  await assert.rejects(
    allocateAuthorityResources(p.api, async () => {}, reserve),
    /already_exists/,
  );
  assert.deepEqual(p.creates, ['database']);
  assert.equal(reservations, 1);
});
test('a reservation survives even when a lost response remains invisible to inventory', async () => {
  const p = provider();
  p.loseReply('database');
  let reserved = false;
  const reserve = async () => {
    assert.equal(reserved, false, 'reservation_exists');
    reserved = true;
  };
  await assert.rejects(
    allocateAuthorityResources(p.api, async () => {}, reserve),
    /requires_inspection/,
  );
  p.stored.clear();
  await assert.rejects(
    allocateAuthorityResources(p.api, async () => {}, reserve),
    /reservation_exists/,
  );
  assert.deepEqual(p.creates, ['database']);
});
test('journal write failure prevents the provider boundary', async () => {
  const p = provider();
  await assert.rejects(
    allocateAuthorityResources(
      p.api,
      async (v) => {
        if ((v as { event: string }).event === 'create_intent') throw new Error('disk_full');
      },
      async () => {},
    ),
    /disk_full/,
  );
  assert.deepEqual(p.creates, []);
});
test('substituted provider identity stays unknown and cannot unlock the next resource', async () => {
  const p = provider();
  p.substitute('vault');
  const events: { event: string }[] = [];
  await assert.rejects(
    allocateAuthorityResources(
      p.api,
      async (v) => {
        events.push(v as { event: string });
      },
      async () => {},
    ),
    /requires_inspection/,
  );
  assert.deepEqual(p.creates, ['database', 'vault']);
  assert.equal(events.at(-1)!.event, 'create_outcome_unknown');
});
test('follows R2 cursor and Queue pages; rejects a repeated cursor instead of trusting absence', async () => {
  const p = provider();
  let repeated = false;
  const api: AllocationAPI = async (method, path, body) => {
    const url = new URL('https://api.cloudflare.com/client/v4' + path);
    if (url.pathname.endsWith('/r2/buckets')) {
      if (url.searchParams.has('cursor'))
        return repeated
          ? ok({ buckets: [] }, { cursor: 'next' })
          : ok({ buckets: [resourceValue('vault')] });
      return ok({ buckets: [] }, { cursor: 'next' });
    }
    if (url.pathname.endsWith('/queues') && url.searchParams.get('page') === '1')
      return ok([{ ...resourceValue('logout_queue'), queue_name: 'unrelated' }]);
    if (url.pathname.endsWith('/queues') && url.searchParams.get('page') === '2')
      return ok([resourceValue('logout_dlq')]);
    return p.api(method, path, body);
  };
  const inventory = await authorityResourceInventory(api);
  assert.deepEqual(
    inventory.resources.map((r) => r.resource),
    ['logout_dlq', 'vault'],
  );
  repeated = true;
  await assert.rejects(authorityResourceInventory(api), /inventory_repeated/);
});
test('authorization and worker identity errors do not masquerade as absent workers', async () => {
  const p = provider();
  const api: AllocationAPI = async (method, path, body) =>
    path.includes('/workers/scripts/')
      ? { status: 404, value: { success: false, errors: [{ code: 10000 }] } }
      : p.api(method, path, body);
  await assert.rejects(
    allocateAuthorityResources(
      api,
      async () => {},
      async () => {},
    ),
    /api_refused/,
  );
  assert.deepEqual(p.creates, []);
});
test('records are private and exclusive across reopened writers', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'mikaki-authority-allocation-test-'));
  const writer = await allocationRecordWriter(directory);
  await writer.record({ event: 'create_intent', resource: 'database' });
  await writer.close();
  const reopened = await allocationRecordWriter(directory);
  await assert.rejects(reopened.record({ event: 'replacement' }), { code: 'EEXIST' });
  await reopened.close();
  assert.deepEqual(await readdir(directory), ['0000.json']);
  const file = join(directory, '0000.json');
  assert.equal((await stat(file)).mode & 0o777, 0o600);
  assert.equal(JSON.parse(await readFile(file, 'utf8')).event, 'create_intent');
});
