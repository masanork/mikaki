import assert from 'node:assert/strict';
import test from 'node:test';
import {
  cloudflareMetadataGet,
  inspectWorkerInventory,
  projectBindings,
  type MetadataGet,
} from './production-worker-inventory.ts';
const version = '11111111-1111-4111-8111-111111111111';
const nextVersion = '22222222-2222-4222-8222-222222222222';
const target = {
  account: '4b749427a0c80c547e726a42aff4b6fc',
  database_id: 'f9299d62-2dbf-4bae-ae49-8b75674572d4',
  qualified_source: '04b94d951465f5f5ab02a3c71eaa55bbfe117448',
  op: 'mikaki-auth',
  claim: 'mikaki-auth-claims',
  logout_queue: 'mikaki-logout-wakeups',
  logout_dlq: 'mikaki-logout-wakeups-dlq',
  versions: { op: version, claim: version },
};
const db = { type: 'd1', name: 'DB', database_id: target.database_id };
const envelope = (result: unknown, result_info?: unknown) => ({
  success: true,
  result,
  ...(result_info === undefined ? {} : { result_info }),
});
type Hook = (path: string, value: any, calls: number) => unknown;
function fixture(
  names = [target.op, target.claim],
  hook: Hook = (_path, value) => value,
): MetadataGet {
  const sorted = names.slice().sort();
  const calls = new Map<string, number>();
  return async (path) => {
    calls.set(path, (calls.get(path) ?? 0) + 1);
    const url = new URL('https://fixture.test' + path);
    let value: unknown;
    if (url.pathname.endsWith('/queues')) {
      assert.equal(url.search, '?page=1&per_page=100');
      value = envelope(
        [
          {
            queue_id: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            queue_name: target.logout_queue,
            producers: [{ type: 'worker', script: target.op }],
            consumers_total_count: 1,
            consumers: [
              {
                consumer_id: 'logout-consumer',
                type: 'worker',
                script: 'stale-embedded-shape',
                dead_letter_queue: target.logout_dlq,
                settings: {
                  batch_size: 1,
                  max_wait_time_ms: 1000,
                  max_retries: 3,
                  max_concurrency: 2,
                  retry_delay: 30,
                },
              },
            ],
          },
          {
            queue_id: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            queue_name: target.logout_dlq,
            consumers_total_count: 0,
            consumers: [],
          },
        ],
        { page: 1, per_page: 100, total_count: 2, total_pages: 1 },
      );
    } else if (url.pathname.endsWith('/consumers')) {
      if (url.pathname.endsWith('/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/consumers')) {
        value = envelope(
          [
            {
              consumer_id: 'logout-consumer',
              type: 'worker',
              script: target.op,
              queue_name: target.logout_queue,
              dead_letter_queue: target.logout_dlq,
              settings: {
                batch_size: 1,
                max_wait_time_ms: 1000,
                max_retries: 3,
                max_concurrency: 2,
                retry_delay: 30,
              },
            },
          ],
          { page: 1, per_page: 100, total_count: 1, total_pages: 1 },
        );
      } else {
        value = envelope([], { page: 1, per_page: 100, total_count: 0, total_pages: 0 });
      }
    } else if (url.pathname.endsWith('/scripts')) {
      assert.equal(url.search, '');
      value = envelope(sorted.map((id) => ({ id })));
    } else {
      const name = /\/scripts\/([^/]+)\//.exec(url.pathname)![1]!;
      const bindings = [
        ...(name === target.op ? [db] : []),
        ...(name === target.op
          ? [{ name: 'LOGOUT_QUEUE', type: 'queue', queue_name: target.logout_queue }]
          : []),
        { name: 'PUBLIC_VALUE', type: 'plain_text', text: 'MUST_NOT_APPEAR' },
        { name: 'JSON_VALUE', type: 'json', json: { secret: 'MUST_NOT_APPEAR' } },
        { name: 'SECRET_NAME', type: 'secret_text' },
        ...(name === target.op
          ? [{ name: 'USERINFO_CLAIMS', type: 'service', service: target.claim }]
          : name === target.claim
            ? [
                {
                  name: 'CLAIM_STORE',
                  type: 'service',
                  service: target.op,
                  entrypoint: 'ClaimStore',
                },
              ]
            : []),
      ];
      if (url.pathname.endsWith('/settings')) value = envelope({ bindings });
      else if (url.pathname.endsWith('/deployments'))
        value = envelope({
          deployments: [
            { strategy: 'percentage', versions: [{ version_id: version, percentage: 100 }] },
          ],
        });
      else {
        const id = url.pathname.endsWith('/versions/' + version) ? version : nextVersion;
        assert.ok(url.pathname.endsWith('/versions/' + id));
        value = envelope({
          id,
          annotations: {
            'workers/tag': target.qualified_source.slice(0, 12),
            'workers/message': `main CI ${target.qualified_source}`,
          },
          resources: { bindings },
        });
      }
    }
    return hook(path, value, calls.get(path)!);
  };
}

test('complete single-page roster retains only sanitized ordinary-Worker evidence and explicit scope', async () => {
  const names = [
    ...Array.from({ length: 20 }, (_, n) => `other-${String(n).padStart(2, '0')}`),
    target.op,
    target.claim,
  ];
  const value = await inspectWorkerInventory(fixture(names), target);
  assert.equal(value.workers.length, 22);
  assert.equal(value.scope, 'ordinary_account_workers_only');
  assert.deepEqual(value.not_inventoried, ['pages_functions', 'workers_for_platforms']);
  assert.deepEqual(value.workers[0]!.settings.databases, [
    { name: 'DB', database_id: target.database_id },
  ]);
  assert.deepEqual(value.workers[1]!.settings.databases, []);
  assert.deepEqual(value.workers[1]!.settings.r2_buckets, []);
  assert.deepEqual(value.workers[0]!.settings.queues, [
    { name: 'LOGOUT_QUEUE', queue_name: target.logout_queue },
  ]);
  assert.deepEqual(value.workers[1]!.settings.queues, []);
  assert.deepEqual(value.logout_queues.consumer, {
    script_name: target.op,
    batch_size: 1,
    max_batch_timeout_ms: 1000,
    max_retries: 3,
    max_concurrency: 2,
    retry_delay: 30,
    dead_letter_queue: target.logout_dlq,
  });
  assert.deepEqual(value.workers[1]!.settings.services, [
    { name: 'CLAIM_STORE', service: target.op, entrypoint: 'ClaimStore' },
  ]);
  assert.match(JSON.stringify(value), /USERINFO_CLAIMS/);
  assert.doesNotMatch(
    JSON.stringify(value),
    /MUST_NOT_APPEAR|PUBLIC_VALUE|JSON_VALUE|SECRET_NAME|plain_text|secret_text/,
  );
});

test('live Queue metadata must match the exact OP producer, bounded consumer, and empty DLQ consumer set', async () => {
  for (const mutate of [
    (v: any) => (v.result[0].script = 'other-worker'),
    (v: any) => (v.result[0].queue_name = 'other-queue'),
    (v: any) => (v.result[0].script_name = 'other-worker'),
    (v: any) => (v.result[0].dead_letter_queue = 'other-dlq'),
    (v: any) => (v.result[0].settings.max_concurrency = 10),
    (v: any) => v.result.push({ ...v.result[0] }),
    (v: any) => v.result.push({ script: 'unexpected-consumer' }),
  ]) {
    await assert.rejects(
      inspectWorkerInventory(
        fixture(undefined, (path, value) => {
          if (path.includes('/consumers') && path.includes('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'))
            mutate(value);
          return value;
        }),
        target,
      ),
    );
  }
  await assert.rejects(
    inspectWorkerInventory(
      fixture(undefined, (path, value) => {
        if (path.includes('/queues?')) value.result[1].queue_id = value.result[0].queue_id;
        return value;
      }),
      target,
    ),
  );
  await assert.rejects(
    inspectWorkerInventory(
      fixture(undefined, (path, value) => {
        if (path.endsWith('/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/consumers'))
          value.result.push({ type: 'worker', script: 'unexpected' });
        return value;
      }),
      target,
    ),
  );
  await assert.rejects(
    inspectWorkerInventory(
      fixture(undefined, (path, value) => {
        if (path.endsWith('/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/consumers'))
          value.result_info.total_pages = 1;
        return value;
      }),
      target,
    ),
  );
  await assert.rejects(
    inspectWorkerInventory(
      fixture(undefined, (path, value) => {
        if (path.endsWith('/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/consumers')) delete value.result_info;
        return value;
      }),
      target,
    ),
    /Missing Queue consumer pagination metadata/,
  );
});

test('projection never accesses text/json/secret values', () => {
  for (const type of [
    'plain_text',
    'json',
    'secret_text',
    'worker_loader',
    'vectorize',
    'workflow',
  ]) {
    const binding = { name: 'VALUE', type };
    for (const key of ['text', 'json', 'secret'])
      Object.defineProperty(binding, key, {
        get() {
          throw new Error('private value accessed');
        },
        enumerable: true,
      });
    assert.deepEqual(projectBindings([binding]), {
      databases: [],
      services: [],
      r2_buckets: [],
      queues: [],
    });
  }
});

test('the complete roster accepts exactly 100 Workers and rejects 101', async () => {
  const names = [target.op, target.claim, ...Array.from({ length: 98 }, (_, n) => `other-${n}`)];
  assert.equal((await inspectWorkerInventory(fixture(names), target)).workers.length, 100);
  await assert.rejects(
    inspectWorkerInventory(fixture([...names, 'one-too-many']), target),
    /excessive Worker roster/,
  );
});

test('empty or individually missing production Workers fail before detail inspection', async () => {
  for (const names of [[], [target.op], [target.claim]])
    await assert.rejects(
      inspectWorkerInventory(
        fixture(names, (path, value) => {
          assert.ok(path.endsWith('/scripts'));
          return value;
        }),
        target,
      ),
      /Expected production Workers are absent/,
    );
});

test('roster identities use id, never the opaque tag, and reject any pagination metadata', async () => {
  const value = await inspectWorkerInventory(
    fixture(undefined, (path, value) => {
      if (path.endsWith('/scripts'))
        for (const item of value.result) item.tag = 'opaque-script-tag';
      return value;
    }),
    target,
  );
  assert.deepEqual(
    value.workers.map((worker) => worker.name),
    [target.op, target.claim],
  );
  await assert.rejects(
    inspectWorkerInventory(
      fixture(undefined, (path, value) => {
        if (path.endsWith('/scripts'))
          for (const item of value.result) {
            item.tag = item.id;
            delete item.id;
          }
        return value;
      }),
      target,
    ),
    /Malformed Worker\/binding name/,
  );
  for (const metadata of [null, {}, [], 'unexpected', 0])
    await assert.rejects(
      inspectWorkerInventory(
        fixture(undefined, (path, value) => {
          if (path.endsWith('/scripts')) value.result_info = metadata;
          return value;
        }),
        target,
      ),
      /Unexpected Worker roster pagination/,
    );
});

test('recognized non-D1 binding types never bypass agent or extra-consumer guards', async () => {
  for (const type of ['worker_loader', 'vectorize', 'workflow'])
    for (const endpoint of ['/settings', '/versions/' + version]) {
      await assert.rejects(
        inspectWorkerInventory(
          fixture(undefined, (path, value) => {
            if (path.includes('/scripts/mikaki-auth/') && path.endsWith(endpoint))
              (endpoint === '/settings' ? value.result : value.result.resources).bindings.push({
                name: 'AGENT_ACCESS',
                type,
              });
            return value;
          }),
          target,
        ),
        /AGENT_ACCESS/,
      );
      await assert.rejects(
        inspectWorkerInventory(
          fixture([target.op, target.claim, 'other'], (path, value) => {
            if (path.includes('/scripts/other/') && path.endsWith(endpoint))
              (endpoint === '/settings' ? value.result : value.result.resources).bindings.push(
                { name: 'KNOWN', type },
                db,
              );
            return value;
          }),
          target,
        ),
        /Another ordinary Worker/,
      );
    }
});

test('extra D1 consumers and OP AGENT_ACCESS fail in settings or any active version', async () => {
  for (const endpoint of ['/settings', '/versions/' + version]) {
    await assert.rejects(
      inspectWorkerInventory(
        fixture([target.op, target.claim, 'other'], (path, value) => {
          if (path.includes('/scripts/other/') && path.endsWith(endpoint))
            (endpoint === '/settings' ? value.result : value.result.resources).bindings.push(db);
          return value;
        }),
        target,
      ),
      /Another ordinary Worker/,
    );
    await assert.rejects(
      inspectWorkerInventory(
        fixture(undefined, (path, value) => {
          if (path.includes('/scripts/mikaki-auth/') && path.endsWith(endpoint))
            (endpoint === '/settings' ? value.result : value.result.resources).bindings.push({
              name: 'AGENT_ACCESS',
              type: 'service',
              service: 'hidden-agent',
            });
          return value;
        }),
        target,
      ),
      /AGENT_ACCESS/,
    );
  }
});

test('Claim Worker uses only the named ClaimStore service, never raw D1 or R2', async () => {
  for (const endpoint of ['/settings', '/versions/' + version]) {
    for (const binding of [db, { ...db, database_id: nextVersion }])
      await assert.rejects(
        inspectWorkerInventory(
          fixture(undefined, (path, value) => {
            if (path.includes('/scripts/mikaki-auth-claims/') && path.endsWith(endpoint))
              (endpoint === '/settings' ? value.result : value.result.resources).bindings.push(
                binding,
              );
            return value;
          }),
          target,
        ),
        /Claim Worker must not bind raw D1 storage/,
      );
    await assert.rejects(
      inspectWorkerInventory(
        fixture(undefined, (path, value) => {
          if (path.includes('/scripts/mikaki-auth-claims/') && path.endsWith(endpoint))
            (endpoint === '/settings' ? value.result : value.result.resources).bindings.push({
              name: 'VAULT_BLOBS',
              type: 'r2_bucket',
              bucket_name: 'mikaki-auth-vault',
            });
          return value;
        }),
        target,
      ),
      /Claim Worker must not bind raw R2 storage/,
    );
  }
});

test('denied, duplicate, missing, unknown and excessive rosters fail closed', async () => {
  for (const mutate of [
    (v: any) => {
      delete v.result;
    },
    (v: any) => {
      v.result = Array.from({ length: 101 }, (_, n) => ({ id: `other-${n}` }));
    },
    (v: any) => {
      v.result_info = { page: 1, total_pages: 2 };
    },
    (v: any) => {
      v.result[1].id = v.result[0].id;
    },
    (v: any) => {
      delete v.result[0].id;
    },
    (v: any) => {
      v.result[0].environment_is_default = false;
    },
    (v: any) => {
      v.result[0].environment_name = 'unknown';
    },
    (v: any) => {
      v.success = false;
    },
  ])
    await assert.rejects(
      inspectWorkerInventory(
        fixture(undefined, (path, value) => {
          if (path.endsWith('/scripts')) mutate(value);
          return value;
        }),
        target,
      ),
    );
  await assert.rejects(inspectWorkerInventory(fixture(['other']), target), /absent/);
  await assert.rejects(
    inspectWorkerInventory(
      fixture(undefined, (path, value) => {
        if (path.endsWith('/settings')) throw new Error('denied');
        return value;
      }),
      target,
    ),
    /denied/,
  );
});

test('binding, deployment and roster ambiguity or drift stops planning', async () => {
  for (const mutate of [
    (p: string, v: any) => {
      if (p.endsWith('/settings'))
        v.result.bindings.push({ name: 'UNKNOWN', type: 'future_database' });
    },
    (p: string, v: any) => {
      if (p.endsWith('/settings')) v.result.bindings.push(v.result.bindings[0]);
    },
    (p: string, v: any) => {
      if (p.endsWith('/settings')) delete v.result.bindings;
    },
    (p: string, v: any) => {
      if (p.includes('/versions/')) v.result.id = nextVersion;
    },
    (p: string, v: any) => {
      if (p.includes('/deployments')) v.result.deployments = [];
    },
    (p: string, v: any) => {
      if (p.includes('/deployments')) v.result.deployments[0].versions[0].percentage = 99;
    },
    (p: string, v: any, n: number) => {
      if (p.includes('/deployments') && n > 1)
        v.result.deployments[0].versions[0].version_id = nextVersion;
    },
    (p: string, v: any, n: number) => {
      if (p.endsWith('/settings') && n > 1)
        v.result.bindings.push({ name: 'NEW', type: 'service', service: 'new-target' });
    },
    (p: string, v: any, n: number) => {
      if (p.endsWith('/scripts') && n > 1) v.result[1].id = 'changed';
    },
  ])
    await assert.rejects(
      inspectWorkerInventory(
        fixture(undefined, (p, v, n) => {
          mutate(p, v, n);
          return v;
        }),
        target,
      ),
    );
});

test('transport is fixed-origin GET metadata, with endpoint allowlist and redacted error bodies', async () => {
  const path = `/accounts/${target.account}/workers/scripts/mikaki-auth/settings`;
  let calls = 0;
  const fetcher: typeof fetch = async (url, init) => {
    calls++;
    assert.equal(url, 'https://api.cloudflare.com/client/v4' + path);
    assert.equal(init?.method, 'GET');
    assert.equal(init?.redirect, 'error');
    return new Response(
      JSON.stringify({
        success: false,
        errors: [{ code: 10000, message: 'MUST_NOT_APPEAR' }],
        sensitive: 'MUST_NOT_APPEAR',
      }),
      { status: 403 },
    );
  };
  const get = cloudflareMetadataGet(target.account, 'synthetic-token', fetcher);
  await assert.rejects(get(path), (e: Error) => {
    assert.match(e.message, /403; codes 10000/);
    assert.doesNotMatch(e.message, /MUST_NOT_APPEAR|synthetic-token/);
    return true;
  });
  for (const bad of [
    path.replace('settings', 'secrets'),
    path.replace('/settings', ''),
    'https://evil.test/',
    path + '?redirect=evil',
    `/accounts/${target.account}/workers/scripts?tags=filtered`,
    `/accounts/${target.account}/workers/scripts-search?order_by=name&page=1&per_page=20`,
  ])
    await assert.rejects(get(bad), /Unapproved/);
  assert.equal(calls, 1);
  await assert.rejects(
    cloudflareMetadataGet(target.account, 'synthetic-token', async () => {
      throw new Error('MUST_NOT_APPEAR');
    })(path),
    (e: Error) => {
      assert.doesNotMatch(e.message, /MUST_NOT_APPEAR/);
      return true;
    },
  );
  await assert.rejects(
    cloudflareMetadataGet(
      target.account,
      'synthetic-token',
      async () => new Response('MUST_NOT_APPEAR', { status: 502 }),
    )(path),
    /502: malformed JSON/,
  );
  await assert.rejects(
    cloudflareMetadataGet(
      target.account,
      'synthetic-token',
      async () => new Response('x'.repeat(2 * 1024 * 1024 + 1)),
    )(path),
    /exceeds limit/,
  );
});

test('unknown binding types still require review', () => {
  assert.throws(
    () => projectBindings([{ name: 'UNKNOWN', type: 'future_binding' }]),
    /Unknown Worker binding type/,
  );
});

test('transport allows only the unfiltered full roster endpoint', async () => {
  const path = `/accounts/${target.account}/workers/scripts`;
  const get = cloudflareMetadataGet(target.account, 'synthetic-token', async (url, init) => {
    assert.equal(url, 'https://api.cloudflare.com/client/v4' + path);
    assert.equal(init?.method, 'GET');
    return new Response(JSON.stringify(envelope([{ id: target.op }])));
  });
  assert.deepEqual(await get(path), envelope([{ id: target.op }]));
  const queuePath = `/accounts/${target.account}/queues?page=1&per_page=100`;
  const queueGet = cloudflareMetadataGet(target.account, 'synthetic-token', async (url, init) => {
    assert.equal(url, 'https://api.cloudflare.com/client/v4' + queuePath);
    assert.equal(init?.method, 'GET');
    return new Response(
      JSON.stringify(envelope([], { page: 1, per_page: 100, total_count: 0, total_pages: 1 })),
    );
  });
  assert.deepEqual(
    await queueGet(queuePath),
    envelope([], { page: 1, per_page: 100, total_count: 0, total_pages: 1 }),
  );
  await assert.rejects(queueGet(`/accounts/${target.account}/queues?page=1`), /Unapproved/);
  const consumerPath = `/accounts/${target.account}/queues/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/consumers`;
  const consumerGet = cloudflareMetadataGet(
    target.account,
    'synthetic-token',
    async (url, init) => {
      assert.equal(url, 'https://api.cloudflare.com/client/v4' + consumerPath);
      assert.equal(init?.method, 'GET');
      return new Response(JSON.stringify(envelope([])));
    },
  );
  assert.deepEqual(await consumerGet(consumerPath), envelope([]));
  await assert.rejects(consumerGet(consumerPath + '?page=1'), /Unapproved/);
});

test('source annotations cannot replace exact qualified activation versions', async () => {
  for (const mutate of [
    (v: any) => {
      delete v.result.annotations;
    },
    (v: any) => {
      v.result.annotations['workers/tag'] = '000000000000';
    },
    (v: any) => {
      v.result.annotations['workers/message'] = 'main CI ' + '0'.repeat(40);
    },
  ])
    await assert.rejects(
      inspectWorkerInventory(
        fixture(undefined, (p, v) => {
          if (p.includes('/versions/')) mutate(v);
          return v;
        }),
        target,
      ),
      /source annotation/,
    );
  await assert.rejects(
    inspectWorkerInventory(fixture(), {
      ...target,
      versions: { ...target.versions, claim: nextVersion },
    }),
    /qualified live version/,
  );
});

test('both active versions of an unrelated Worker are checked for the production database', async () => {
  await assert.rejects(
    inspectWorkerInventory(
      fixture([target.op, target.claim, 'other'], (path, value) => {
        if (path.includes('/scripts/other/') && path.includes('/deployments'))
          value.result.deployments[0].versions = [
            { version_id: version, percentage: 50 },
            { version_id: nextVersion, percentage: 50 },
          ];
        if (path.includes('/scripts/other/') && path.endsWith('/versions/' + nextVersion))
          value.result.resources.bindings.push(db);
        return value;
      }),
      target,
    ),
    /Another ordinary Worker/,
  );
});
