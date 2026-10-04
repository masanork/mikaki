import assert from 'node:assert/strict';
import test from 'node:test';
import {
  cloudflareMetadataGet,
  inspectWorkerInventory,
  projectBindings,
  rosterShape,
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
    if (url.pathname.endsWith('/scripts-search')) {
      const page = Number(url.searchParams.get('page'));
      assert.equal(url.searchParams.get('order_by'), 'name');
      assert.equal(url.searchParams.get('per_page'), '20');
      const items = sorted
        .slice((page - 1) * 20, page * 20)
        .map((script_name) => ({ script_name }));
      value = envelope(items, {
        page,
        per_page: 20,
        count: items.length,
        total_count: sorted.length,
        total_pages: Math.ceil(sorted.length / 20),
      });
    } else {
      const name = /\/scripts\/([^/]+)\//.exec(url.pathname)![1]!;
      const bindings = [
        ...([target.op, target.claim].includes(name) ? [db] : []),
        { name: 'PUBLIC_VALUE', type: 'plain_text', text: 'MUST_NOT_APPEAR' },
        { name: 'JSON_VALUE', type: 'json', json: { secret: 'MUST_NOT_APPEAR' } },
        { name: 'SECRET_NAME', type: 'secret_text' },
        ...(name === target.op
          ? [{ name: 'USERINFO_CLAIMS', type: 'service', service: target.claim }]
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

test('complete multi-page roster retains only sanitized ordinary-Worker evidence and explicit scope', async () => {
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
  assert.match(JSON.stringify(value), /USERINFO_CLAIMS/);
  assert.doesNotMatch(
    JSON.stringify(value),
    /MUST_NOT_APPEAR|PUBLIC_VALUE|JSON_VALUE|SECRET_NAME|plain_text|secret_text/,
  );
});

test('projection never accesses text/json/secret values', () => {
  for (const type of ['plain_text', 'json', 'secret_text']) {
    const binding = { name: 'VALUE', type };
    for (const key of ['text', 'json', 'secret'])
      Object.defineProperty(binding, key, {
        get() {
          throw new Error('private value accessed');
        },
        enumerable: true,
      });
    assert.deepEqual(projectBindings([binding]), { databases: [], services: [] });
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

test('denied, duplicate, missing, unknown and excessive roster pages fail closed', async () => {
  for (const mutate of [
    (v: any) => {
      v.result_info = null;
    },
    (v: any) => {
      v.result_info.total_count = 101;
      v.result_info.total_pages = 6;
    },
    (v: any) => {
      v.result_info.page = 2;
    },
    (v: any) => {
      v.result_info.count = 100;
    },
    (v: any) => {
      v.result_info.total_pages = 2;
    },
    (v: any) => {
      v.result[1].script_name = v.result[0].script_name;
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
          if (path.includes('/scripts-search')) mutate(value);
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
      if (p.includes('/scripts-search') && n > 1 && v.result.length > 1)
        v.result[1].script_name = 'changed';
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

function pageOf(path: string) {
  return Number(new URL('https://fixture.test' + path).searchParams.get('page'));
}

test('optional pagination fields can be absent, partial or appear/disappear without treating them as zero', async () => {
  for (const keep of [[], ['page'], ['per_page'], ['count'], ['total_count'], ['total_pages']]) {
    const pages: number[] = [];
    const value = await inspectWorkerInventory(
      fixture(undefined, (path, response) => {
        if (path.includes('/scripts-search')) {
          pages.push(pageOf(path));
          response.result_info = Object.fromEntries(
            keep.map((key) => [key, response.result_info[key]]),
          );
        }
        return response;
      }),
      target,
    );
    assert.equal(value.workers.length, 2);
    assert.deepEqual(pages, [1, 2, 1, 2]);
  }
  for (const omit of [1, 2, 0]) {
    const pages: number[] = [];
    const value = await inspectWorkerInventory(
      fixture(undefined, (path, response) => {
        if (path.includes('/scripts-search')) {
          pages.push(pageOf(path));
          if (omit === 0 || pageOf(path) === omit) delete response.result_info;
        }
        return response;
      }),
      target,
    );
    assert.equal(value.workers.length, 2);
    assert.deepEqual(pages, [1, 2, 1, 2]);
  }
});

test('a short page containing both declared Workers still continues and detects a later D1 consumer', async () => {
  for (const unsafe of [false, true]) {
    const seen: number[] = [];
    const get = fixture([target.op, target.claim, 'other'], (path, response) => {
      if (path.includes('/scripts-search')) {
        const page = pageOf(path);
        seen.push(page);
        delete response.result_info;
        response.result =
          page === 1
            ? [{ script_name: target.op }, { script_name: target.claim }]
            : page === 2
              ? [{ script_name: 'other' }]
              : [];
      }
      if (unsafe && path.includes('/scripts/other/') && path.endsWith('/settings'))
        response.result.bindings.push(db);
      return response;
    });
    if (unsafe) {
      await assert.rejects(inspectWorkerInventory(get, target), /Another ordinary Worker/);
      assert.deepEqual(seen, [1, 2, 3]);
    } else {
      assert.equal((await inspectWorkerInventory(get, target)).workers.length, 3);
      assert.deepEqual(seen, [1, 2, 3, 1, 2, 3]);
    }
  }
});

test('100 Workers need a sixth empty sentinel; a nonempty sixth page or repeated page fails closed', async () => {
  const names = [target.op, target.claim, ...Array.from({ length: 98 }, (_, i) => `other-${i}`)];
  const pages: number[] = [];
  assert.equal(
    (
      await inspectWorkerInventory(
        fixture(names, (path, response) => {
          if (path.includes('/scripts-search')) {
            pages.push(pageOf(path));
            delete response.result_info;
          }
          return response;
        }),
        target,
      )
    ).workers.length,
    100,
  );
  assert.deepEqual(pages, [1, 2, 3, 4, 5, 6, 1, 2, 3, 4, 5, 6]);
  await assert.rejects(
    inspectWorkerInventory(
      fixture([...names, 'last'], (path, response) => {
        if (path.includes('/scripts-search')) delete response.result_info;
        return response;
      }),
      target,
    ),
    /inventory limit/,
  );
  await assert.rejects(
    inspectWorkerInventory(
      fixture(undefined, (path, response) => {
        if (path.includes('/scripts-search')) {
          delete response.result_info;
          response.result = [{ script_name: target.op }, { script_name: target.claim }];
        }
        return response;
      }),
      target,
    ),
    /Duplicate Worker/,
  );
});

test('present metadata is validated even when other fields are omitted', async () => {
  for (const key of ['page', 'per_page', 'count', 'total_count', 'total_pages']) {
    for (const value of [null, 'MUST_NOT_APPEAR', -1, 1.5]) {
      await assert.rejects(
        inspectWorkerInventory(
          fixture(undefined, (path, response) => {
            if (path.includes('/scripts-search')) response.result_info = { [key]: value };
            return response;
          }),
          target,
        ),
        (error: Error) => {
          assert.match(error.message, /malformed/);
          assert.doesNotMatch(error.message, /MUST_NOT_APPEAR/);
          return true;
        },
      );
    }
  }
  await assert.rejects(
    inspectWorkerInventory(
      fixture(undefined, (path, response) => {
        if (path.includes('/scripts-search'))
          response.result_info = { total_count: 3, total_pages: 2 };
        return response;
      }),
      target,
    ),
    /total\/page count/,
  );
  await assert.rejects(
    inspectWorkerInventory(
      fixture(undefined, (path, response) => {
        if (path.includes('/scripts-search')) response.result_info = { total_count: 3 };
        return response;
      }),
      target,
    ),
    /ended before its declared total/,
  );
  await assert.rejects(
    inspectWorkerInventory(
      fixture(undefined, (path, response) => {
        if (path.includes('/scripts-search'))
          response.result_info = { total_count: pageOf(path) === 1 ? 2 : 3 };
        return response;
      }),
      target,
    ),
    /total changed/,
  );
  // Supplying an understated total cannot cause an early stop before a later nonempty page.
  await assert.rejects(
    inspectWorkerInventory(
      fixture(undefined, (path, response) => {
        if (path.includes('/scripts-search')) {
          response.result_info = { total_count: 2 };
          if (pageOf(path) === 2) response.result = [{ script_name: 'other' }];
        }
        return response;
      }),
      target,
    ),
    /exceeds its declared total/,
  );
});

test('shape-only failures never disclose rows, arbitrary keys or field values', async () => {
  const payload = {
    success: true,
    result: { private: 'MUST_NOT_APPEAR' },
    result_info: { page: 'MUST_NOT_APPEAR', secret: 'MUST_NOT_APPEAR' },
    SECRET_ENV: 'MUST_NOT_APPEAR',
  };
  const shape = rosterShape(payload, 1);
  assert.match(shape, /"result":"object"/);
  assert.match(shape, /"page":"string"/);
  assert.doesNotMatch(shape, /MUST_NOT_APPEAR|SECRET_ENV|secret|private/);
  await assert.rejects(
    inspectWorkerInventory(async () => payload, target),
    (error: Error) => {
      assert.match(error.message, /not an array.*Roster shape:/);
      assert.doesNotMatch(error.message, /MUST_NOT_APPEAR|SECRET_ENV|secret|private/);
      return true;
    },
  );
});

test('metadata endpoint allowlist permits only the bounded sixth sentinel page', async () => {
  const calls: string[] = [];
  const get = cloudflareMetadataGet(target.account, 'synthetic-token', async (url) => {
    calls.push(String(url));
    return new Response(JSON.stringify({ success: true, result: [] }));
  });
  const prefix = `/accounts/${target.account}/workers/scripts-search?order_by=name&page=`;
  await get(prefix + '6&per_page=20');
  await assert.rejects(get(prefix + '7&per_page=20'), /Unapproved/);
  assert.equal(calls.length, 1);
  assert.match(calls[0]!, /page=6&per_page=20$/);
});
