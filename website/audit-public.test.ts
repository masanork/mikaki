import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { auditPublicWebsite, fetchPublicResource } from './audit-public.ts';

const url = 'https://mikaki.org/sitemap.xml';
const noWait = async () => {};

test('public audit retries transport and body failures with bounded backoff', async () => {
  let calls = 0;
  const waits: number[] = [];
  const response = await fetchPublicResource(url, {
    wait: async (ms) => {
      waits.push(ms);
    },
    request: async (input, init) => {
      assert.equal(input, url);
      assert.equal(init?.redirect, 'manual');
      assert.equal(init?.credentials, 'omit');
      assert.ok(init.signal instanceof AbortSignal);
      calls++;
      if (calls === 1) throw new TypeError('private transport details');
      if (calls === 2)
        return new Response(
          new ReadableStream({
            start(controller) {
              controller.error(new TypeError('truncated body'));
            },
          }),
        );
      return new Response('complete', {
        headers: { 'content-type': 'application/xml', 'x-proof': 'kept' },
      });
    },
  });
  assert.equal(await response.text(), 'complete');
  assert.equal(response.headers.get('x-proof'), 'kept');
  assert.equal(calls, 3);
  assert.deepEqual(waits, [250, 500]);
});

test('public audit retries only selected transient HTTP statuses and releases their bodies', async () => {
  for (const status of [408, 429, 502, 503, 504]) {
    let calls = 0;
    let cancelled = false;
    const response = await fetchPublicResource(url, {
      wait: noWait,
      request: async () =>
        ++calls === 1
          ? new Response(
              new ReadableStream({
                cancel() {
                  cancelled = true;
                },
              }),
              { status },
            )
          : new Response('recovered'),
    });
    assert.equal(await response.text(), 'recovered');
    assert.equal(calls, 2);
    assert.equal(cancelled, true);
  }
});

test('persistent failures identify the resource and fail after exactly three attempts', async () => {
  for (const status of [null, 503]) {
    let calls = 0;
    const waits: number[] = [];
    await assert.rejects(
      fetchPublicResource(url, {
        wait: async (ms) => {
          waits.push(ms);
        },
        request: async () => {
          calls++;
          if (status === null) throw new TypeError('sensitive network details');
          return new Response('unavailable', { status });
        },
      }),
      {
        message: `/sitemap.xml: request failed after 3 attempts (${status === null ? 'network error' : 'HTTP 503'})`,
      },
    );
    assert.equal(calls, 3);
    assert.deepEqual(waits, [250, 500]);
  }
});

test(
  'the attempt deadline covers a real HTTP body that never finishes',
  { timeout: 5000 },
  async () => {
    let received = 0;
    const server = createServer((_request, response) => {
      received++;
      response.writeHead(200, { 'content-type': 'application/xml' });
      response.write('<urlset>');
    });
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    try {
      const address = server.address();
      assert.ok(address && typeof address !== 'string');
      let calls = 0;
      await assert.rejects(
        fetchPublicResource(url, {
          timeoutMs: 250,
          wait: noWait,
          request: async (_input, init) => {
            calls++;
            return fetch(`http://127.0.0.1:${address.port}/sitemap.xml`, init);
          },
        }),
        { message: '/sitemap.xml: request failed after 3 attempts (timeout)' },
      );
      assert.equal(calls, 3);
      assert.equal(received, 3);
    } finally {
      server.closeAllConnections();
      await new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      );
    }
  },
);

test('redirects and permanent HTTP failures fail immediately without following a target', async () => {
  for (const status of [301, 302, 307, 400, 401, 403, 404, 500]) {
    let calls = 0;
    await assert.rejects(
      fetchPublicResource(url, {
        wait: async () => assert.fail('must not retry permanent failure'),
        request: async (_input, init) => {
          calls++;
          assert.equal(init?.redirect, 'manual');
          return new Response('', { status, headers: { location: 'https://outside.example/' } });
        },
      }),
      new RegExp(`/sitemap.xml: expected 200, got ${status}`),
    );
    assert.equal(calls, 1);
  }
  for (const input of [
    'https://outside.example/',
    'https://owner:password@mikaki.org/',
    `${url}?token=secret`,
    `${url}#fragment`,
  ])
    await assert.rejects(
      fetchPublicResource(input, { request: async () => assert.fail('out-of-scope request') }),
    );
});

test('invalid successful content is not retried into a passing audit', async () => {
  let calls = 0;
  await assert.rejects(
    auditPublicWebsite((target) =>
      fetchPublicResource(target, {
        wait: async () => assert.fail('must not retry content defects'),
        request: async () => {
          calls++;
          return new Response('<not-a-sitemap/>', {
            headers: { 'content-type': 'application/xml' },
          });
        },
      }),
    ),
    /bounded nonempty sitemap/,
  );
  assert.equal(calls, 1);
});

test('a failed CLI invocation replaces previous passing evidence and exits unsuccessfully', async () => {
  const cwd = await mkdtemp(join(tmpdir(), 'mikaki-public-audit-'));
  try {
    await mkdir(join(cwd, 'artifacts'));
    await writeFile(
      join(cwd, 'artifacts/website-findability.json'),
      JSON.stringify({ status: 'passed' }),
    );
    const preload = `globalThis.fetch = async () => new Response('<invalid/>', { headers: { 'content-type': 'application/xml' } });`;
    const child = spawnSync(
      process.execPath,
      [
        '--import',
        `data:text/javascript,${encodeURIComponent(preload)}`,
        fileURLToPath(new URL('audit-public.ts', import.meta.url)),
      ],
      { cwd, encoding: 'utf8', timeout: 5000 },
    );
    assert.equal(child.status, 1, child.stderr);
    assert.match(child.stderr, /Public website findability failed/);
    const report = JSON.parse(
      await readFile(join(cwd, 'artifacts/website-findability.json'), 'utf8'),
    );
    assert.equal(report.status, 'failed');
    assert.equal(report.origin, 'https://mikaki.org');
    assert.match(report.error, /bounded nonempty sitemap/);
    assert.ok(Number.isFinite(Date.parse(report.checked_at)));
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});
