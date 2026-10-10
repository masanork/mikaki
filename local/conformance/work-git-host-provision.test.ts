/** Real R2 + actual Linux bootstrap contract; the private TCP port is loopback. */
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { Miniflare, convertV4MiniflareOptions, Response as LocalResponse } from 'miniflare';
import { copyJobFixture } from './support/work-copy-job-fixture.ts';
import { materializeGitRegistry } from '../../scripts/work-git-registry.ts';
import { gitHostBootstrap } from '../../scripts/work-git-host-bootstrap.ts';

test('private R2 provisioning rejects substituted bytes before Git-host activation', async () => {
  const f = await copyJobFixture({ LOCAL_COPY_TRIGGER_DISABLED: 'true' });
  let host: Awaited<ReturnType<typeof gitHostBootstrap>> | undefined;
  let mf: Miniflare | undefined;
  try {
    const sealed = await materializeGitRegistry(f.nativeDisclosure, f.sourceBindings, f.directory);
    let base = '';
    const calls: string[] = [];
    const root = fileURLToPath(new URL('../../', import.meta.url));
    const module = await build({
      stdin: {
        contents: `import {provisionGitHost} from './crates/work-git-host-worker/worker.ts'; export default {async fetch(r,e){try {await provisionGitHost(e,e.PORT);return new Response(null,{status:204});}catch{return new Response(null,{status:409});}}}`,
        resolveDir: root,
      },
      bundle: true,
      write: false,
      format: 'esm',
      platform: 'browser',
      external: ['cloudflare:workers'],
      logLevel: 'silent',
    });
    mf = new Miniflare(
      convertV4MiniflareOptions({
        resourcePersistencePath: join(f.directory, 'host-r2'),
        workers: [
          {
            name: 'provision',
            modules: true,
            script: module.outputFiles[0]!.text,
            compatibilityDate: '2026-10-10',
            bindings: {
              WORK_GIT_REGISTRY_SHA256: sealed.registry_sha256,
              WORK_GIT_DISCLOSURE_DIGEST: sealed.registry.disclosure_digest,
            },
            r2Buckets: { GIT_SOURCES: 'synthetic-sealed-sources' },
            serviceBindings: {
              PORT: async (request) => {
                const path = new URL(request.url).pathname;
                assert.match(path, /^\/provision\/(registry|task|snapshot|activate)$/);
                assert.equal(request.headers.has('Authorization'), false);
                calls.push(path);
                const r = await fetch(base + path, {
                  method: request.method,
                  body: request.body ? new Uint8Array(await request.arrayBuffer()) : undefined,
                });
                const bytes = new Uint8Array(await r.arrayBuffer());
                return new LocalResponse(r.status === 204 ? null : bytes, { status: r.status });
              },
            },
          },
        ],
      }),
    );
    const bucket = await mf.getR2Bucket('GIT_SOURCES'),
      prefix = `registry/${sealed.registry_sha256}/`;
    const start = async () => {
      host = await gitHostBootstrap({
        account: 'a'.repeat(32),
        namespace: 'mikaki-dev',
        authority: 'synthetic-managed-work',
        registrySha256: sealed.registry_sha256,
        temporaryParent: f.directory,
      });
      await new Promise<void>((resolve) => host!.server.listen(0, '127.0.0.1', resolve));
      const address = host.server.address();
      assert.ok(address && typeof address !== 'string');
      base = `http://127.0.0.1:${address.port}`;
    };
    await start();
    for (const name of ['registry.json', 'task.pack', 'snapshot.pack'])
      await bucket.put(prefix + name, await readFile(join(sealed.directory, name)));
    await bucket.put(prefix + 'registry.json', '{}');
    let result = await mf.dispatchFetch('https://fixture/provision');
    assert.equal(result.status, 409);
    await result.text();
    assert.equal(calls.length, 0);
    await bucket.put(
      prefix + 'registry.json',
      await readFile(join(sealed.directory, 'registry.json')),
    );
    const changed = Buffer.from(await readFile(join(sealed.directory, 'snapshot.pack')));
    changed[20] = changed[20]! ^ 1;
    await bucket.put(prefix + 'snapshot.pack', changed);
    result = await mf.dispatchFetch('https://fixture/provision');
    assert.equal(result.status, 409);
    await result.text();
    let ready = await fetch(base + '/ready');
    assert.equal(ready.status, 503);
    await ready.text();
    assert.deepEqual(calls, ['/provision/registry', '/provision/task', '/provision/snapshot']);
    await host!.close();
    host = undefined;
    await start();
    calls.length = 0;
    await bucket.put(
      prefix + 'snapshot.pack',
      await readFile(join(sealed.directory, 'snapshot.pack')),
    );
    result = await mf.dispatchFetch('https://fixture/provision');
    assert.equal(result.status, 204);
    await result.text();
    ready = await fetch(base + '/ready');
    assert.equal(ready.status, 200);
    await ready.text();
    assert.deepEqual(calls, [
      '/provision/registry',
      '/provision/task',
      '/provision/snapshot',
      '/provision/activate',
    ]);
    assert.equal((await f.remote()).counts.create ?? 0, 0);
  } finally {
    await host?.close();
    await mf?.dispose();
    await f.close();
  }
});
