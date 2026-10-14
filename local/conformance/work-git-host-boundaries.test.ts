/** Actual SQLite/RPC admission; Linux port responses are explicitly synthetic. */
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import type { GitPlan } from '../../crates/work-effect-worker/protocol.ts';

const basePlan = (): GitPlan => {
  const expiry = Math.floor(Date.now() / 1000) + 120;
  return {
    format_version: 1,
    effect: 'git.upload',
    attempt_id: 'm'.repeat(43),
    digest: 'd'.repeat(64),
    namespace: 'mikaki-dev',
    name: `wk-${'e'.repeat(32)}-code`,
    role: 'task',
    deadline: expiry,
    checkpoint: {
      authority: 'synthetic-managed-work',
      epoch: 'a'.repeat(64),
      sequence: 0,
      tip: 'b'.repeat(64),
    },
    artifacts_account: 'a'.repeat(32),
    purpose: 'upload',
    scope: 'write',
    repo_id: 'repo',
    initial_attempt_id: 'i'.repeat(43),
    key_version: 1,
    key_fingerprint: 'f'.repeat(64),
    preparation_digest: 'c'.repeat(64),
    disclosure_digest: 'b'.repeat(64),
    commit: 'a'.repeat(40),
    tree: 'b'.repeat(40),
    branch: 'work',
    observation: { repo_id: 'repo', token_id: 'mint', scope: 'write', expires_at: expiry },
  };
};
async function fixture(directory: string, vars: Record<string, string> = {}) {
  const root = fileURLToPath(new URL('../../', import.meta.url));
  const built = await build({
    stdin: {
      contents: `
      import { DurableObject } from 'cloudflare:workers';
      import main, { WorkGitHost, checkedGitHostPlan, initializeGitHostStorage, retainGitHostAttempt } from './crates/work-git-host-worker/worker.ts';
      export { WorkGitHost };
      export class FixtureContainer extends DurableObject {
        constructor(ctx, env) { super(ctx, env); initializeGitHostStorage(ctx.storage); }
        async fetch(request) {
          if (new URL(request.url).pathname === '/inspect') return Response.json({
            attempts: this.ctx.storage.sql.exec('SELECT * FROM host_attempt').toArray(),
            frame: this.ctx.storage.sql.exec('SELECT * FROM host_frame').toArray(),
            calls: this.ctx.storage.sql.exec('SELECT count(*) AS n FROM host_attempt').one().n
          });
          try {
            const p = await checkedGitHostPlan(request, this.env);
            await retainGitHostAttempt(this.ctx.storage, this.env, p);
            if (this.env.FIXTURE_LOST === 'true') throw new Error('synthetic lost port reply');
            return Response.json({ method: 'git_push_accepted', commit: p.commit, tree: p.tree, branch: p.branch, commits: 1, objects: 3, object_bytes: 100, inventory_sha256: 'a'.repeat(64), receipt: 'b'.repeat(64) });
          } catch { return new Response(null, {status:409}); }
        }
      }
      export default main;
    `,
      resolveDir: root,
    },
    bundle: true,
    write: false,
    format: 'esm',
    platform: 'browser',
    target: 'es2022',
    external: ['cloudflare:workers'],
    logLevel: 'silent',
  });
  const mf = new Miniflare(
    convertV4MiniflareOptions({
      resourcePersistencePath: join(directory, 'do'),
      workers: [
        {
          name: 'git-host',
          modules: true,
          script: built.outputFiles[0]!.text,
          compatibilityDate: '2026-10-10',
          bindings: {
            WORK_GIT_HOST_ENABLED: 'true',
            WORK_ARTIFACTS_ACCOUNT: 'a'.repeat(32),
            WORK_ARTIFACTS_NAMESPACE: 'mikaki-dev',
            WORK_AUTHORITY_ID: 'synthetic-managed-work',
            WORK_GIT_DISCLOSURE_DIGEST: 'b'.repeat(64),
            WORK_GIT_REGISTRY_SHA256: 'c'.repeat(64),
            ...vars,
          },
          durableObjects: { GIT_HOST: { className: 'FixtureContainer', useSQLite: true } },
        },
        {
          name: 'caller',
          modules: true,
          compatibilityDate: '2026-10-10',
          script: `export default {fetch(r,e){ return e.HOST.fetch(new Request('https://private.invalid'+new URL(r.url).pathname,r)); }}`,
          serviceBindings: { HOST: { name: 'git-host', entrypoint: 'WorkGitHost' } },
        },
        {
          name: 'inspect',
          modules: true,
          compatibilityDate: '2026-10-10',
          script: `export default {fetch(r,e){ return e.GIT_HOST.getByName('synthetic-managed-work:'+'b'.repeat(64)).fetch('http://fixture/inspect'); }}`,
          durableObjects: {
            GIT_HOST: { className: 'FixtureContainer', scriptName: 'git-host', useSQLite: true },
          },
        },
      ],
    }),
  );
  const call = async (p: unknown, path = '/git-execute') => {
    const r = await mf.dispatchFetch('https://fixture' + path, {
      method: 'POST',
      headers: {
        'MF-Route-Override': 'caller',
        Authorization: 'Bearer SYNTHETIC_HOST_SECRET',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(p),
    });
    await r.text();
    return r.status;
  };
  const inspect = async () => {
    const r = await mf.dispatchFetch('http://fixture/inspect', {
      headers: { 'MF-Route-Override': 'inspect' },
    });
    return (await r.json()) as { attempts: { plan: string }[]; frame: unknown[]; calls: number };
  };
  return { mf, call, inspect };
}
test('private host retains one role/purpose dispatch across concurrency and runtime restart', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'mikaki-host-boundary-'));
  let f = await fixture(dir);
  try {
    const p = basePlan();
    const responses = await Promise.all([f.call(p), f.call(p)]);
    assert.deepEqual(responses.sort(), [200, 409]);
    assert.equal((await f.inspect()).calls, 1);
    assert.equal(await f.call({ ...p, attempt_id: 'n'.repeat(43) }), 409);
    assert.doesNotMatch(JSON.stringify(await f.inspect()), /SYNTHETIC_HOST_SECRET/);
    await f.mf.dispose();
    f = await fixture(dir);
    assert.equal(await f.call(p), 409);
    assert.equal((await f.inspect()).calls, 1);
  } finally {
    await f.mf.dispose();
    await rm(dir, { recursive: true, force: true });
  }
});
test('lost port outcome is retained; image registry replacement cannot rebind the host', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'mikaki-host-loss-'));
  let f = await fixture(dir, { FIXTURE_LOST: 'true' });
  try {
    const p = basePlan();
    assert.equal(await f.call(p), 409);
    assert.equal((await f.inspect()).calls, 1);
    await f.mf.dispose();
    f = await fixture(dir);
    assert.equal(await f.call(p), 409);
    await f.mf.dispose();
    f = await fixture(dir, { WORK_GIT_REGISTRY_SHA256: 'd'.repeat(64) });
    const next = {
      ...p,
      attempt_id: 'n'.repeat(43),
      effect: 'git.readback',
      purpose: 'readback',
      scope: 'read',
      observation: { ...p.observation, scope: 'read' },
    };
    assert.equal(await f.call(next), 409);
    assert.equal((await f.inspect()).calls, 1);
  } finally {
    await f.mf.dispose();
    await rm(dir, { recursive: true, force: true });
  }
});
test('default and cold private ingress refuse; account/authority/disclosure/body cannot choose a host', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'mikaki-host-cold-'));
  let f = await fixture(dir);
  try {
    const p = basePlan();
    const publicResponse = await f.mf.dispatchFetch('https://public/git-execute', {
      headers: { 'MF-Route-Override': 'git-host' },
    });
    assert.equal(publicResponse.status, 404);
    await publicResponse.text();
    for (const bad of [
      { ...p, artifacts_account: 'f'.repeat(32) },
      { ...p, disclosure_digest: 'f'.repeat(64) },
      { ...p, checkpoint: { ...p.checkpoint, authority: 'foreign' } },
      { ...p, command: 'git push' },
      { ...p, observation: { ...p.observation, expires_at: 1 } },
    ])
      assert.equal(await f.call(bad), 409);
    assert.equal(await f.call(p, '/register'), 409);
    assert.equal((await f.inspect()).calls, 0);
    await f.mf.dispose();
    f = await fixture(dir, { WORK_GIT_HOST_ENABLED: 'false' });
    assert.equal(await f.call(p), 404);
    assert.equal((await f.inspect()).calls, 0);
  } finally {
    await f.mf.dispose();
    await rm(dir, { recursive: true, force: true });
  }
});

/** Real host admission/storage; container control and port I/O are synthetic. */
async function preflightFixture(
  directory: string,
  failStart = false,
  vars: Record<string, string> = {},
) {
  const root = fileURLToPath(new URL('../../', import.meta.url));
  const built = await build({
    stdin: {
      resolveDir: root,
      contents: `
        import main, { WorkGitHost, GitHostContainer } from './crates/work-git-host-worker/worker.ts';
        import { WorkGitTransport } from './crates/work-effect-worker/git-transport.ts';
        export { WorkGitHost, WorkGitTransport };
        export class InspectionContainer extends GitHostContainer {
          constructor(ctx, env) {
            const c = { running: false, starts: 0, exchanges: 0, calls: [],
              images: {host: 'synthetic-pinned-image'},
              start(options) { this.starts++; if (${failStart}) throw new Error('SYNTHETIC_PRIVATE_PROVIDER_DETAIL'); this.running = true; },
              async inspect() { return { image: this.images.host }; },
              async setInactivityTimeout() {},
              getTcpPort() { return {fetch: async (url, init) => {
                c.calls.push(new URL(url).pathname);
                if (url.endsWith('/health')) return new Response(null,{status:200});
                if (url.endsWith('/ready')) return Response.json({registry_sha256:env.WORK_GIT_REGISTRY_SHA256,disclosure_digest:env.WORK_GIT_DISCLOSURE_DIGEST});
                if (url.endsWith('/git-execute')) {
                  c.exchanges++;
                  const p = JSON.parse(init.body);
                  return Response.json({method:'git_push_accepted',commit:p.commit,tree:p.tree,branch:p.branch,commits:1,objects:3,object_bytes:100,inventory_sha256:'a'.repeat(64),receipt:'b'.repeat(64)});
                }
                throw new Error('synthetic unexpected port path');
              }}; }
            };
            Object.defineProperty(ctx, 'container', {value:c});
            super(ctx, env);
          }
          inspectFixture() { return {
            preflight: this.ctx.storage.sql.exec('SELECT * FROM host_preflight').toArray(),
            ready: this.ctx.storage.sql.exec('SELECT * FROM host_ready').toArray(),
            attempts: this.ctx.storage.sql.exec('SELECT * FROM host_attempt').toArray(),
            starts: this.ctx.container.starts, exchanges: this.ctx.container.exchanges, calls: this.ctx.container.calls
          }; }
          seedUnknownFixture() {
            this.ctx.storage.sql.exec('INSERT INTO host_attempt VALUES(?,?,?,?)','retained-unknown','task','upload','retained-original-plan');
          }
        }
        export default main;`,
    },
    bundle: true,
    write: false,
    format: 'esm',
    platform: 'browser',
    external: ['cloudflare:workers'],
    logLevel: 'silent',
  });
  const mf = new Miniflare(
    convertV4MiniflareOptions({
      resourcePersistencePath: join(directory, 'preflight'),
      workers: [
        {
          name: 'host',
          modules: true,
          script: built.outputFiles[0]!.text,
          compatibilityDate: '2026-10-10',
          bindings: {
            WORK_GIT_HOST_ENABLED: 'true',
            WORK_GIT_TRANSPORT_ENABLED: 'true',
            WORK_ARTIFACTS_ACCOUNT: 'a'.repeat(32),
            WORK_ARTIFACTS_NAMESPACE: 'mikaki-dev',
            WORK_AUTHORITY_ID: 'synthetic-managed-work',
            WORK_GIT_DISCLOSURE_DIGEST: 'b'.repeat(64),
            WORK_GIT_REGISTRY_SHA256: 'c'.repeat(64),
            ...vars,
          },
          durableObjects: { GIT_HOST: { className: 'InspectionContainer', useSQLite: true } },
          serviceBindings: { GIT_EXECUTOR: { name: 'host', entrypoint: 'WorkGitHost' } },
        },
        {
          name: 'caller',
          modules: true,
          compatibilityDate: '2026-10-10',
          script: `export default {async fetch(r,e) {
          const path = new URL(r.url).pathname;
          const object = e.GIT_HOST.getByName('synthetic-managed-work:'+'b'.repeat(64));
          if(path==='/inspect') return Response.json(await object.inspectFixture());
          if(path==='/seed-unknown') { await object.seedUnknownFixture(); return new Response(null,{status:204}); }
          if(path==='/direct') { try {return Response.json(await object.prepare(...await r.json()));} catch {return new Response(null,{status:409});} }
          const request = new Request('https://private.invalid'+path,r);
          return path==='/git-prepare' ? e.TRANSPORT.fetch(request) : e.HOST.fetch(request);
        }}`,
          serviceBindings: {
            HOST: { name: 'host', entrypoint: 'WorkGitHost' },
            TRANSPORT: { name: 'host', entrypoint: 'WorkGitTransport' },
          },
          durableObjects: {
            GIT_HOST: { className: 'InspectionContainer', scriptName: 'host', useSQLite: true },
          },
        },
      ],
    }),
  );
  const call = (path: string, body: unknown, authorization?: string) =>
    mf.dispatchFetch('https://fixture' + path, {
      method: 'POST',
      headers: {
        'MF-Route-Override': 'caller',
        'Content-Type': 'application/json',
        ...(authorization ? { Authorization: authorization } : {}),
      },
      body: JSON.stringify(body),
    });
  const inspect = async () => {
    const r = await call('/inspect', {});
    return (await r.json()) as {
      preflight: unknown[];
      ready: unknown[];
      attempts: unknown[];
      starts: number;
      exchanges: number;
      calls: string[];
    };
  };
  return { mf, call, inspect };
}

test('failed container startup retains preflight without a Git dispatch, including after restart', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'mikaki-host-preflight-fail-'));
  let f = await preflightFixture(dir, true);
  try {
    const request = { disclosure_digest: 'b'.repeat(64) };
    const r = await f.call('/git-prepare', request);
    assert.equal(r.status, 409);
    assert.doesNotMatch(await r.text(), /SYNTHETIC_PRIVATE_PROVIDER_DETAIL/);
    let observed = await f.inspect();
    assert.equal(observed.preflight.length, 1);
    assert.equal(observed.ready.length, 0);
    assert.equal(observed.attempts.length, 0);
    assert.equal(observed.exchanges, 0);
    assert.equal(observed.starts, 1);
    await f.mf.dispose();
    f = await preflightFixture(dir);
    assert.equal((await f.call('/git-prepare', request)).status, 409);
    assert.equal(
      (await f.call('/git-execute', basePlan(), 'Bearer SYNTHETIC_HOST_SECRET')).status,
      409,
    );
    observed = await f.inspect();
    assert.equal(observed.preflight.length, 1);
    assert.equal(observed.ready.length, 0);
    assert.equal(observed.attempts.length, 0);
    assert.equal(observed.starts, 0);
    assert.equal(observed.exchanges, 0);
  } finally {
    await f.mf.dispose();
    await rm(dir, { recursive: true, force: true });
  }
});

test('private preflight accepts only its fixed disclosure and readiness precedes one physical Git use', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'mikaki-host-preflight-ready-'));
  const f = await preflightFixture(dir);
  try {
    for (const bad of [
      { disclosure_digest: 'f'.repeat(64) },
      { disclosure_digest: 'b'.repeat(64), command: 'git push' },
    ])
      assert.equal((await f.call('/git-prepare', bad)).status, 409);
    assert.equal(
      (
        await f.call(
          '/git-prepare',
          { disclosure_digest: 'b'.repeat(64) },
          'Bearer SYNTHETIC_HOST_SECRET',
        )
      ).status,
      409,
    );
    assert.equal((await f.call('/direct', ['caller-source-selector'])).status, 409);
    assert.equal((await f.inspect()).starts, 0);
    const r = await f.call('/git-prepare', { disclosure_digest: 'b'.repeat(64) });
    assert.equal(r.status, 200);
    assert.deepEqual(await r.json(), { ready: true, disclosure_digest: 'b'.repeat(64) });
    const before = await f.inspect();
    assert.equal(before.preflight.length, 1);
    assert.equal(before.ready.length, 1);
    assert.equal(before.attempts.length, 0);
    assert.equal(before.exchanges, 0);
    assert.deepEqual(before.calls, ['/health', '/ready']);
    const p = basePlan();
    assert.equal((await f.call('/git-execute', p, 'Bearer SYNTHETIC_HOST_SECRET')).status, 200);
    assert.equal((await f.call('/git-execute', p, 'Bearer SYNTHETIC_HOST_SECRET')).status, 409);
    assert.equal((await f.call('/git-prepare', { disclosure_digest: 'b'.repeat(64) })).status, 409);
    const after = await f.inspect();
    assert.equal(after.exchanges, 1);
    assert.equal(after.starts, 1);
    assert.equal(after.attempts.length, 1);
    assert.doesNotMatch(JSON.stringify(after), /SYNTHETIC_HOST_SECRET/);
  } finally {
    await f.mf.dispose();
    await rm(dir, { recursive: true, force: true });
  }
});

test('a retained unknown host attempt cannot acquire preflight or start a process', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'mikaki-host-preflight-unknown-'));
  const f = await preflightFixture(dir);
  try {
    assert.equal((await f.call('/seed-unknown', {})).status, 204);
    assert.equal((await f.call('/git-prepare', { disclosure_digest: 'b'.repeat(64) })).status, 409);
    const observed = await f.inspect();
    assert.equal(observed.attempts.length, 1);
    assert.equal(observed.preflight.length, 0);
    assert.equal(observed.ready.length, 0);
    assert.equal(observed.starts, 0);
    assert.equal(observed.exchanges, 0);
  } finally {
    await f.mf.dispose();
    await rm(dir, { recursive: true, force: true });
  }
});
