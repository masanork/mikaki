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
