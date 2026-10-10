/** Actual private RPC/SQLite retention; local workerd has no Cloudflare Container. */
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import {
  qualificationTargetSchema,
  qualificationImage,
  qualificationObservation,
} from '../../scripts/work-git-host-qualification.ts';
async function fixture(directory: string, vars: Record<string, string> = {}) {
  const root = fileURLToPath(new URL('../../', import.meta.url));
  const built = await build({
    stdin: {
      resolveDir: root,
      contents: `
      import main, {WorkGitHostQualification, GitHostQualificationContainer} from './crates/work-git-host-worker/qualification.ts';
      export {WorkGitHostQualification};
      export class InspectionContainer extends GitHostQualificationContainer {
        inspectQualification() { return {
          attempts: this.ctx.storage.sql.exec('SELECT * FROM qualification_attempt').toArray(),
          frame: this.ctx.storage.sql.exec('SELECT * FROM qualification_frame').toArray(),
          gitTables: this.ctx.storage.sql.exec("SELECT name FROM sqlite_schema WHERE name='host_attempt'").toArray()
        }; }
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
      resourcePersistencePath: join(directory, 'runtime'),
      workers: [
        {
          name: 'qualification',
          modules: true,
          script: built.outputFiles[0]!.text,
          compatibilityDate: '2026-10-10',
          bindings: {
            WORK_GIT_HOST_ENABLED: 'false',
            WORK_GIT_PROVISION_ENABLED: 'true',
            WORK_ARTIFACTS_ACCOUNT: 'a'.repeat(32),
            WORK_ARTIFACTS_NAMESPACE: 'mikaki-dev',
            WORK_AUTHORITY_ID: 'mikaki-git-host-qualification-v1',
            WORK_GIT_REGISTRY_SHA256: 'c'.repeat(64),
            WORK_GIT_DISCLOSURE_DIGEST: 'd'.repeat(64),
            ...vars,
          },
          durableObjects: { GIT_HOST: { className: 'InspectionContainer', useSQLite: true } },
        },
        {
          name: 'caller',
          modules: true,
          compatibilityDate: '2026-10-10',
          script: `export default {async fetch(r,e) {
          const path = new URL(r.url).pathname;
          const object = e.GIT_HOST.getByName('mikaki-git-host-qualification-v1:'+'d'.repeat(64));
          if (path === '/inspect') return Response.json(await object.inspectQualification());
          if (path === '/entry-fetch') return e.HOST.fetch(r);
          try {
            const args = await r.json();
            const v = path === '/direct' ? await object.prepare(...args) : await e.HOST.prepare(...args);
            return Response.json(v);
          } catch (error) { return new Response(null, {status: error.message === 'qualification_denied' ? 409 : 500}); }
        }}`,
          serviceBindings: {
            HOST: { name: 'qualification', entrypoint: 'WorkGitHostQualification' },
          },
          durableObjects: {
            GIT_HOST: {
              className: 'InspectionContainer',
              scriptName: 'qualification',
              useSQLite: true,
            },
          },
        },
      ],
    }),
  );
  const call = (path: string, args: unknown[] = []) =>
    mf.dispatchFetch('https://fixture' + path, {
      method: 'POST',
      headers: { 'MF-Route-Override': 'caller', 'Content-Type': 'application/json' },
      body: JSON.stringify(args),
    });
  const denied = async (args: unknown[] = [], direct = false) => {
    const r = await call(direct ? '/direct' : '/prepare', args);
    assert.equal(r.status, 409);
    await r.text();
  };
  const inspect = async () => {
    const r = await call('/inspect');
    assert.equal(r.status, 200);
    return (await r.json()) as {
      attempts: { ordinal: number }[];
      frame: unknown[];
      gitTables: unknown[];
    };
  };
  return { mf, call, denied, inspect };
}
test('qualification refuses public ingress, arguments and productive flags before admission', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'mikaki-host-qualification-'));
  let f: Awaited<ReturnType<typeof fixture>> | undefined;
  try {
    f = await fixture(dir);
    assert.equal(
      (await f.mf.dispatchFetch('https://fixture/git-execute', { method: 'POST' })).status,
      404,
    );
    assert.equal((await f.call('/entry-fetch')).status, 404);
    await f.denied([{ registry: 'other' }]);
    await f.denied([{ role: 'task' }], true);
    assert.deepEqual((await f.inspect()).attempts, []);
    await f.mf.dispose();
    f = await fixture(dir, { WORK_GIT_HOST_ENABLED: 'true' });
    await f.denied();
    assert.deepEqual((await f.inspect()).attempts, []);
    await f.mf.dispose();
    f = await fixture(dir, { WORK_GIT_PROVISION_ENABLED: 'false' });
    await f.denied();
    assert.deepEqual((await f.inspect()).attempts, []);
  } finally {
    await f?.mf.dispose();
    await rm(dir, { recursive: true, force: true });
  }
});
test('unknown Container startup consumes the bounded probe budget across runtime restart', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'mikaki-host-qualification-'));
  let f: Awaited<ReturnType<typeof fixture>> | undefined;
  try {
    f = await fixture(dir);
    await f.denied();
    assert.deepEqual((await f.inspect()).attempts, [{ ordinal: 1 }]);
    await f.mf.dispose();
    f = await fixture(dir);
    for (let i = 0; i < 3; i++) await f.denied();
    const state = await f.inspect();
    assert.deepEqual(state.attempts, [{ ordinal: 1 }, { ordinal: 2 }, { ordinal: 3 }]);
    assert.equal(state.frame.length, 1);
    assert.deepEqual(state.gitTables, []);
  } finally {
    await f?.mf.dispose();
    await rm(dir, { recursive: true, force: true });
  }
});
test('a registry change cannot rebind the retained qualification frame', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'mikaki-host-qualification-'));
  let f: Awaited<ReturnType<typeof fixture>> | undefined;
  try {
    f = await fixture(dir);
    await f.denied();
    const original = await f.inspect();
    await f.mf.dispose();
    f = await fixture(dir, { WORK_GIT_REGISTRY_SHA256: 'e'.repeat(64) });
    await f.denied();
    assert.deepEqual(await f.inspect(), original);
  } finally {
    await f?.mf.dispose();
    await rm(dir, { recursive: true, force: true });
  }
});
test('infra observations reject substituted pins, foreign images and authority claims', () => {
  const target = qualificationTargetSchema.parse({
    format_version: 1,
    account_id: 'a'.repeat(32),
    worker: 'mikaki-work-git-host-qualification',
    bucket: 'mikaki-work-git-host-qualification',
    namespace: 'mikaki-dev',
    authority: 'mikaki-git-host-qualification-v1',
    disclosure_digest: 'd'.repeat(64),
    registry_sha256: 'c'.repeat(64),
    source_commit: 'f'.repeat(40),
    source_clean: true,
    host_sha256: 'a'.repeat(64),
    dockerfile_sha256: 'b'.repeat(64),
    worker_sha256: 'e'.repeat(64),
  });
  const image = `registry.cloudflare.com/${target.account_id}/host@sha256:${'a'.repeat(64)}`;
  const observed = {
    kind: 'git_host_infrastructure',
    ready: true,
    image,
    started: true,
    ordinal: 1,
    registry_sha256: target.registry_sha256,
    disclosure_digest: target.disclosure_digest,
    elapsed_ms: 10,
    internet_enabled: false,
    git_dispatches: 0,
  };
  assert.equal(qualificationImage(target.account_id, image), image);
  assert.deepEqual(qualificationObservation(target, image, 1, true, observed), observed);
  for (const change of [
    { registry_sha256: 'e'.repeat(64) },
    { image: image.replace(target.account_id, 'b'.repeat(32)) },
    { ordinal: 2 },
    { started: false },
    { internet_enabled: true },
    { git_dispatches: 1 },
    { grant: 'invented' },
  ])
    assert.throws(() =>
      qualificationObservation(target, image, 1, true, { ...observed, ...change }),
    );
  assert.throws(() => qualificationImage(target.account_id, image + ':latest'));
  assert.throws(() => qualificationImage('b'.repeat(32), image));
  assert.throws(() => qualificationTargetSchema.parse({ ...target, worker: 'mikaki-auth' }));
  assert.throws(() => qualificationTargetSchema.parse({ ...target, bucket: 'mikaki-auth-vault' }));
});
