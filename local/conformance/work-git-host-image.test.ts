/** Explicit Docker lane: exact bundled Linux entry and fixed private provisioning. */
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { copyJobFixture } from './support/work-copy-job-fixture.ts';
import { prepareGitHostImage } from '../../scripts/prepare-work-git-host.ts';
const exec = promisify(execFile);
test(
  'the Linux image cold-starts without source layers and validates private provisioning',
  { timeout: 240000 },
  async () => {
    const f = await copyJobFixture({ LOCAL_COPY_TRIGGER_DISABLED: 'true' });
    let id: string | undefined;
    try {
      const prepared = await prepareGitHostImage(f.nativeDisclosure, f.sourceBindings, f.directory);
      const tag = 'mikaki-work-git-host:qualification';
      await exec('docker', ['build', '--platform', 'linux/amd64', '-t', tag, prepared.image], {
        timeout: 180000,
        maxBuffer: 4 * 1024 * 1024,
      });
      const image = JSON.parse((await exec('docker', ['image', 'inspect', tag])).stdout)[0];
      id = (
        await exec('docker', [
          'run',
          '--detach',
          '--platform',
          'linux/amd64',
          '--memory',
          '1g',
          '--cpus',
          '1',
          '-p',
          '127.0.0.1::8080',
          '-e',
          'WORK_ARTIFACTS_ACCOUNT=' + 'a'.repeat(32),
          '-e',
          'WORK_ARTIFACTS_NAMESPACE=mikaki-dev',
          '-e',
          'WORK_AUTHORITY_ID=synthetic-managed-work',
          '-e',
          'WORK_GIT_REGISTRY_SHA256=' + prepared.registry_sha256,
          tag,
        ])
      ).stdout.trim();
      const port = (await exec('docker', ['port', id, '8080/tcp'])).stdout
        .trim()
        .split(':')
        .at(-1)!;
      const base = 'http://127.0.0.1:' + port;
      const deadline = Date.now() + 30000;
      for (;;) {
        try {
          const r = await fetch(base + '/health', { signal: AbortSignal.timeout(1000) });
          await r.text();
          if (r.status === 200) break;
        } catch {
          /* wait for process startup only */
        }
        if (Date.now() > deadline) throw new Error('Linux host did not start');
        await new Promise<void>((resolve) => setTimeout(resolve, 200));
      }
      const cold = await fetch(base + '/ready');
      assert.equal(cold.status, 503);
      await cold.text();
      const wrong = await fetch(base + '/provision/registry', { method: 'POST', body: '{}' });
      assert.equal(wrong.status, 409);
      await wrong.text();
      for (const [path, file] of [
        ['registry', 'registry.json'],
        ['task', 'task.pack'],
        ['snapshot', 'snapshot.pack'],
      ] as const) {
        const bytes = await readFile(join(prepared.directory, file));
        if (path === 'snapshot') {
          const changed = Buffer.from(bytes);
          changed[20] = changed[20]! ^ 1;
          const bad = await fetch(base + '/provision/' + path, { method: 'POST', body: changed });
          assert.equal(bad.status, 409);
          await bad.text();
        }
        const r = await fetch(base + '/provision/' + path, { method: 'POST', body: bytes });
        assert.equal(r.status, 204);
        await r.text();
      }
      const activated = await fetch(base + '/provision/activate', { method: 'POST' });
      assert.equal(activated.status, 204);
      await activated.text();
      const ready = await fetch(base + '/ready');
      assert.equal(ready.status, 200);
      assert.deepEqual(await ready.json(), {
        registry_sha256: prepared.registry_sha256,
        disclosure_digest: f.nativeDisclosure.digest,
      });
      const rebind = await fetch(base + '/provision/activate', { method: 'POST' });
      assert.equal(rebind.status, 409);
      await rebind.text();
      const sourceApi = await fetch(base + '/register', { method: 'POST' });
      assert.equal(sourceApi.status, 404);
      await sourceApi.text();
      const logOutput = await exec('docker', ['logs', id]);
      const logs = logOutput.stdout + logOutput.stderr;
      assert.doesNotMatch(logs, /SECRET|Selected context|selected\.md|private\.md/);
      await mkdir('artifacts/work-git-host', { recursive: true });
      await writeFile(
        'artifacts/work-git-host/container.json',
        JSON.stringify(
          {
            ...prepared.receipt,
            image_id: image.Id,
            architecture: image.Architecture,
            platform: image.Os,
            limits: { memory: '1GiB', cpus: 1 },
            checks: [
              'cold-before-provision',
              'wrong-pin-refused',
              'tampered-pack-refused',
              'exact-activation',
              'no-rebinding',
              'no-source-api',
            ],
            scope:
              'Local Docker Linux image; synthetic Native/provider identity. No remote Artifacts call or Cloudflare Container deployment.',
          },
          null,
          2,
        ) + '\n',
      );
    } finally {
      if (id) {
        await exec('docker', ['stop', '--time', '5', id]);
        await exec('docker', ['rm', id]);
      }
      await f.close();
    }
  },
);
