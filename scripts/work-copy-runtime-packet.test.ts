/** Actual companion bundles, local cold admission, and retained-byte refusals. No remote bindings. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, readFile, rm, symlink, unlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import {
  COPY_RUNTIME_MODULES,
  prepareCopyRuntimePacket,
  verifyCopyRuntimePacket,
} from './work-copy-runtime-packet.ts';

const root = fileURLToPath(new URL('../', import.meta.url));
const parent = join(root, 'local/generated/copy-runtime-tests');
const sha = (b: Buffer) => createHash('sha256').update(b).digest('hex');
const privatePaths: Record<string, string> = {
  copy: '/start',
  initial: '/initial',
  'initial-reconcile': '/reconcile',
  mint: '/mint',
  'mint-reconcile': '/reconcile-mint',
  'mint-close': '/close-mint',
  git: '/git',
  'git-transport': '/git-exchange',
  preparation: '/verify-preparation',
};

test('committed companion packet loads real bundles cold and rejects substitution, extra members and links', async (t) => {
  const packet = await prepareCopyRuntimePacket(parent);
  const expected = { source_commit: packet.source_commit, manifest_sha256: packet.manifest_sha256 };
  try {
    assert.equal((await verifyCopyRuntimePacket(packet.directory, expected)).modules, 14);
    await t.test(
      'real public and named private entrypoints refuse cold requests without provider capabilities',
      async () => {
        const workers = await Promise.all(
          COPY_RUNTIME_MODULES.map(async ([id]) => ({
            name: id,
            modules: true,
            script: await readFile(join(packet.directory, `workers/${id}.mjs`), 'utf8'),
            compatibilityDate: '2026-10-10',
          })),
        );
        const bindings = Object.fromEntries(
          COPY_RUNTIME_MODULES.filter(([id]) => id !== 'checkpoint').map(([id, , entrypoint]) => [
            id.replaceAll('-', '_'),
            { name: id, entrypoint },
          ]),
        );
        const mf = new Miniflare(
          convertV4MiniflareOptions({
            workers: [
              {
                name: 'probe',
                modules: true,
                compatibilityDate: '2026-10-10',
                script: `export default { async fetch(request, env) {
            const [binding, ...path] = new URL(request.url).pathname.slice(1).split('/');
            return env[binding].fetch(new Request('https://private.invalid/' + path.join('/'), {
              method: 'POST', body: JSON.stringify({attempt_id:'a'.repeat(43)})
            }));
          }};`,
                serviceBindings: bindings,
              },
              ...workers,
            ],
          }),
        );
        try {
          for (const [id] of COPY_RUNTIME_MODULES) {
            const r = await (await mf.getWorker(id)).fetch('https://public.invalid/');
            assert.equal(r.status, 404, id);
            assert.equal(await r.text(), '');
          }
          for (const id of Object.keys(bindings)) {
            const path = privatePaths[id.replaceAll('_', '-')] ?? '/';
            const r = await mf.dispatchFetch(`https://probe.invalid/${id}${path}`);
            assert.ok([404, 409, 503].includes(r.status), `${id}: ${r.status}`);
            assert.ok((await r.text()).length <= 4096);
          }
        } finally {
          await mf.dispose();
        }
      },
    );
    await t.test(
      'changed bundle, missing/extra member, source substitution and symlinks cannot pass a retained receipt',
      async () => {
        const target = join(packet.directory, 'workers/copy.mjs');
        const original = await readFile(target);
        await writeFile(target, Buffer.concat([original, Buffer.from('\n// substitution\n')]));
        await assert.rejects(
          verifyCopyRuntimePacket(packet.directory, expected),
          /members_changed/,
        );
        await writeFile(target, original);
        await writeFile(join(packet.directory, 'credentials.json'), '{}');
        await assert.rejects(
          verifyCopyRuntimePacket(packet.directory, expected),
          /members_changed/,
        );
        await unlink(join(packet.directory, 'credentials.json'));
        await unlink(target);
        await assert.rejects(
          verifyCopyRuntimePacket(packet.directory, expected),
          /members_changed/,
        );
        await symlink('../workers/git.mjs', target);
        await assert.rejects(verifyCopyRuntimePacket(packet.directory, expected), /link_denied/);
        await unlink(target);
        await writeFile(target, original);
        await assert.rejects(
          verifyCopyRuntimePacket(packet.directory, {
            ...expected,
            source_commit: 'a'.repeat(40),
          }),
        );
        const input = join(packet.directory, 'inputs/crates/work-effect-worker/worker.ts');
        const source = await readFile(input);
        await writeFile(input, 'different source');
        await assert.rejects(
          verifyCopyRuntimePacket(packet.directory, expected),
          /members_changed/,
        );
        await writeFile(input, source);
        await verifyCopyRuntimePacket(packet.directory, expected);
      },
    );
    await t.test(
      'manifest rewriting cannot reuse the pinned digest or relabel execution authority',
      async () => {
        const path = join(packet.directory, 'manifest.json');
        const original = await readFile(path);
        const value = JSON.parse(original.toString());
        value.prerequisites.execution_authorized = true;
        const changed = Buffer.from(JSON.stringify(value) + '\n');
        await writeFile(path, changed);
        await assert.rejects(
          verifyCopyRuntimePacket(packet.directory, expected),
          /manifest_changed/,
        );
        await assert.rejects(
          verifyCopyRuntimePacket(packet.directory, {
            ...expected,
            manifest_sha256: sha(changed),
          }),
          /authority_denied/,
        );
        await writeFile(path, original);
      },
    );
  } finally {
    await rm(packet.directory, { recursive: true, force: true });
  }
});

test('packet output must remain within ignored local generation and refuse directory links', async () => {
  await assert.rejects(
    prepareCopyRuntimePacket(join(root, 'artifacts/copy-runtime')),
    /output_denied/,
  );
  const target = join(parent, 'target'),
    link = join(parent, 'linked');
  await mkdir(target, { recursive: true });
  await symlink(target, link);
  try {
    await assert.rejects(prepareCopyRuntimePacket(join(link, 'child')), /output_link_denied/);
  } finally {
    await rm(link, { force: true });
    await rm(target, { recursive: true, force: true });
  }
});
