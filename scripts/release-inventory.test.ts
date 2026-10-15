import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtemp, mkdir, writeFile, readFile, rm, symlink, truncate } from 'node:fs/promises';
import { writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { collectRelease, verifyRelease, releaseSource } from './release-inventory.ts';
import { prepareReleaseUpload, verifyPreparedUpload } from './prepare-release-upload.ts';

const source = { commit: 'a'.repeat(40), clean: true };
const entries = ['index.js', 'index_bg.wasm', 'package.json', 'worker/shim.mjs'];
async function fixture() {
  const root = await mkdtemp(join(tmpdir(), 'mikaki-release-test-'));
  await mkdir(join(root, 'build/worker'), { recursive: true });
  await mkdir(join(root, 'artifacts'));
  await mkdir(join(root, 'crates/worker/migrations'), { recursive: true });
  await mkdir(join(root, 'crates/userinfo-claim-worker'), { recursive: true });
  await mkdir(join(root, 'crates/work-checkpoint-worker'), { recursive: true });
  await writeFile(
    join(root, 'crates/work-checkpoint-worker/wrangler.production.jsonc'),
    '{"name":"checkpoint"}',
  );
  await writeFile(join(root, 'build/worker/checkpoint.mjs'), 'fixture:worker/checkpoint.mjs');
  await writeFile(join(root, 'crates/worker/wrangler.production.jsonc'), '{"name":"op"}');
  await writeFile(
    join(root, 'crates/userinfo-claim-worker/wrangler.production.jsonc'),
    '{"name":"userinfo"}',
  );
  for (const entry of entries) await writeFile(join(root, 'build', entry), `fixture:${entry}`);
  await writeFile(
    join(root, 'crates/worker/migrations/0001_initial.sql'),
    'CREATE TABLE example(id INTEGER);',
  );
  await writeFile(join(root, 'build/worker/service.mjs'), 'fixture:worker/service.mjs');
  const archive = (names = entries) => {
    for (const name of ['mikaki-worker', 'mikaki-userinfo-claim-worker'])
      execFileSync('tar', [
        '-C',
        join(root, 'build'),
        '-czf',
        join(root, `artifacts/${name}.tar.gz`),
        ...names,
        ...(name === 'mikaki-worker' ? ['worker/service.mjs'] : []),
      ]);
    execFileSync('tar', [
      '-C',
      join(root, 'build'),
      '-czf',
      join(root, 'artifacts/mikaki-work-checkpoint.tar.gz'),
      'worker/checkpoint.mjs',
    ]);
  };
  archive();
  return { root, archive };
}
test('release inventory binds both Workers, source and migration bytes; dirty releases require explicit local mode', async () => {
  const { root } = await fixture();
  try {
    const inventory = await collectRelease(root, source);
    await verifyRelease(root, inventory, source);
    await assert.rejects(verifyRelease(root, inventory, { ...source, commit: 'b'.repeat(40) }));
    const dirty = { ...source, clean: false };
    const local = await collectRelease(root, dirty);
    await assert.rejects(verifyRelease(root, local, dirty), /clean source/);
    await verifyRelease(root, local, dirty, true);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
test('upload preparation stages only verified archive members and records Wrangler bundle bytes', async () => {
  const { root, archive } = await fixture();
  try {
    const inventory = await collectRelease(root, source);
    const fakeBundle = async (entry: string, _config: string, output: string, upload: string) => {
      assert.equal(
        execFileSync('cat', [entry], { encoding: 'utf8' }),
        entry.endsWith('service.mjs')
          ? 'fixture:worker/service.mjs'
          : entry.endsWith('checkpoint.mjs')
            ? 'fixture:worker/checkpoint.mjs'
            : 'fixture:worker/shim.mjs',
      );
      writeFileSync(
        join(
          output,
          entry.endsWith('service.mjs')
            ? 'service.js'
            : entry.endsWith('checkpoint.mjs')
              ? 'checkpoint.js'
              : 'shim.js',
        ),
        'bundled entry',
      );
      if (!entry.endsWith('checkpoint.mjs'))
        writeFileSync(join(output, 'module.wasm'), 'bundled wasm');
      const name = entry.endsWith('service.mjs')
        ? 'service'
        : entry.endsWith('checkpoint.mjs')
          ? 'checkpoint'
          : 'shim';
      writeFileSync(join(output, `${name}.js.map`), 'debug source map excluded from upload size');
      const form = new FormData();
      form.set('metadata', JSON.stringify({ main_module: `${name}.js` }));
      form.set(
        `${name}.js`,
        new Blob(['bundled entry'], { type: 'application/javascript+module' }),
        `${name}.js`,
      );
      if (!entry.endsWith('checkpoint.mjs'))
        form.set(
          'module.wasm',
          new Blob(['bundled wasm'], { type: 'application/wasm' }),
          'module.wasm',
        );
      form.set(
        `${name}.js.map`,
        new Blob(['debug source map excluded from upload size'], {
          type: 'application/source-map',
        }),
        `${name}.js.map`,
      );
      await writeFile(upload, new Uint8Array(await new Response(form).arrayBuffer()));
    };
    const prepared = await prepareReleaseUpload(root, inventory, source, false, fakeBundle);
    assert.equal(prepared.result.promotion_ready, true);
    assert.equal(prepared.result.workers.length, 3);
    assert.equal(prepared.result.workers[0]?.bundle_files.length, 3);
    assert.equal(
      prepared.result.workers[0]?.bundle_raw_bytes,
      Buffer.byteLength('bundled entrybundled wasm'),
    );
    assert.equal(prepared.result.workers[2]?.bundle_raw_bytes, Buffer.byteLength('bundled entry'));
    const changedSize = structuredClone(prepared.result);
    changedSize.workers[0]!.bundle_raw_bytes++;
    await assert.rejects(
      verifyPreparedUpload(root, prepared.destination, changedSize, source),
      /bundle size changed/,
    );
    const uploadPath = join(prepared.destination, 'op/upload.multipart');
    const originalUpload = await readFile(uploadPath);
    await writeFile(uploadPath, Buffer.concat([originalUpload, Buffer.from('changed')]));
    await assert.rejects(
      verifyPreparedUpload(root, prepared.destination, prepared.result, source),
      /Worker upload changed/,
    );
    await writeFile(uploadPath, originalUpload);
    assert.equal(
      (await readFile(join(prepared.destination, 'op/input/index_bg.wasm'))).toString(),
      'fixture:index_bg.wasm',
    );
    await writeFile(
      join(prepared.destination, 'op/bundle/service.js'),
      'changed after preparation',
    );
    await assert.rejects(
      verifyPreparedUpload(root, prepared.destination, prepared.result, source),
      { code: 'ERR_ASSERTION' },
    );
    await rm(prepared.destination, { recursive: true });
    await writeFile(join(root, 'build/index_bg.wasm'), 'changed');
    archive();
    await assert.rejects(
      prepareReleaseUpload(root, inventory, source, false, fakeBundle),
      /do not match/,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
test('changed archives and SQL are rejected against the original inventory', async () => {
  const { root, archive } = await fixture();
  try {
    const inventory = await collectRelease(root, source);
    await writeFile(join(root, 'build/index_bg.wasm'), 'substituted runtime');
    archive();
    await assert.rejects(verifyRelease(root, inventory, source), /do not match/);
    const updated = await collectRelease(root, source);
    await writeFile(join(root, 'crates/worker/migrations/0001_initial.sql'), 'DROP TABLE example;');
    await assert.rejects(verifyRelease(root, updated, source), /do not match/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
test('release inventory rejects a claim Worker built with the conformance pause gate', async () => {
  const { root, archive } = await fixture();
  try {
    await writeFile(join(root, 'build/index_bg.wasm'), 'fixture:CONFORMANCE_GATE');
    archive();
    await assert.rejects(collectRelease(root, source), /Conformance pause gate/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
test('linked archive inputs and oversized archives are rejected before tar inspection', async () => {
  const { root, archive } = await fixture();
  const path = join(root, 'artifacts/mikaki-worker.tar.gz');
  try {
    await rm(path);
    await symlink('mikaki-userinfo-claim-worker.tar.gz', path);
    await assert.rejects(collectRelease(root, source), { code: 'ELOOP' });
    await rm(path);
    archive();
    await truncate(path, 64 * 1024 * 1024 + 1);
    await assert.rejects(collectRelease(root, source), /bounded regular/);
    await rm(path);
    execFileSync('mkfifo', [path]);
    await assert.rejects(collectRelease(root, source), /bounded regular/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
test('release source detection rejects tracked edits and untracked inputs in an actual Git checkout', async () => {
  const { root } = await fixture();
  const git = (args: string[]) => execFileSync('git', ['-C', root, ...args], { stdio: 'pipe' });
  try {
    await writeFile(join(root, '.gitignore'), '/artifacts/\n');
    git(['init', '--quiet']);
    git(['add', '.gitignore', 'build', 'crates']);
    git([
      '-c',
      'user.name=fixture',
      '-c',
      'user.email=fixture@example.invalid',
      '-c',
      'commit.gpgsign=false',
      'commit',
      '--quiet',
      '-m',
      'disposable fixture',
    ]);
    assert.equal(releaseSource(root).clean, true);
    await writeFile(join(root, 'build/index.js'), 'edited runtime');
    assert.equal(releaseSource(root).clean, false);
    await writeFile(join(root, 'build/index.js'), 'fixture:index.js');
    assert.equal(releaseSource(root).clean, true);
    await writeFile(join(root, 'new-source.ts'), 'untracked input');
    assert.equal(releaseSource(root).clean, false);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
test('unexpected, duplicate, linked archive entries and incomplete migrations are rejected before use', async () => {
  const { root, archive } = await fixture();
  try {
    await writeFile(join(root, 'build/unreviewed.js'), 'extra');
    archive([...entries, 'unreviewed.js']);
    await assert.rejects(collectRelease(root, source), /archive entries/);
    archive([...entries, 'index.js']);
    await assert.rejects(collectRelease(root, source), /archive entries/);
    await rm(join(root, 'build/index.js'));
    await symlink('unreviewed.js', join(root, 'build/index.js'));
    archive();
    await assert.rejects(collectRelease(root, source), /regular files/);
    await rm(join(root, 'build/index.js'));
    await writeFile(join(root, 'build/index.js'), 'valid');
    archive();
    await writeFile(join(root, 'crates/worker/migrations/0003_gap.sql'), '-- skipped migration');
    await assert.rejects(collectRelease(root, source), /sequence/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
