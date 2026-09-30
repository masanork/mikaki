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
  const archive = (names = entries) => {
    for (const name of ['mikaki-worker', 'mikaki-userinfo-claim-worker'])
      execFileSync('tar', [
        '-C',
        join(root, 'build'),
        '-czf',
        join(root, `artifacts/${name}.tar.gz`),
        ...names,
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
    const fakeBundle = (entry: string, _config: string, output: string) => {
      assert.equal(execFileSync('cat', [entry], { encoding: 'utf8' }), 'fixture:worker/shim.mjs');
      writeFileSync(join(output, 'shim.js'), 'bundled entry');
      writeFileSync(join(output, 'module.wasm'), 'bundled wasm');
    };
    const prepared = await prepareReleaseUpload(root, inventory, source, false, fakeBundle);
    assert.equal(prepared.result.promotion_ready, true);
    assert.equal(prepared.result.workers.length, 2);
    assert.equal(prepared.result.workers[0]?.bundle_files.length, 2);
    assert.equal(
      (await readFile(join(prepared.destination, 'op/input/index_bg.wasm'))).toString(),
      'fixture:index_bg.wasm',
    );
    await writeFile(join(prepared.destination, 'op/bundle/shim.js'), 'changed after preparation');
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
