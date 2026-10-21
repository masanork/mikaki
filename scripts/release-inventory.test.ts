import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import {
  mkdtemp,
  mkdir,
  writeFile,
  readFile,
  rm,
  symlink,
  truncate,
  copyFile,
} from 'node:fs/promises';
import { writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { createHash } from 'node:crypto';
import {
  releaseArguments,
  MESSAGING_PACKAGE_FILES,
  MESSAGING_PACKAGE_ENTRYPOINTS,
  type ReleaseProfile,
} from './release-profile.ts';
import { collectRelease, verifyRelease, releaseSource } from './release-inventory.ts';
import { prepareReleaseUpload, verifyPreparedUpload } from './prepare-release-upload.ts';

const source = { commit: 'a'.repeat(40), clean: true };
const entries = ['index.js', 'index_bg.wasm', 'package.json', 'worker/shim.mjs'];

function profileWasm(profile: ReleaseProfile, stamp = '') {
  const name = Buffer.from(`mikaki_release_profile_${profile.replace('-', '_')}`);
  const wasm = Buffer.from([
    0,
    97,
    115,
    109,
    1,
    0,
    0,
    0,
    1,
    4,
    1,
    96,
    0,
    0,
    3,
    2,
    1,
    0,
    7,
    name.length + 4,
    1,
    name.length,
    ...name,
    0,
    0,
    10,
    4,
    1,
    2,
    0,
    11,
  ]);
  return stamp
    ? Buffer.concat([wasm, Buffer.from([0, stamp.length + 1, 0]), Buffer.from(stamp)])
    : wasm;
}

async function fakeBundle(entry: string, _config: string, output: string, upload: string) {
  const wasm = entry.endsWith('checkpoint.mjs')
    ? undefined
    : await readFile(join(dirname(entry), '../index_bg.wasm'));
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
  if (wasm) writeFileSync(join(output, 'module.wasm'), wasm);
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
      new Blob([new Uint8Array(wasm!)], { type: 'application/wasm' }),
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
}

test('font assets are source-bound and prepared bytes cannot change before upload', async () => {
  const { root } = await fixture();
  try {
    await mkdir(join(root, 'assets/fonts'), { recursive: true });
    await writeFile(join(root, 'assets/fonts/fonts.css'), 'font fixture');
    await writeFile(join(root, 'assets/fonts/sample.woff2'), 'font bytes');
    await writeFile(
      join(root, 'crates/worker/wrangler.production.jsonc'),
      JSON.stringify({ name: 'op', assets: { directory: '../../assets' } }),
    );
    const inventory = await collectRelease(root, source);
    assert.equal(inventory.assets?.length, 2);
    const prepared = await prepareReleaseUpload(root, inventory, source, false, fakeBundle);
    await writeFile(join(prepared.destination, 'op/assets/fonts/sample.woff2'), 'tampered');
    await assert.rejects(
      verifyPreparedUpload(root, prepared.destination, prepared.result, source),
      /Prepared static assets differ/,
    );
    await writeFile(join(root, 'assets/fonts/fonts.css'), 'changed source');
    await assert.rejects(verifyRelease(root, inventory, source));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
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
  await writeFile(join(root, 'build/index_bg.wasm'), profileWasm('default'));
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

async function betaFixture() {
  const f = await fixture();
  await mkdir(join(f.root, 'assets/fonts'), { recursive: true });
  await mkdir(join(f.root, 'assets/chat'), { recursive: true });
  await mkdir(join(f.root, 'artifacts/messaging-package'), { recursive: true });
  await writeFile(join(f.root, 'assets/fonts/fonts.css'), 'font fixture');
  await writeFile(join(f.root, 'assets/chat/client.js'), 'chat client');
  await writeFile(join(f.root, 'assets/chat/crypto.wasm'), 'chat crypto');
  await writeFile(
    join(f.root, 'crates/worker/wrangler.production.jsonc'),
    JSON.stringify({ name: 'op', assets: { directory: '../../assets' } }),
  );
  await writeFile(join(f.root, 'build/index_bg.wasm'), profileWasm('messaging-beta'));
  f.archive();
  const files = await Promise.all(
    MESSAGING_PACKAGE_FILES.map(async (path) => {
      const bytes = await readFile(
        join(
          f.root,
          path.startsWith('assets/')
            ? path
            : 'build/' + path.slice('crates/worker/build-messaging-beta/'.length),
        ),
      );
      return {
        path,
        bytes: bytes.length,
        sha256: createHash('sha256').update(bytes).digest('hex'),
      };
    }),
  );
  const report = {
    schema: 'mikaki-messaging-package-qualification-v2',
    source,
    profile: 'messaging-beta',
    runtime: { build_profile: 'messaging-beta', source_commit: source.commit, source_clean: true },
    entrypoints: MESSAGING_PACKAGE_ENTRYPOINTS,
    files,
    upload: {
      entry: 'service.js',
      raw: 1,
      modules: [
        {
          name: 'service.js',
          type: 'application/javascript+module',
          bytes: 1,
          sha256: 'a'.repeat(64),
        },
      ],
    },
  };
  const writeReport = (value = report) =>
    writeFile(join(f.root, 'artifacts/messaging-package/summary.json'), JSON.stringify(value));
  await writeReport();
  return { ...f, report, writeReport };
}

test('release profile selection rejects unknown and duplicate options', () => {
  assert.deepEqual(releaseArguments([]), { profile: 'default', allowDirty: false, operands: [] });
  assert.deepEqual(releaseArguments(['path', '--profile', 'messaging-beta', '--allow-dirty']), {
    profile: 'messaging-beta',
    allowDirty: true,
    operands: ['path'],
  });
  for (const args of [
    ['--profile'],
    ['--profile', 'all'],
    ['--profile', 'default', '--profile', 'messaging-beta'],
    ['--allow-dirty', '--allow-dirty'],
    ['--unknown'],
  ]) {
    assert.throws(() => releaseArguments(args));
  }
});

test('compiled beta and default modules cannot be relabeled, including without qualification evidence', async () => {
  const f = await betaFixture();
  try {
    await assert.rejects(collectRelease(f.root, source), /Compiled release profile differs/);
    const inventory = await collectRelease(f.root, source, 'messaging-beta');
    assert.equal(inventory.profile, 'messaging-beta');
    await assert.rejects(verifyRelease(f.root, inventory, source));
    await verifyRelease(f.root, inventory, source, false, 'messaging-beta');
    await rm(join(f.root, 'artifacts/messaging-package/summary.json'));
    await assert.rejects(collectRelease(f.root, source, 'messaging-beta'), { code: 'ENOENT' });
    await f.writeReport();
    await writeFile(join(f.root, 'build/index_bg.wasm'), profileWasm('default'));
    f.archive();
    await assert.rejects(
      collectRelease(f.root, source, 'messaging-beta'),
      /Compiled release profile differs/,
    );
    const normal = await collectRelease(f.root, source);
    assert.deepEqual(
      normal.assets?.map((file) => file.name),
      ['fonts/fonts.css'],
    );
    assert.equal(normal.messaging, undefined);
  } finally {
    await rm(f.root, { recursive: true, force: true });
  }
});

test('Chat qualification binds source, runtime, archive members and exact lazy assets', async () => {
  const f = await betaFixture();
  try {
    for (const mutate of [
      (q: typeof f.report) => {
        q.source = { ...source, commit: 'b'.repeat(40) };
      },
      (q: typeof f.report) => {
        q.runtime.build_profile = 'default';
      },
      (q: typeof f.report) => {
        q.runtime.source_clean = false;
      },
      (q: typeof f.report) => {
        q.files[0]!.sha256 = '0'.repeat(64);
      },
      (q: typeof f.report) => {
        q.entrypoints = q.entrypoints.slice(1);
      },
      (q: typeof f.report) => {
        q.upload.raw++;
      },
    ]) {
      const q = structuredClone(f.report);
      mutate(q);
      await f.writeReport(q);
      await assert.rejects(collectRelease(f.root, source, 'messaging-beta'));
    }
    await f.writeReport();
    await writeFile(join(f.root, 'assets/chat/client.js'), 'substituted client');
    await assert.rejects(
      collectRelease(f.root, source, 'messaging-beta'),
      /differ from qualified bytes/,
    );
    await writeFile(join(f.root, 'assets/chat/client.js'), 'chat client');
    await writeFile(join(f.root, 'assets/chat/unreviewed.js'), 'extra asset');
    await assert.rejects(collectRelease(f.root, source, 'messaging-beta'));
    await rm(join(f.root, 'assets/chat/unreviewed.js'));
    await writeFile(join(f.root, 'build/worker/service.mjs'), 'replaced service');
    f.archive();
    await assert.rejects(
      collectRelease(f.root, source, 'messaging-beta'),
      /differ from qualified bytes/,
    );
  } finally {
    await rm(f.root, { recursive: true, force: true });
  }
});

test('prepared beta candidates require explicit verification and cannot enter ordinary promotion', async () => {
  const f = await betaFixture();
  try {
    const inventory = await collectRelease(f.root, source, 'messaging-beta');
    await assert.rejects(prepareReleaseUpload(f.root, inventory, source, false, fakeBundle));
    const { destination, result } = await prepareReleaseUpload(
      f.root,
      inventory,
      source,
      false,
      fakeBundle,
      'messaging-beta',
    );
    assert.equal(result.profile, 'messaging-beta');
    assert.equal(result.promotion_ready, false);
    await verifyPreparedUpload(f.root, destination, result, source, false, 'messaging-beta');
    // A new attestation checkout has no generated Chat assets. Rehydrate only
    // the frozen copies, then verify the complete source-bound inventories again.
    await rm(join(f.root, 'assets/chat'), { recursive: true });
    await assert.rejects(
      verifyPreparedUpload(f.root, destination, result, source, false, 'messaging-beta'),
    );
    await mkdir(join(f.root, 'assets/chat'));
    for (const name of ['client.js', 'crypto.wasm']) {
      await copyFile(join(destination, 'op/assets/chat', name), join(f.root, 'assets/chat', name));
    }
    await verifyPreparedUpload(f.root, destination, result, source, false, 'messaging-beta');
    await assert.rejects(
      verifyPreparedUpload(f.root, destination, result, source),
      /Unexpected upload release profile/,
    );
    const changed = structuredClone(result);
    changed.promotion_ready = true;
    await assert.rejects(
      verifyPreparedUpload(f.root, destination, changed, source, false, 'messaging-beta'),
    );
    await writeFile(join(destination, 'op/assets/chat/crypto.wasm'), 'replaced after preparation');
    await assert.rejects(
      verifyPreparedUpload(f.root, destination, result, source, false, 'messaging-beta'),
      /Prepared static assets differ/,
    );
  } finally {
    await rm(f.root, { recursive: true, force: true });
  }
});
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
test('bundling cannot substitute another Wasm in either Worker upload', async () => {
  const { root } = await fixture();
  try {
    const inventory = await collectRelease(root, source);
    for (const target of ['service.mjs', 'shim.mjs']) {
      const substituted: typeof fakeBundle = async (entry, config, output, upload) => {
        await fakeBundle(entry, config, output, upload);
        if (!entry.endsWith(target)) return;
        const bytes = await readFile(upload);
        const boundary = bytes.subarray(0, bytes.indexOf(10)).toString().trimEnd().slice(2);
        const form = await new Response(bytes, {
          headers: { 'Content-Type': `multipart/form-data; boundary=${boundary}` },
        }).formData();
        const changed = profileWasm('messaging-beta');
        form.set(
          'module.wasm',
          new Blob([new Uint8Array(changed)], { type: 'application/wasm' }),
          'module.wasm',
        );
        await writeFile(join(output, 'module.wasm'), changed);
        await writeFile(upload, new Uint8Array(await new Response(form).arrayBuffer()));
      };
      await assert.rejects(
        prepareReleaseUpload(root, inventory, source, false, substituted),
        /Upload Wasm differs/,
      );
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
test('upload preparation stages only verified archive members and records Wrangler bundle bytes', async () => {
  const { root, archive } = await fixture();
  try {
    const inventory = await collectRelease(root, source);

    const prepared = await prepareReleaseUpload(root, inventory, source, false, fakeBundle);
    assert.equal(prepared.result.promotion_ready, true);
    assert.equal(prepared.result.workers.length, 3);
    assert.equal(prepared.result.workers[0]?.bundle_files.length, 3);
    assert.equal(
      prepared.result.workers[0]?.bundle_raw_bytes,
      Buffer.byteLength('bundled entry') + profileWasm('default').length,
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
      (await readFile(join(prepared.destination, 'op/input/index_bg.wasm'))).toString('hex'),
      profileWasm('default').toString('hex'),
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
    await writeFile(join(root, 'build/index_bg.wasm'), profileWasm('default', 'changed'));
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
    await writeFile(
      join(root, 'build/index_bg.wasm'),
      profileWasm('default', 'substituted runtime'),
    );
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
    await writeFile(join(root, 'build/index_bg.wasm'), profileWasm('default', 'CONFORMANCE_GATE'));
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
