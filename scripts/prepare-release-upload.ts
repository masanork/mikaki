/** Prepare Wrangler upload inputs from a verified release without uploading them. */
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { appendFile, mkdir, mkdtemp, open, readdir, rm, writeFile } from 'node:fs/promises';
import { join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  releaseSource,
  verifyRelease,
  type ReleaseInventory,
  type ReleaseSource,
} from './release-inventory.ts';

const limit = 64 * 1024 * 1024;
const workers = [
  {
    archive: 'mikaki-worker.tar.gz',
    directory: 'op',
    entry: 'service',
    config: 'crates/worker/wrangler.production.jsonc',
  },
  {
    archive: 'mikaki-userinfo-claim-worker.tar.gz',
    directory: 'userinfo',
    entry: 'shim',
    config: 'crates/userinfo-claim-worker/wrangler.production.jsonc',
  },
] as const;

function digest(bytes: Uint8Array) {
  return { bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex') };
}
async function boundedFile(path: string): Promise<Buffer> {
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = await file.stat();
    assert.ok(stat.isFile() && stat.size <= limit, 'Expected a bounded regular file');
    const buffer = Buffer.alloc(stat.size + 1);
    let length = 0;
    while (length < buffer.length) {
      const read = await file.read(buffer, length, buffer.length - length, null);
      if (read.bytesRead === 0) break;
      length += read.bytesRead;
    }
    assert.equal(length, stat.size, 'File changed while reading');
    return buffer.subarray(0, length);
  } finally {
    await file.close();
  }
}
function extractMember(archive: Buffer, name: string): Buffer {
  return execFileSync('tar', ['-xOz', '-f', '-', name], {
    input: archive,
    maxBuffer: limit,
    timeout: 30_000,
  });
}

export async function prepareReleaseUpload(
  root: string,
  inventory: ReleaseInventory,
  source: ReleaseSource,
  allowDirty = false,
  bundle?: (entry: string, config: string, output: string) => void,
) {
  await verifyRelease(root, inventory, source, allowDirty);
  const destination = await mkdtemp(join(root, 'artifacts/promotion-'));
  try {
    const wrangler = join(root, 'node_modules/.bin/wrangler');
    const wranglerEnv = {
      ...process.env,
      WRANGLER_SEND_METRICS: 'false',
      WRANGLER_LOG_PATH: join(root, 'node_modules/.cache/mikaki-wrangler-logs'),
    };
    const wranglerVersion = bundle
      ? 'test-bundler'
      : execFileSync(wrangler, ['--version'], {
          encoding: 'utf8',
          timeout: 10_000,
          env: wranglerEnv,
        }).trim();
    const prepared = [];
    for (const worker of workers) {
      const original = inventory.archives.find((archive) => archive.name === worker.archive);
      assert.ok(original, `Missing archive inventory: ${worker.archive}`);
      const archive = await boundedFile(join(root, 'artifacts', worker.archive));
      assert.deepEqual(digest(archive), original.digest, `Archive changed: ${worker.archive}`);
      const input = join(destination, worker.directory, 'input');
      const output = join(destination, worker.directory, 'bundle');
      await mkdir(join(input, 'worker'), { recursive: true, mode: 0o700 });
      await mkdir(output, { recursive: true, mode: 0o700 });
      for (const member of original.members) {
        const bytes = extractMember(archive, member.name);
        assert.deepEqual(digest(bytes), member.digest, `Archive member changed: ${member.name}`);
        await writeFile(join(input, member.name), bytes, { flag: 'wx', mode: 0o600 });
      }
      const entry = join(input, `worker/${worker.entry}.mjs`);
      const config = join(root, worker.config);
      if (bundle) bundle(entry, config, output);
      else
        execFileSync(
          wrangler,
          ['deploy', entry, '--config', config, '--dry-run', '--outdir', output],
          {
            cwd: root,
            env: wranglerEnv,
            timeout: 120_000,
            maxBuffer: 2 * 1024 * 1024,
            stdio: ['ignore', 'pipe', 'pipe'],
          },
        );
      const bundleFiles = [];
      for (const name of (await readdir(output)).sort()) {
        assert.match(name, /^[a-zA-Z0-9_.-]+$/, 'Unexpected bundle filename');
        bundleFiles.push({ name, digest: digest(await boundedFile(join(output, name))) });
      }
      assert.ok(bundleFiles.some((file) => file.name === `${worker.entry}.js`));
      assert.equal(bundleFiles.filter((file) => file.name.endsWith('.wasm')).length, 1);
      prepared.push({
        worker: worker.directory,
        archive: worker.archive,
        archive_digest: original.digest,
        config_sha256: digest(await boundedFile(config)).sha256,
        bundle_files: bundleFiles,
      });
    }
    const result = {
      schema_version: 1,
      source,
      promotion_ready: source.clean,
      wrangler_version: wranglerVersion,
      release_inventory: inventory,
      workers: prepared,
    };
    await writeFile(
      join(destination, 'upload-manifest.json'),
      `${JSON.stringify(result, null, 2)}\n`,
      {
        flag: 'wx',
        mode: 0o600,
      },
    );
    await verifyPreparedUpload(root, destination, result, source, allowDirty);
    return { destination, result };
  } catch (error) {
    await rm(destination, { recursive: true, force: true });
    throw error;
  }
}

export async function verifyPreparedUpload(
  root: string,
  destination: string,
  result: Awaited<ReturnType<typeof prepareReleaseUpload>>['result'],
  source: ReleaseSource,
  allowDirty = false,
) {
  assert.equal(result.schema_version, 1);
  assert.deepEqual(result.source, source);
  assert.equal(result.promotion_ready, source.clean);
  await verifyRelease(root, result.release_inventory, source, allowDirty);
  assert.deepEqual(
    result.workers.map((worker) => worker.worker),
    workers.map((worker) => worker.directory),
  );
  for (const [index, worker] of workers.entries()) {
    const record = result.workers[index]!;
    const archive = result.release_inventory.archives.find((item) => item.name === worker.archive);
    assert.ok(archive);
    assert.equal(record.archive, worker.archive);
    assert.deepEqual(record.archive_digest, archive.digest);
    assert.equal(record.config_sha256, digest(await boundedFile(join(root, worker.config))).sha256);
    const input = join(destination, worker.directory, 'input');
    assert.deepEqual((await readdir(input)).sort(), [
      'index.js',
      'index_bg.wasm',
      'package.json',
      'worker',
    ]);
    assert.deepEqual(
      (await readdir(join(input, 'worker'))).sort(),
      archive.members
        .filter((member) => member.name.startsWith('worker/'))
        .map((member) => member.name.slice(7))
        .sort(),
    );
    for (const member of archive.members) {
      assert.deepEqual(digest(await boundedFile(join(input, member.name))), member.digest);
    }
    const output = join(destination, worker.directory, 'bundle');
    assert.deepEqual(
      (await readdir(output)).sort(),
      record.bundle_files.map((file) => file.name).sort(),
    );
    assert.ok(record.bundle_files.some((file) => file.name === `${worker.entry}.js`));
    assert.equal(record.bundle_files.filter((file) => file.name.endsWith('.wasm')).length, 1);
    for (const file of record.bundle_files) {
      assert.match(file.name, /^[a-zA-Z0-9_.-]+$/);
      assert.deepEqual(digest(await boundedFile(join(output, file.name))), file.digest);
    }
  }
}

async function main() {
  const [action, ...args] = process.argv.slice(2);
  assert.ok(
    action === 'create' || action === 'verify',
    'Usage: prepare-release-upload.ts create [--allow-dirty] | verify <directory> [--allow-dirty]',
  );
  const allowDirty = args.at(-1) === '--allow-dirty';
  const operands = allowDirty ? args.slice(0, -1) : args;
  assert.equal(operands.length, action === 'create' ? 0 : 1);
  const root = fileURLToPath(new URL('../', import.meta.url));
  const source = releaseSource(root);
  if (action === 'verify') {
    const destination = resolve(operands[0]!);
    assert.ok(destination.startsWith(join(root, 'artifacts/promotion-')));
    const result = JSON.parse(
      (await boundedFile(join(destination, 'upload-manifest.json'))).toString('utf8'),
    ) as Awaited<ReturnType<typeof prepareReleaseUpload>>['result'];
    await verifyPreparedUpload(root, destination, result, source, allowDirty);
    console.log(
      `Verified ${result.promotion_ready ? 'clean' : 'LOCAL DIRTY'} upload: ${destination}`,
    );
    return;
  }
  const inventory = JSON.parse(
    (await boundedFile(join(root, 'artifacts/release-manifest.json'))).toString('utf8'),
  ) as ReleaseInventory;
  const { destination, result } = await prepareReleaseUpload(root, inventory, source, allowDirty);
  if (process.env.GITHUB_OUTPUT) {
    await appendFile(process.env.GITHUB_OUTPUT, `promotion_dir=${relative(root, destination)}\n`);
  }
  console.log(
    `Prepared ${result.promotion_ready ? 'clean' : 'LOCAL DIRTY'} upload: ${destination}`,
  );
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
