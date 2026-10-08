/** Local Wasm fixture only: product Rust WorkStore, synthetic verifier, no deployment. */
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdir, readdir, readFile, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { build } from 'esbuild';

const root = new URL('../', import.meta.url).pathname;
const out = join(root, 'local/generated/work-store');
const lock = await readFile(join(root, 'Cargo.lock'), 'utf8');
const version = lock.match(/name = "wasm-bindgen"\nversion = "([^"]+)"/)?.[1];
if (!version) throw new Error('Locked wasm-bindgen version is missing');
let bindgen = process.env.MIKAKI_WORK_BINDGEN;
if (!bindgen) {
  const caches = [join(homedir(), 'Library/Caches'), join(homedir(), '.cache')];
  const candidates = ['wasm-bindgen'];
  for (const cache of caches) {
    for (const tool of ['worker-build', '.wasm-pack']) {
      const dir = join(cache, tool);
      for (const entry of await readdir(dir).catch(() => [] as string[])) {
        if (entry.startsWith('wasm-bindgen-') && entry.endsWith(version))
          candidates.push(join(dir, entry, 'wasm-bindgen'));
      }
    }
  }
  bindgen = candidates.find((candidate) => {
    try {
      return (
        execFileSync(candidate, ['--version'], {
          encoding: 'utf8',
          stdio: ['ignore', 'pipe', 'ignore'],
        }).trim() === `wasm-bindgen ${version}`
      );
    } catch {
      return false;
    }
  });
}
if (
  !bindgen ||
  execFileSync(bindgen, ['--version'], { encoding: 'utf8' }).trim() !== `wasm-bindgen ${version}`
) {
  throw new Error(
    `Install wasm-bindgen-cli ${version} or set MIKAKI_WORK_BINDGEN to its executable.`,
  );
}
await mkdir(out, { recursive: true });
const compilation = spawnSync(
  'cargo',
  [
    'build',
    '--offline',
    '--locked',
    '-p',
    'mikaki-worker',
    '--target',
    'wasm32-unknown-unknown',
    '--no-default-features',
    '--features',
    'work-qualification',
    '--example',
    'work-store-qualification',
  ],
  { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
);
await writeFile(join(out, 'cargo.log'), `${compilation.stdout ?? ''}${compilation.stderr ?? ''}`);
if (compilation.status !== 0) {
  console.error(String(compilation.stderr ?? compilation.error).slice(-12000));
  throw new Error(
    'Qualification fixture compilation failed; see local/generated/work-store/cargo.log',
  );
}
execFileSync(
  bindgen,
  [
    join(root, 'target/wasm32-unknown-unknown/debug/examples/work_store_qualification.wasm'),
    '--target',
    'web',
    '--out-dir',
    out,
    '--out-name',
    'qualification',
    '--no-typescript',
  ],
  { cwd: root, stdio: 'inherit' },
);
await writeFile(
  join(out, 'worker.mjs'),
  `import { WorkerEntrypoint } from 'cloudflare:workers';
import { initSync, fetch } from './qualification.js';
import module from './qualification_bg.wasm';
initSync({ module });
export default class extends WorkerEntrypoint { fetch(request) { return fetch(request, this.env, this.ctx); } }
`,
);
for (const [source, name] of [
  ['local/conformance/support/work-source-reader.ts', 'source-reader.mjs'],
]) {
  await build({
    entryPoints: [join(root, source)],
    bundle: true,
    format: 'esm',
    platform: 'browser',
    external: ['cloudflare:workers'],
    outfile: join(out, name),
  });
}
console.log('Built current-main WorkStore qualification fixture; never deploy.');
