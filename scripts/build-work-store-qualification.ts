/** Local-only Rust WorkStore fixture. No deployed owner routes, launcher or provider effects. */
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdir, readdir, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const output = join(root, 'local/generated/work-store-main');
const version = '0.2.129'; // current main's pinned wasm-bindgen
const candidates = [process.env.MIKAKI_WORK_BINDGEN, 'wasm-bindgen'].filter(
  (x): x is string => !!x,
);
for (const cache of [join(homedir(), 'Library/Caches'), join(homedir(), '.cache')]) {
  for (const tool of ['worker-build', '.wasm-pack']) {
    const directory = join(cache, tool);
    for (const name of await readdir(directory).catch(() => [] as string[])) {
      if (name.startsWith('wasm-bindgen-') && name.endsWith(version))
        candidates.push(join(directory, name, 'wasm-bindgen'));
    }
  }
}
const bindgen = candidates.find((candidate) => {
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
if (!bindgen) throw new Error(`Install wasm-bindgen-cli ${version} or set MIKAKI_WORK_BINDGEN.`);
await mkdir(output, { recursive: true });
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
  { cwd: root, encoding: 'utf8', maxBuffer: 4 * 1024 * 1024 },
);
await writeFile(
  join(output, 'cargo.log'),
  `${compilation.stdout ?? ''}${compilation.stderr ?? ''}`,
);
if (compilation.status !== 0) {
  console.error(String(compilation.stderr ?? compilation.error).slice(-12000));
  throw new Error('WorkStore fixture compilation failed; see its generated cargo.log.');
}
execFileSync(
  bindgen,
  [
    join(root, 'target/wasm32-unknown-unknown/debug/examples/work_store_qualification.wasm'),
    '--target',
    'web',
    '--out-dir',
    output,
    '--out-name',
    'qualification',
    '--no-typescript',
  ],
  { cwd: root, stdio: 'inherit' },
);
await writeFile(
  join(output, 'worker.mjs'),
  `
import { initSync, fetch } from './qualification.js';
import module from './qualification_bg.wasm';
initSync({ module });
export default { fetch };
`,
);
