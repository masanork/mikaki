/** Local Wasm entrypoint for real SSO/D1 messaging adapters. Never deploy. */
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdir, readdir, readFile, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { isAbsolute, join, resolve } from 'node:path';

const root = new URL('../', import.meta.url).pathname;
const out = join(root, 'local/generated/messaging');
const lock = await readFile(join(root, 'Cargo.lock'), 'utf8');
const version = lock.match(/name = "wasm-bindgen"\nversion = "([^"]+)"/)?.[1];
if (!version) throw new Error('Locked wasm-bindgen version is missing');
const configured = process.env.MIKAKI_MESSAGING_BINDGEN;
if (configured && !isAbsolute(configured))
  throw new Error('MIKAKI_MESSAGING_BINDGEN must be an absolute executable path');
const candidates = [configured, join(homedir(), '.cargo/bin/wasm-bindgen')].filter(
  (v): v is string => !!v,
);
// The selected executable is absolute. Its children must not resolve tools
// through a writable project directory or an inherited custom PATH.
const bindgenEnvironment = { ...process.env, PATH: '/usr/bin:/bin' };
for (const base of [join(homedir(), 'Library/Caches'), join(homedir(), '.cache')]) {
  for (const tool of ['worker-build', '.wasm-pack']) {
    const directory = join(base, tool);
    for (const entry of await readdir(directory).catch(() => [] as string[])) {
      if (entry.startsWith('wasm-bindgen-')) {
        // wasm-pack and worker-build use different version/platform directory
        // orders. The executable's exact locked version is checked below.
        candidates.push(
          join(directory, entry, 'wasm-bindgen'),
          join(directory, entry, 'bin', 'wasm-bindgen'),
        );
      }
    }
  }
}
const bindgen = candidates.find((file) => {
  try {
    return (
      execFileSync(resolve(file), ['--version'], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore'],
        env: bindgenEnvironment,
      }).trim() === `wasm-bindgen ${version}`
    );
  } catch {
    return false;
  }
});
if (!bindgen)
  throw new Error(`Install wasm-bindgen-cli ${version} or set MIKAKI_MESSAGING_BINDGEN`);
await mkdir(out, { recursive: true });
const compilation = spawnSync(
  'cargo',
  [
    'build',
    '--locked',
    '-p',
    'mikaki-worker',
    '--target',
    'wasm32-unknown-unknown',
    '--no-default-features',
    '--features',
    'messaging-qualification',
    '--example',
    'messaging-qualification',
  ],
  { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
);
await writeFile(join(out, 'cargo.log'), `${compilation.stdout ?? ''}${compilation.stderr ?? ''}`);
if (compilation.status !== 0)
  throw new Error(`Messaging qualification build failed; see ${join(out, 'cargo.log')}`);
execFileSync(
  resolve(bindgen),
  [
    join(root, 'target/wasm32-unknown-unknown/debug/examples/messaging_qualification.wasm'),
    '--target',
    'web',
    '--out-dir',
    out,
    '--out-name',
    'qualification',
    '--no-typescript',
  ],
  { cwd: root, stdio: 'inherit', env: bindgenEnvironment },
);
await writeFile(
  join(out, 'worker.mjs'),
  await readFile(join(root, 'design/probes/mls/server/worker-fixture.mjs'), 'utf8'),
);
