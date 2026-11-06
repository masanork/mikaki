/** Build an isolated local Worker qualification; never deploy its output. */
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdir, readdir, readFile, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { isAbsolute, join, resolve } from 'node:path';

export async function buildQualificationWorker(options: {
  name: 'messaging' | 'installation';
  fixture: string;
  bindgenVariable: 'MIKAKI_MESSAGING_BINDGEN' | 'MIKAKI_INSTALLATION_BINDGEN';
  bundle: boolean;
}): Promise<void> {
  const root = new URL('../', import.meta.url).pathname;
  const out = join(root, 'local/generated', options.name);
  const lock = await readFile(join(root, 'Cargo.lock'), 'utf8');
  const version = lock.match(/name = "wasm-bindgen"\nversion = "([^\"]+)"/)?.[1];
  if (!version) throw new Error('Locked wasm-bindgen version is missing');
  const configured = process.env[options.bindgenVariable];
  if (configured && !isAbsolute(configured))
    throw new Error(`${options.bindgenVariable} must be an absolute executable path`);
  const cargoHome = process.env.CARGO_HOME ?? join(homedir(), '.cargo');
  if (!isAbsolute(cargoHome)) throw new Error('CARGO_HOME must be an absolute directory');
  const candidates = [configured, join(homedir(), '.cargo/bin/wasm-bindgen')].filter(
    (v): v is string => !!v,
  );
  // Do not resolve child tools through a writable project directory or custom PATH.
  const bindgenEnvironment = { ...process.env, PATH: '/usr/bin:/bin' };
  for (const base of [join(homedir(), 'Library/Caches'), join(homedir(), '.cache')]) {
    for (const tool of ['worker-build', '.wasm-pack']) {
      const directory = join(base, tool);
      for (const entry of await readdir(directory).catch(() => [] as string[])) {
        if (entry.startsWith('wasm-bindgen-')) {
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
    throw new Error(`Install wasm-bindgen-cli ${version} or set ${options.bindgenVariable}`);
  await mkdir(out, { recursive: true });
  const profile = `${options.name}-qualification`;
  const compilation = spawnSync(
    join(cargoHome, 'bin/cargo'),
    [
      'build',
      '--locked',
      '-p',
      'mikaki-worker',
      '--target',
      'wasm32-unknown-unknown',
      '--no-default-features',
      '--features',
      profile,
      '--example',
      profile,
    ],
    { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
  );
  await writeFile(join(out, 'cargo.log'), `${compilation.stdout ?? ''}${compilation.stderr ?? ''}`);
  if (compilation.status !== 0)
    throw new Error(`${options.name} qualification build failed; see ${join(out, 'cargo.log')}`);
  execFileSync(
    resolve(bindgen),
    [
      join(root, `target/wasm32-unknown-unknown/debug/examples/${options.name}_qualification.wasm`),
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
  await writeFile(join(out, 'worker.mjs'), await readFile(join(root, options.fixture), 'utf8'));
  if (options.bundle) {
    const { build } = await import('esbuild');
    await build({
      entryPoints: [join(out, 'worker.mjs')],
      outfile: join(out, 'worker.bundle.mjs'),
      bundle: true,
      format: 'esm',
      platform: 'browser',
      external: ['*.wasm'],
    });
  }
}
