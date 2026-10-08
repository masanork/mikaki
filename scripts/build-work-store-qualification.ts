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
import { initSync, fetch, administer_op_authority } from './qualification.js';
import { authorityFacades } from './authority-admin-facade.mjs';
import module from './qualification_bg.wasm';
initSync({ module });
export class FixtureCheckpointSourceReader extends WorkerEntrypoint {
  async readRegisteredSource() {
    await this.env.DB.prepare('UPDATE fixture_source_reads SET n=n+1 WHERE id=1').run();
    if (this.env.LOCAL_CHECKPOINT_SOURCE_PAUSE === 'true') {
      const expected = await this.env.DB.prepare('SELECT authority,epoch,sequence,tip FROM work_authority_checkpoint WHERE id=1').first();
      const response = await this.env.WORK_AUTHORITY_CHECKPOINT.fetch('https://private.invalid/checkpoint', {
        method:'POST',body:JSON.stringify({action:'begin',release:1,expected,operation:'fixture-during-source-read'}),
      });
      if (response.status !== 200) throw new Error('fixture_checkpoint_pending');
    }
    return this.env.LOCAL_CHECKPOINT_SOURCE_REPLY;
  }
}
class FixtureRustOp extends WorkerEntrypoint {
  fetch(request) { return fetch(request, this.env, this.ctx); }
  administer_op_authority(request, env) { return administer_op_authority(request, env); }
}
const {Admin, Public} = authorityFacades(FixtureRustOp);
export {Admin as OpAuthorityAdmin};
export default class extends Public { async fetch(request) {
  const env=this.env, ctx=this.ctx;
  if (env.LOCAL_WORK_QUALIFICATION === 'true' && new URL(request.url).pathname === '/authority-fixture') {
    return env.OP_AUTHORITY_ADMIN.fetch(new Request('https://private.invalid/authority', request));
  }
  if (env.LOCAL_WORK_QUALIFICATION === 'true' && new URL(request.url).pathname === '/checkpoint-fixture') {
    const i = await request.json();
    try {
      if (i.action === 'bootstrap') return Response.json(await env.CHECKPOINT_ADMIN.bootstrap(i.checkpoint, i.floor));
      if (i.action === 'raise-floor') { await env.CHECKPOINT_ADMIN.raiseFloor(i.floor); return Response.json({}); }
      if (i.action === 'freeze') { await env.CHECKPOINT_ADMIN.freeze(); return Response.json({}); }
      if (i.action === 'public') return env.CHECKPOINT_PUBLIC.fetch('https://private.invalid/checkpoint', {method:'POST',body:'{}'});
      if (i.action === 'public-admin-rpc') return env.OP_PUBLIC.administer_op_authority();
      if (i.action === 'named-admin-raw-rpc') return env.OP_AUTHORITY_ADMIN.administer_op_authority();
      return env.WORK_AUTHORITY_CHECKPOINT.fetch('https://private.invalid/checkpoint', {method:'POST',body:JSON.stringify(i)});
    } catch { return Response.json({error:'checkpoint_unavailable'}, {status:409}); }
  }
  return fetch(request, env, ctx);
} };
`,
);
for (const [source, name] of [
  ['crates/worker/service/authority-admin-facade.ts', 'authority-admin-facade.mjs'],
  ['crates/work-checkpoint-worker/worker.ts', 'checkpoint.mjs'],
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
console.log('Built current-main work authority/checkpoint qualification fixture; never deploy.');
