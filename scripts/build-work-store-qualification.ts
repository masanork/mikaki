/** Local Wasm fixture only: product Rust WorkStore, synthetic verifier, no deployment. */
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdir, readdir, readFile, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { build } from 'esbuild';

const root = new URL('../', import.meta.url).pathname;
const out = join(root, 'local/generated/work-store-main');
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
    'Qualification fixture compilation failed; see local/generated/work-store-main/cargo.log',
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
import { initSync, fetch, administer_op_authority, administer_work_effect } from './qualification.js';
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
  administer_work_effect(request, env) { return administer_work_effect(request, env); }
}
const {Admin, Effect, Mint, Git, Public} = authorityFacades(FixtureRustOp);
export {Admin as OpAuthorityAdmin, Effect as WorkEffectStore, Mint as WorkMintStore, Git as WorkGitStore};
export class FixtureEffectBridge extends WorkerEntrypoint {
  async fetch(request) {
    const refusalInput=await request.clone().json();
    if(this.env.LOCAL_MINT_CLOSE_FREEZE==='true' && refusalInput.action==='mint-close') await this.env.CHECKPOINT_ADMIN.freeze();
    if(this.env.LOCAL_MINT_CLEANUP_LOST==='true' && (await request.clone().json()).action==='mint-cleanup') return Response.json({error:'synthetic_cleanup_unavailable'},{status:409});
    if (this.env.LOCAL_MINT_CAPTURE_PAUSE) {
      const i=await request.clone().json();
      if(i.action==='capture-mint') {
        if(this.env.LOCAL_MINT_CAPTURE_PAUSE==='revoke') {
          const r=await this.env.OP_AUTHORITY_ADMIN.fetch('https://private.invalid/authority',{method:'POST',body:JSON.stringify({action:'revoke-account',account:'synthetic-delivery-owner',expected_epoch:0,actor:'fixture',reason:'after mint admission'})});
          if(r.status!==200) throw new Error('fixture_revoke_failed');
        }
        if(this.env.LOCAL_MINT_CAPTURE_PAUSE==='source') await this.env.DB.prepare('UPDATE work_source_access SET active=0,access_revision=access_revision+1').run();
        if(this.env.LOCAL_MINT_CAPTURE_PAUSE==='rotate') {
          const r=await this.env.OP_PUBLIC.fetch('https://work.test/fixture',{method:'POST',body:JSON.stringify({action:'activate-credential-key',key_version:2})});
          if(r.status!==200) throw new Error('fixture_rotate_failed');
        }
      }
    }
    if(this.env.LOCAL_MINT_BEGIN_CLEANUP==='true') {
      const i=await request.clone().json();
      if(i.action==='capture-mint') await this.env.MINT_MAINTENANCE.begin(i.attempt_id,i.digest);
    }
    const response = await (new URL(request.url).pathname === '/mint-effect' ? this.env.OP_MINT_STORE : this.env.OP_EFFECT_STORE).fetch(request);
    if(this.env.LOCAL_MINT_CLOSE_LOST==='true' && refusalInput.action==='mint-close' && response.status===200) return Response.json({error:'synthetic_close_lost'},{status:409});
    if (response.status === 200 && this.env.LOCAL_EFFECT_CAPTURE_LOST === 'true') {
      const value = await response.clone().json();
      if (value.state === 'closed' || value.state === 'captured') return Response.json({error:'synthetic_lost_ack'},{status:409});
    }
    if (response.status === 200 && this.env.LOCAL_EFFECT_PAUSE) {
      const p = await response.clone().json();
      if (p.effect === 'repo.create' || p.effect === 'token.mint') {
        if (this.env.LOCAL_EFFECT_PAUSE === 'pending') {
          const result = await this.env.WORK_AUTHORITY_CHECKPOINT.fetch('https://private.invalid/checkpoint', {method:'POST',body:JSON.stringify({action:'begin',release:1,expected:p.checkpoint,operation:'fixture-before-effect'})});
          if (result.status !== 200) throw new Error('fixture_pending_failed');
        }
        if (this.env.LOCAL_EFFECT_PAUSE === 'freeze') await this.env.CHECKPOINT_ADMIN.freeze();
        if (this.env.LOCAL_EFFECT_PAUSE === 'revoke') {
          const result = await this.env.OP_AUTHORITY_ADMIN.fetch('https://private.invalid/authority', {method:'POST',body:JSON.stringify({action:'revoke-account',account:'synthetic-delivery-owner',expected_epoch:0,actor:'fixture',reason:'between plan and claim'})});
          if (result.status !== 200) throw new Error('fixture_revoke_failed');
        }
      }
    }
    return response;
  }
}
export class FixtureEffectLedger extends WorkerEntrypoint {
  lookup(attempt){return this.env.EFFECT_LEDGER.lookup(attempt);}
  async claim(plan){await this.env.EFFECT_LEDGER.claim(plan);throw new Error('synthetic_claim_lost');}
  observe(attempt,digest,repo){return this.env.EFFECT_LEDGER.observe(attempt,digest,repo);}
  close(attempt,digest,value){return this.env.EFFECT_LEDGER.close(attempt,digest,value);}
}
export class FixtureGitCheckpoint extends WorkerEntrypoint {
  lookup(attempt){return this.env.GIT_CHECKPOINT.lookup(attempt);}
  async claim(plan){const r=await this.env.GIT_CHECKPOINT.claim(plan);if(this.env.LOCAL_GIT_CLAIM_LOST==='true')throw new Error('synthetic_claim_lost');return r;}
}
export class FixtureGitTransmission extends WorkerEntrypoint {
  current(attempt,digest){return this.env.GIT_TRANSMISSION.current(attempt,digest);}
  async take(attempt,digest){const r=await this.env.GIT_TRANSMISSION.take(attempt,digest);if(this.env.LOCAL_GIT_TAKE_LOST==='true')throw new Error('synthetic_take_lost');return r;}
}
export class FixtureMintLedger extends WorkerEntrypoint {
  lookup(attempt){return this.env.MINT_LEDGER.lookup(attempt);}
  async claim(plan){const r=await this.env.MINT_LEDGER.claim(plan);if(this.env.LOCAL_MINT_LEDGER_LOST==='claim') throw new Error('synthetic_claim_lost');return r;}
  async observe(attempt,digest,value){await this.env.MINT_LEDGER.observe(attempt,digest,value);if(['observe','observe-and-abandon'].includes(this.env.LOCAL_MINT_LEDGER_LOST)) throw new Error('synthetic_observe_lost');}
  async custody(attempt,digest){const r=await this.env.MINT_LEDGER.custody(attempt,digest);if(this.env.LOCAL_MINT_LEDGER_LOST==='custody') throw new Error('synthetic_custody_lost');return r;}
  abandon(attempt,digest){if(this.env.LOCAL_MINT_LEDGER_LOST==='observe-and-abandon') throw new Error('synthetic_abandon_unavailable');return this.env.MINT_LEDGER.abandon(attempt,digest);}
  close(attempt,digest,receipt){return this.env.MINT_LEDGER.close(attempt,digest,receipt);}
  revoked(attempt,digest){return this.env.MINT_LEDGER.revoked(attempt,digest);}
}
export class FixtureMintRefusalLedger extends WorkerEntrypoint {
  lookup(attempt){return this.env.MINT_REFUSAL_CHECKPOINT.lookup(attempt);}
  async refused(attempt,digest,proof){const r=await this.env.MINT_REFUSAL_CHECKPOINT.refused(attempt,digest,proof);if(this.env.LOCAL_MINT_REFUSAL_LOST==='true') throw new Error('synthetic_refusal_lost');return r;}
}
export default class extends Public { async fetch(request) {
  const env=this.env, ctx=this.ctx;
  if (env.LOCAL_WORK_QUALIFICATION === 'true' && new URL(request.url).pathname === '/git-fixture') return env.GIT_BROKER.fetch(new Request('https://private.invalid/copy',request));
  if (env.LOCAL_WORK_QUALIFICATION === 'true' && new URL(request.url).pathname === '/effect-fixture') {
    const i=await request.json();
    try {
      if(i.action==='mint-close') return env.MINT_CLOSER.fetch('https://private.invalid/close-mint',{method:'POST',body:JSON.stringify(i.input)});
      if(i.action==='git-public') return env.GIT_PUBLIC.fetch('https://private.invalid/copy',{method:'POST',body:'{}'});
      if(i.action==='git-call') {const value=await env[i.binding][i.method](...(i.args??[]));return value instanceof Response?value:Response.json(value);}
      if(i.action==='mint-close-public') return env.MINT_CLOSURE_PUBLIC.fetch('https://private.invalid/close-mint',{method:'POST',body:'{}'});
      if(i.action==='mint-refusal-public') return env.MINT_REFUSAL_TRANSPORT_PUBLIC.fetch('https://private.invalid/');
      if(i.action==='mint-refusal-call') return Response.json(await env.MINT_REFUSAL_CHECKPOINT[i.method](...(i.args??[])));
      if(i.action==='mint-refusal-transport') return env.WORK_MINT_REFUSAL_TRANSPORT.fetch(new Request(i.url,{method:i.method??'GET',headers:i.headers,body:i.body}));
      if(i.action==='mint-reconcile') return env.MINT_RECONCILER.fetch('https://private.invalid/reconcile-mint',{method:'POST',body:JSON.stringify(i.input)});
      if(i.action==='mint-reconcile-public') return env.MINT_RECONCILE_PUBLIC.fetch('https://private.invalid/reconcile-mint',{method:'POST',body:'{}'});
      if(i.action==='mint-broker-public') return env.MINT_MAINTENANCE_PUBLIC.fetch('https://private.invalid/',{method:'POST',body:'{}'});
      if(i.action==='mint-safety-call') return Response.json(await env.MINT_MAINTENANCE[i.method](...(i.args??[])));
      if(i.action==='mint-lookup-call') return Response.json(await env.MINT_LOOKUP[i.method](...(i.args??[])));
      if(i.action==='mint-broker-factory-call') return Response.json(await env.MINT_ARTIFACTS_MAINTENANCE[i.method](i.input));
      if(i.action==='mint-broker-call') {
        const repo=await env.MINT_ARTIFACTS_MAINTENANCE.open(i.input);
        try {
          if(i.pause==='replace') await env.ARTIFACTS_FIXTURE.fetch('https://fixture.invalid/',{method:'POST',body:JSON.stringify({action:'configure',mode:'replaced-repo'})});
          if(i.dispose) repo[Symbol.dispose]();
          if(i.complete) {
            const r=await env.MINT_MAINTENANCE.lookup(i.input.attempt_id);
            await env.MINT_MAINTENANCE.record(i.input.attempt_id,r.plan.digest,i.complete);
          }
          return Response.json(await repo[i.method](i.argument));
        } finally {repo[Symbol.dispose]();}
      }
      if(i.action==='mint') return env.MINT_GATE.fetch('https://private.invalid/mint',{method:'POST',body:JSON.stringify(i.input)});
      if(i.action==='mint-public') return env.MINT_PUBLIC.fetch('https://private.invalid/mint',{method:'POST',body:'{}'});
      if(i.action==='mint-lookup') return Response.json(await env.MINT_LEDGER.lookup(i.attempt_id));
      if(i.action==='mint-claim') return Response.json(await env.MINT_LEDGER.claim(i.plan));
      if(i.action==='mint-ledger-call') return Response.json(await env.MINT_LEDGER[i.method](...(i.args??[i.input])));
      if(i.action==='execute') return env.EFFECT_GATE.fetch('https://private.invalid/initial',{method:'POST',body:JSON.stringify(i.input)});
      if(i.action==='reconcile') return env.EFFECT_RECONCILER.fetch('https://private.invalid/reconcile',{method:'POST',body:JSON.stringify(i.input)});
      if(i.action==='reconcile-public') return env.RECONCILE_PUBLIC.fetch('https://private.invalid/reconcile',{method:'POST',body:'{}'});
      if(i.action==='broker-public') return env.ARTIFACTS_MAINTENANCE_PUBLIC.fetch('https://private.invalid/',{method:'POST',body:'{}'});
      if(i.action==='broker-factory-call') return Response.json(await env.ARTIFACTS_MAINTENANCE[i.method](i.input));
      if(i.action==='lookup-call') return Response.json(await env.EFFECT_LOOKUP[i.method](i.input));
      if(i.action==='broker-call') {
        const repo=await env.ARTIFACTS_MAINTENANCE.open(i.input);
        try {
          if(i.pause==='replace') await env.ARTIFACTS_FIXTURE.fetch('https://fixture.invalid/',{method:'POST',body:JSON.stringify({action:'configure',mode:'replaced-repo'})});
          if(i.pause==='close') {
            const r=await env.EFFECT_MAINTENANCE.lookup(i.input.attempt_id), info=await repo.info(), ts=await repo.listTokens();
            await env.EFFECT_MAINTENANCE.observe(i.input.attempt_id,r.plan.digest,info.id);
            await env.EFFECT_LEDGER.close(i.input.attempt_id,r.plan.digest,{repo_id:info.id,token_id:ts.tokens[0].id,expires_at:null,receipt:'c'.repeat(64)});
          }
          if(i.dispose) repo[Symbol.dispose]();
          if(i.observe) {
            const r=await env.EFFECT_MAINTENANCE.lookup(i.input.attempt_id), info=await repo.info(), ts=await repo.listTokens();
            await env.EFFECT_MAINTENANCE.observe(i.input.attempt_id,r.plan.digest,info.id);
            await env.EFFECT_MAINTENANCE.observeToken(i.input.attempt_id,r.plan.digest,{repo_id:info.id,token_id:ts.tokens[0].id,scope:'write',expires_at:Math.ceil(Date.parse(ts.tokens[0].expiresAt)/1000)});
          }
          return Response.json(await repo[i.method](i.argument));
        } finally {repo[Symbol.dispose]();}
      }
      if(i.action==='maintenance-claim') return Response.json(await env.EFFECT_MAINTENANCE.claim(i.plan));
      if(i.action==='maintenance-record') return Response.json(await env.EFFECT_MAINTENANCE.recordRevocation(i.attempt_id,i.digest,i.value));
      if(i.action==='plan' || i.action==='capture') { const mint=i.input.action.includes('mint'); return (mint ? env.OP_MINT_STORE : env.OP_EFFECT_STORE).fetch('https://private.invalid/'+(mint?'mint-effect':'effect'),{method:'POST',body:JSON.stringify(i.input)}); }
      if(i.action==='store-call') return env[i.binding].fetch('https://private.invalid'+i.path,{method:'POST',body:JSON.stringify(i.input)});
      if(i.action==='mint-raw') return env.OP_MINT_STORE.administer_work_effect();
      if(i.action==='mint-admin-raw') return env.OP_MINT_STORE.administer_op_authority();
      if(i.action==='ledger-lookup') return Response.json(await env.EFFECT_LEDGER.lookup(i.attempt_id));
      if(i.action==='ledger-claim') return Response.json(await env.EFFECT_LEDGER.claim(i.plan));
      if(i.action==='public') return env.EFFECT_PUBLIC.fetch('https://private.invalid/initial',{method:'POST',body:'{}'});
      if(i.action==='public-raw') return env.OP_PUBLIC.administer_work_effect();
      if(i.action==='effect-raw') return env.OP_EFFECT_STORE.administer_work_effect();
      if(i.action==='effect-admin-raw') return env.OP_EFFECT_STORE.administer_op_authority();
      if(i.action==='admin-effect-raw') return env.OP_AUTHORITY_ADMIN.administer_work_effect();
      return env.ARTIFACTS_FIXTURE.fetch('https://fixture.invalid/',{method:'POST',body:JSON.stringify(i)});
    } catch {return Response.json({error:'fixture_effect_unavailable'},{status:409});}
  }
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
await build({
  entryPoints: [join(root, 'crates/worker/service/authority-admin-facade.ts')],
  bundle: true,
  format: 'esm',
  platform: 'browser',
  external: ['cloudflare:workers'],
  outfile: join(out, 'authority-admin-facade.mjs'),
});
await build({
  entryPoints: [join(root, 'crates/work-checkpoint-worker/worker.ts')],
  bundle: true,
  format: 'esm',
  platform: 'browser',
  external: ['cloudflare:workers'],
  outfile: join(out, 'checkpoint.mjs'),
});
for (const [source, name] of [
  ['local/conformance/support/work-source-reader.ts', 'source-reader.mjs'],
  ['crates/work-effect-worker/worker.ts', 'effect.mjs'],
  ['crates/work-effect-worker/mint.ts', 'mint.mjs'],
  ['crates/work-effect-worker/git.ts', 'git.mjs'],
  ['crates/work-effect-worker/git-transport.ts', 'git-transport.mjs'],
  ['crates/work-effect-worker/mint-maintenance.ts', 'mint-maintenance.mjs'],
  ['crates/work-effect-worker/mint-reconcile.ts', 'mint-reconcile.mjs'],
  ['crates/work-effect-worker/mint-closure.ts', 'mint-closure.mjs'],
  ['crates/work-effect-worker/mint-refusal-transport.ts', 'mint-refusal-transport.mjs'],
  ['crates/work-effect-worker/reconcile.ts', 'reconcile.mjs'],
  ['crates/work-effect-worker/maintenance.ts', 'maintenance.mjs'],
  ['local/conformance/support/work-effect-loss.ts', 'effect-loss.mjs'],
  ['local/conformance/support/work-artifacts-fixture.ts', 'artifacts-fixture.mjs'],
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
console.log(
  'Built current-main work authority/effect qualification fixture (synthetic verifier; never deploy).',
);
