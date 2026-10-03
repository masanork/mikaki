import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createServer } from 'node:http';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { chromium, firefox, webkit } from '@playwright/test';

test('browser WebCrypto owner lease opens many records once and rejects late unlock/locked reads', async () => {
  const bundle = await build({
    stdin: {
      resolveDir: fileURLToPath(new URL('../../', import.meta.url)),
      contents: `
import { createOwnerKey, rewrapOwnerKey, rewrapOwnerRecord, openOwnerKey, openOwnerRecord } from './crates/worker/ui/vault-owner-crypto.ts';
import { OwnerKeySession } from './crates/worker/ui/vault-owner-session.ts';
import { VaultScope } from './crates/worker/ui/vault-lifecycle.ts';
import { encodeBase64Url } from './crates/worker/ui/vault-crypto.ts';
window.ownerKeyProbe = async () => {
  const require = (condition, label) => { if (!condition) throw new Error(label); };
  const rejected = async (run,label) => { let failed=false;try{await run();}catch{failed=true;}require(failed,label); };
  const bytes = () => crypto.getRandomValues(new Uint8Array(32));
  const context = {origin:'https://auth.mikaki.org',ownerId:'owner',vaultId:'vault',keyGeneration:1};
  const item = {collectionId:'conversations',recordId:'thread-one-message',kind:'message',revision:1};
  const credential = bytes(), secret = bytes(), consumed = secret.slice();
  const {key,envelope} = await createOwnerKey(context,credential,bytes(),consumed);
  require(!key.extractable && consumed.every(x=>x===0),'nonextractable/consumed');
  await rejected(()=>crypto.subtle.exportKey('raw',key),'no root export');
  const identity={account_id:'owner',credential_id:encodeBase64Url(credential),session_tag:'s'.repeat(43)};
  const makeScope = () => {const s=new VaultScope(()=>{},undefined,undefined,async()=>Response.json(identity));s.observe(identity);return s;};
  let visible=true,calls=0;
  const scope=makeScope(),session=new OwnerKeySession(scope,context,()=>visible);
  const evaluate=async()=>{calls++;return {credentialId:credential,output:secret.slice()};};
  await session.unlock(envelope,evaluate);
  let record;
  for(let i=1;i<=10;i++) {
    const p=new TextEncoder().encode('会話の記録 '+i);
    record=await session.seal(p,item);
    const opened=await session.open(record,item);
    require(new TextDecoder().decode(opened)==='会話の記録 '+i,'round trip');opened.fill(0);
  }
  await session.unlock(envelope,evaluate);require(calls===1,'one ceremony');
  visible=false;session.suspend();await rejected(()=>session.open(record,item),'hidden read');
  visible=true;await session.resume();require(session.opened && calls===1,'resume without PRF');
  const target=bytes(),targetSecret=bytes();
  const targetWrap=await rewrapOwnerKey(envelope,context,credential,secret.slice(),target,bytes(),targetSecret.slice());
  const targetKey=await openOwnerKey(targetWrap,context,target,targetSecret.slice());
  const targetOpened=await openOwnerRecord(record,targetKey,context,item);require(targetOpened.length>0,'additional key');targetOpened.fill(0);
  const nextContext={...context,keyGeneration:2};
  const next=await createOwnerKey(nextContext,credential,bytes(),secret.slice());
  const rotated=await rewrapOwnerRecord(record,targetKey,context,next.key,nextContext,item);
  require(rotated.ciphertext===record.ciphertext,'rotation preserves ciphertext');
  const rotatedOpened=await openOwnerRecord(rotated,next.key,nextContext,item);require(rotatedOpened.length>0,'rotation round trip');rotatedOpened.fill(0);
  await rejected(()=>openOwnerRecord(rotated,targetKey,context,item),'old parent rejected');
  const pendingRead=session.open(record,item);session.lock();await rejected(()=>pendingRead,'late read');
  require(!session.opened,'locked');
  const lateSession=new OwnerKeySession(makeScope(),context);
  let resolve,entered;const started=new Promise(r=>entered=r),response=new Promise(r=>resolve=r);
  const pending=lateSession.unlock(envelope,async()=>{entered();return response;});await started;
  lateSession.dispose();const output=secret.slice();resolve({credentialId:credential,output});
  await rejected(()=>pending,'late unlock');require(output.every(x=>x===0)&&!lateSession.opened,'late PRF cleanup');
  return {ceremonies:calls,records:10,locked:!session.opened,lateRejected:!lateSession.opened};
};`,
    },
    bundle: true,
    write: false,
    format: 'iife',
    platform: 'browser',
  });
  const server = createServer((req, res) => {
    if (req.method !== 'GET') {
      res.writeHead(405).end();
      return;
    }
    if (req.url === '/')
      res
        .writeHead(200, { 'Content-Type': 'text/html', 'Cache-Control': 'no-store' })
        .end('<!doctype html><script src="/probe.js"></script>');
    else if (req.url === '/probe.js')
      res
        .writeHead(200, { 'Content-Type': 'text/javascript', 'Cache-Control': 'no-store' })
        .end(bundle.outputFiles[0]!.text);
    else res.writeHead(404).end();
  });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  assert(address && typeof address !== 'string');
  const engines =
    process.env['MIKAKI_OWNER_KEY_ALL_BROWSERS'] === '1'
      ? { chromium, firefox, webkit }
      : { chromium };
  try {
    for (const [name, engine] of Object.entries(engines)) {
      const browser = await engine.launch();
      try {
        const page = await browser.newPage();
        const errors: string[] = [];
        page.on('pageerror', (e: Error) => errors.push(String(e)));
        await page.goto(`http://127.0.0.1:${address.port}`);
        await page.waitForFunction(
          () =>
            typeof (window as Window & { ownerKeyProbe?: unknown }).ownerKeyProbe === 'function',
        );
        const result = await page.evaluate('window.ownerKeyProbe()');
        assert.deepEqual(
          result,
          { ceremonies: 1, records: 10, locked: true, lateRejected: true },
          name,
        );
        assert.deepEqual(
          await page.evaluate(async () => ({
            local: localStorage.length,
            session: sessionStorage.length,
            idb: (await indexedDB.databases()).length,
            caches: (await caches.keys()).length,
          })),
          { local: 0, session: 0, idb: 0, caches: 0 },
        );
        assert.deepEqual(errors, [], name);
      } finally {
        await browser.close();
      }
    }
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});
