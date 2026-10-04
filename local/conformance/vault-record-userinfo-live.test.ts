/** CI-only runtime qualification: real Rust Workers, disposable Secrets Store and browser WebCrypto. */
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { chromium } from '@playwright/test';
import { build } from 'esbuild';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { unstable_splitSqlQuery as splitSqlQuery } from 'wrangler';
import { OwnerKeySession } from '../../crates/worker/ui/vault-owner-session.ts';
import { VaultScope } from '../../crates/worker/ui/vault-lifecycle.ts';
import { vaultCiphertextDigest } from '../../crates/worker/ui/vault-record-source.ts';
import { fetchVerifiedRecordUserInfoRecipient } from '../../crates/worker/ui/recipient-directory-v2.ts';
import { encodeBase64Url } from '../../crates/worker/ui/vault-crypto.ts';
import { activateWorkerPolicy } from '../../scripts/worker-policy-store.ts';
const root = fileURLToPath(new URL('../..', import.meta.url));
const secretName = 'VAULT_USERINFO_MLKEM_TEST';
const digest = (v: Uint8Array | string) => createHash('sha256').update(v).digest('base64url');
async function createLocalSecret(state: string, storeId: string, value: string) {
  // Use an isolated config so Wrangler cannot discover repository production bindings.
  const config = join(state, 'wrangler.json');
  await writeFile(
    config,
    JSON.stringify({
      name: 'record-userinfo-local-test',
      compatibility_date: '2026-09-23',
      send_metrics: false,
    }),
  );
  const child = spawn(
    process.execPath,
    [
      join(root, 'node_modules/wrangler/bin/wrangler.js'),
      '--config',
      config,
      'secrets-store',
      'secret',
      'create',
      storeId,
      '--name',
      secretName,
      '--scopes',
      'workers',
      '--remote=false',
      '--persist-to',
      state,
    ],
    {
      cwd: state,
      env: {
        ...process.env,
        CI: 'true',
        WRANGLER_SEND_METRICS: 'false',
        WRANGLER_LOG_PATH: join(state, 'wrangler.log'),
      },
      stdio: ['pipe', 'pipe', 'pipe'],
    },
  );
  // Do not put the seed in command arguments, fixture files, or test output.
  child.stdin.end(`${value}\n`);
  let output = '';
  for (const stream of [child.stdout, child.stderr]) {
    stream.on('data', (chunk: Buffer) => {
      output += chunk.toString();
    });
  }
  const [exitCode] = await once(child, 'exit');
  assert.equal(exitCode, 0, `local Secrets Store setup failed: ${output.slice(-500)}`);
  const secretId = output.match(new RegExp(`│\\s*${secretName}\\s*│\\s*([a-f0-9]{32})\\s*│`))?.[1];
  assert.ok(secretId, 'local Secrets Store did not return a secret ID');
  return secretId;
}

async function qualifyRecordUserInfo(browserCrypto: boolean) {
  const temporary = await mkdtemp(join(tmpdir(), 'mikaki-record-userinfo-'));
  let mf: Miniflare | undefined;
  let browser: Awaited<ReturnType<typeof chromium.launch>> | undefined;
  let releaseGate: (() => void) | undefined;
  try {
    const seed = randomBytes(64),
      storeId = randomBytes(16).toString('hex');
    await createLocalSecret(temporary, storeId, seed.toString('base64url'));
    const keys = ml_kem768.keygen(seed);
    seed.fill(0);
    const keyId = digest(keys.publicKey);
    const origin = 'https://mikaki.test';
    let beforeAudit: (() => Promise<void>) | undefined;
    let claimFailure: 'none' | 'throw' | 'unavailable' | 'missing-secret' = 'none';
    const claimBuild = join(root, 'crates/userinfo-claim-worker/build-conformance');
    const opBuild = join(root, 'crates/worker/build');
    const authorityBuild = join(temporary, 'authority');
    await mkdir(authorityBuild);
    await build({
      entryPoints: [join(root, 'crates/worker/service/entrypoint.ts')],
      outfile: join(authorityBuild, 'index.js'),
      bundle: true,
      format: 'esm',
      platform: 'browser',
      target: 'es2022',
      external: ['cloudflare:workers'],
      loader: { '.sql': 'text' },
      plugins: [
        {
          name: 'wasm-reference',
          setup(builder) {
            builder.onResolve({ filter: /\.wasm$/ }, () => ({
              path: './index_bg.wasm',
              external: true,
            }));
          },
        },
      ],
    });
    const options = convertV4MiniflareOptions({
      name: 'mikaki-userinfo-claim-worker',
      compatibilityDate: '2026-09-23',
      modules: true,
      scriptPath: join(claimBuild, 'index.js'),
      modulesRoot: claimBuild,
      resourcePersistencePath: join(temporary, 'v3'),
      bindings: { MIKAKI_ISSUER: origin },
      serviceBindings: {
        CLAIM_STORE: { name: 'mikaki-op-worker', entrypoint: 'ClaimStore' },
        CONFORMANCE_GATE: async () => {
          await beforeAudit?.();
          return new Response(null, { status: 200 });
        },
      },
      secretsStoreSecrets: { [secretName]: { store_id: storeId, secret_name: secretName } },
    });
    options.workers[0].config.manifest!.modules['index_bg.wasm'] = {
      type: 'wasm',
      contents: new Uint8Array(await readFile(join(claimBuild, 'index_bg.wasm'))),
    };
    const opOptions = convertV4MiniflareOptions({
      name: 'mikaki-op-worker',
      // Register only this synthetic host with Miniflare's local request proxy.
      routes: ['mikaki.test/*'],
      compatibilityDate: '2026-09-23',
      modules: true,
      scriptPath: join(authorityBuild, 'index.js'),
      modulesRoot: authorityBuild,
      bindings: { MIKAKI_ISSUER: origin },
      d1Databases: { DB: 'record-userinfo' },
      r2Buckets: { VAULT_BLOBS: 'record-userinfo' },
      serviceBindings: {
        USERINFO_CLAIMS: async (request, runtime) => {
          if (claimFailure === 'throw') throw new Error('simulated claim transport failure');
          if (claimFailure === 'unavailable') return new Response(null, { status: 503 });
          const name =
            claimFailure === 'missing-secret'
              ? 'claims-without-secret'
              : 'mikaki-userinfo-claim-worker';
          return (await runtime.getWorker(name)).fetch(request);
        },
      },
    });
    opOptions.workers[0].config.manifest!.modules['index_bg.wasm'] = {
      type: 'wasm',
      contents: new Uint8Array(await readFile(join(opBuild, 'index_bg.wasm'))),
    };
    const noSecret = convertV4MiniflareOptions({
      name: 'claims-without-secret',
      compatibilityDate: '2026-09-23',
      modules: true,
      scriptPath: join(claimBuild, 'index.js'),
      modulesRoot: claimBuild,
      bindings: { MIKAKI_ISSUER: origin },
      serviceBindings: { CLAIM_STORE: { name: 'mikaki-op-worker', entrypoint: 'ClaimStore' } },
    });
    noSecret.workers[0].config.manifest!.modules['index_bg.wasm'] =
      options.workers[0].config.manifest!.modules['index_bg.wasm'];
    options.workers.push(noSecret.workers[0]);
    options.workers.unshift(opOptions.workers[0]);
    mf = new Miniflare(options);
    const db = await mf.getD1Database('DB'),
      blobs = await mf.getR2Bucket('VAULT_BLOBS');
    for (const name of (await readdir(join(root, 'crates/worker/migrations')))
      .filter((n) => n.endsWith('.sql'))
      .sort())
      await db.batch(
        splitSqlQuery(await readFile(join(root, 'crates/worker/migrations', name), 'utf8')).map(
          (s) => db.prepare(s),
        ),
      );
    await activateWorkerPolicy(
      db,
      JSON.parse(await readFile(join(root, 'local/generated/worker-policy.json'), 'utf8')),
      { actor: 'record-userinfo-test', reason: 'Isolated v2 profile qualification' },
    );
    const now = Math.floor(Date.now() / 1000),
      cookie = randomBytes(32).toString('base64url'),
      access = randomBytes(32).toString('base64url');
    await db.batch([
      db.prepare("INSERT INTO account_security VALUES('owner',1,1)"),
      db.prepare("INSERT INTO credential VALUES('AQ','owner',1)"),
      db.prepare("INSERT INTO sso_session VALUES('sso','owner','AQ',1,?,0)").bind(now + 3600),
      db.prepare("INSERT INTO sso_context VALUES('sso',?,?)").bind(digest(cookie), now),
      db.prepare(
        "INSERT INTO client(client_id,revision,active,sector_identifier) VALUES('rp',1,1,'https://rp.test')",
      ),
      db.prepare(
        "INSERT INTO client_redirect_uri(client_id,redirect_uri) VALUES('rp','https://rp.test/callback')",
      ),
      db.prepare("INSERT INTO app_connection VALUES('owner','rp',1,1)"),
      db.prepare("INSERT INTO client_session VALUES('rp','sid','sso','owner','pairwise',1,0)"),
      db.prepare("INSERT INTO signing_key VALUES('op',1,1,'ES256','{}')"),
      db
        .prepare(
          "INSERT INTO authorization_code(code_hash,client_id,sid,client_revision,redirect_uri,pkce_challenge,expires_at,consumed_by,consumed_at) VALUES(?,'rp','sid',1,'https://rp.test/callback','',?,'issue',?)",
        )
        .bind(digest('code'), now + 60, now),
      db
        .prepare("INSERT INTO code_context(code_hash,nonce,scope) VALUES(?,NULL,'openid profile')")
        .bind(digest('code')),
      db
        .prepare(
          "INSERT INTO token_issue(code_hash,operation_id,access_hash,access_expires_at,signing_kid,issued_at,revoked) VALUES(?,'issue',?,?,'op',?,0)",
        )
        .bind(digest('code'), digest(access), now + 3600, now),
      db
        .prepare(
          "INSERT INTO vault_recipient_key(key_id,service_id,algorithm,public_key,secret_ref,generation,state,revision,created_at) VALUES(?,'userinfo','ML-KEM-768',?,?,1,'staged',1,?)",
        )
        .bind(keyId, keys.publicKey, secretName, now),
    ]);
    await db
      .prepare(
        "UPDATE vault_recipient_key SET state='active',revision=2,activated_at=? WHERE key_id=?",
      )
      .bind(now, keyId)
      .run();
    const op = await mf.getWorker('mikaki-op-worker');
    const userinfo = () =>
      op.fetch(origin + '/userinfo', { headers: { Authorization: `Bearer ${access}` } });
    assert.deepEqual(await (await userinfo()).json(), { sub: 'pairwise' });
    let prepared: any;
    if (browserCrypto) {
      const bundle = await build({
        stdin: {
          resolveDir: root,
          contents: `
import { OwnerKeySession } from './crates/worker/ui/vault-owner-session.ts';
import { VaultScope } from './crates/worker/ui/vault-lifecycle.ts';
import { vaultCiphertextDigest } from './crates/worker/ui/vault-record-source.ts';
import { fetchVerifiedRecordUserInfoRecipient } from './crates/worker/ui/recipient-directory-v2.ts';
import { encodeBase64Url } from './crates/worker/ui/vault-crypto.ts';
window.recordProbe=async()=>{
 const identity={account_id:'owner',credential_id:'AQ',session_tag:'s'.repeat(43)};
 const scope=new VaultScope(()=>{},undefined,undefined,async()=>Response.json(identity));scope.observe(identity);
 const context={origin:'https://mikaki.test',ownerId:'owner',vaultId:'vault',keyGeneration:1};
 const session=new OwnerKeySession(scope,context);let ceremonies=0;
 const ownerEnvelope=await session.initialize(async()=>{ceremonies++;return{credentialId:new Uint8Array([1]),output:new Uint8Array(32).fill(4)}});
 const record=await session.seal(new TextEncoder().encode('Alice 山田 😀'),{collectionId:'personal',recordId:'name',kind:'name',revision:1});
 const source={storage_version:2,origin:context.origin,owner_id:'owner',vault_id:'vault',collection_id:'personal',record_id:'name',kind:'name',revision:1,ciphertext_sha256:await vaultCiphertextDigest(record.ciphertext)};
 const authority={key_generation:1,owner_key_revision:1};const recipient=await fetchVerifiedRecordUserInfoRecipient(fetch,localStorage);
 const frame=encodeBase64Url(await session.sealUserInfoRecipient(record,source,authority,recipient));
 const pending=session.sealUserInfoRecipient(record,source,authority,recipient);session.suspend();let rejected=false;try{await pending}catch{rejected=true}if(!rejected)throw new Error('late result escaped');session.dispose();
 return{ownerEnvelope,record,source,authority,recipient,frame,ceremonies,lateRejected:rejected};
};`,
        },
        bundle: true,
        write: false,
        format: 'iife',
        platform: 'browser',
      });
      browser = await chromium.launch();
      const page = await browser.newPage();
      await page.context().addCookies([
        {
          name: '__Host-op-sso',
          value: cookie,
          url: origin,
          secure: true,
          httpOnly: true,
          sameSite: 'Lax',
        },
      ]);
      await page.route(origin + '/**', async (route) => {
        const request = route.request();
        const path = new URL(request.url()).pathname;
        if (path === '/probe') {
          await route.fulfill({
            status: 200,
            contentType: 'text/html',
            body: '<!doctype html><script src="/probe.js"></script>',
          });
          return;
        }
        if (path === '/probe.js') {
          await route.fulfill({
            status: 200,
            contentType: 'text/javascript',
            body: bundle.outputFiles[0]!.text,
          });
          return;
        }
        const response = await op.fetch(request.url(), {
          method: request.method(),
          headers: await request.allHeaders(),
          body: request.postDataBuffer() ?? undefined,
        });
        await route.fulfill({
          status: response.status,
          headers: Object.fromEntries(response.headers.entries()),
          body: Buffer.from(await response.arrayBuffer()),
        });
      });
      await page.goto(origin + '/probe');
      prepared = await page.evaluate(() =>
        (window as unknown as { recordProbe: () => Promise<any> }).recordProbe(),
      );
    } else {
      const identity = { account_id: 'owner', credential_id: 'AQ', session_tag: 's'.repeat(43) };
      const scope = new VaultScope(
        () => {},
        undefined,
        undefined,
        async () => Response.json(identity),
      );
      scope.observe(identity);
      const context = { origin, ownerId: 'owner', vaultId: 'vault', keyGeneration: 1 };
      const session = new OwnerKeySession(scope, context);
      let ceremonies = 0;
      const ownerEnvelope = await session.initialize(async () => {
        ceremonies++;
        return { credentialId: new Uint8Array([1]), output: new Uint8Array(32).fill(4) };
      });
      const record = await session.seal(new TextEncoder().encode('Alice 山田 😀'), {
        collectionId: 'personal',
        recordId: 'name',
        kind: 'name',
        revision: 1,
      });
      const source = {
        storage_version: 2 as const,
        origin,
        owner_id: 'owner',
        vault_id: 'vault',
        collection_id: 'personal' as const,
        record_id: 'name' as const,
        kind: 'name' as const,
        revision: 1,
        ciphertext_sha256: await vaultCiphertextDigest(record.ciphertext),
      };
      const authority = { key_generation: 1, owner_key_revision: 1 };
      const storage = new Map<string, string>();
      const recipient = await fetchVerifiedRecordUserInfoRecipient(
        (async (input: string | URL | Request, init?: RequestInit) => {
          const requestHeaders = new Headers(init?.headers);
          requestHeaders.set('Cookie', `__Host-op-sso=${cookie}`);
          const response = await op.fetch(new URL(String(input), origin), {
            method: init?.method ?? 'GET',
            headers: Object.fromEntries(requestHeaders.entries()),
          });
          return new Response(await response.arrayBuffer(), {
            status: response.status,
            headers: Object.fromEntries(response.headers.entries()),
          });
        }) as typeof fetch,
        {
          getItem: (key) => storage.get(key) ?? null,
          setItem: (key, value) => {
            storage.set(key, value);
          },
        },
      );
      const frame = encodeBase64Url(
        await session.sealUserInfoRecipient(record, source, authority, recipient),
      );
      const pending = session.sealUserInfoRecipient(record, source, authority, recipient);
      session.suspend();
      let lateRejected = false;
      try {
        await pending;
      } catch {
        lateRejected = true;
      }
      session.dispose();
      prepared = {
        ownerEnvelope,
        record,
        source,
        authority,
        recipient,
        frame,
        ceremonies,
        lateRejected,
      };
    }
    assert.equal(prepared.ceremonies, 1);
    assert.equal(prepared.lateRejected, true);
    await blobs.put('record-blob', Buffer.from(prepared.record.ciphertext, 'base64url'));
    await db.batch([
      db
        .prepare(
          "INSERT INTO vault_owner_key_head VALUES('owner','vault',?,1,1,2,'PRF-HKDF-SHA256-AES256GCM-v2',?,?,?)",
        )
        .bind(origin, digest('root-op'), digest('root-body'), now),
      db
        .prepare("INSERT INTO vault_owner_key_wrap VALUES('owner',1,'AQ',?)")
        .bind(JSON.stringify(prepared.ownerEnvelope)),
      db
        .prepare(
          "INSERT INTO vault_owner_record_head VALUES('owner','vault','personal','name','name',1,1,2,'record-blob',?,?,0,?)",
        )
        .bind(prepared.source.ciphertext_sha256, prepared.record.key_envelope, now),
    ]);
    const operation = () => randomBytes(32).toString('base64url');
    const headers = (id: string, version: number) => ({
      Cookie: `__Host-op-sso=${cookie}`,
      Origin: origin,
      'Content-Type': 'application/json',
      'X-Operation-ID': id,
      'If-Match': `"${version}"`,
    });
    const sharing = origin + '/vault/records/personal/name/sharing',
      releases = origin + '/vault/records/personal/name/releases';
    const shareBody = {
      source: prepared.source,
      authority: prepared.authority,
      key_id: keyId,
      generation: 1,
      directory_revision: 2,
      policy_revision: 2,
      expected_grant_version: 0,
      frame: prepared.frame,
    };
    const shareId = operation();
    const share = () =>
      op.fetch(sharing, {
        method: 'POST',
        headers: headers(shareId, 1),
        body: JSON.stringify(shareBody),
      });
    const disabledShare = await share();
    assert.equal(disabledShare.status, 403);
    assert.deepEqual(await disabledShare.json(), { error: 'sharing_disabled_or_changed' });
    await db.prepare('UPDATE vault_record_share_policy SET enabled=1,revision=2').run();
    let response = await share();
    assert.equal(response.status, 200, await response.text());
    assert.equal((await share()).status, 200);
    assert.equal(
      (
        await op.fetch(sharing, {
          method: 'POST',
          headers: headers(shareId, 1),
          body: JSON.stringify({ ...shareBody, directory_revision: 1 }),
        })
      ).status,
      409,
    );
    assert.deepEqual(await (await userinfo()).json(), { sub: 'pairwise' });
    const stale = await op.fetch(sharing, {
      method: 'POST',
      headers: headers(operation(), 1),
      body: JSON.stringify({ ...shareBody, expected_grant_version: 1, directory_revision: 1 }),
    });
    assert.equal(stale.status, 409);
    await db
      .prepare(
        "CREATE TRIGGER fail_share_audit BEFORE INSERT ON vault_record_share_audit BEGIN SELECT RAISE(ABORT,'test');END",
      )
      .run();
    const failed = await op.fetch(sharing, {
      method: 'POST',
      headers: headers(operation(), 1),
      body: JSON.stringify({ ...shareBody, expected_grant_version: 1 }),
    });
    assert.equal(failed.status, 409);
    assert.equal(
      await db.prepare('SELECT count(*) AS n FROM vault_record_recipient_envelope').first('n'),
      1,
    );
    await db.prepare('DROP TRIGGER fail_share_audit').run();
    await db.prepare('UPDATE vault_claim_release_policy SET enabled=1,revision=2').run();
    const consentBody = {
      source: prepared.source,
      authority: prepared.authority,
      client_id: 'rp',
      client_revision: 1,
      connection_grant_version: 1,
      policy_revision: 2,
      expected_release_version: 0,
    };
    const consent = () =>
      op.fetch(releases, {
        method: 'POST',
        headers: headers(operation(), 1),
        body: JSON.stringify(consentBody),
      });
    response = await consent();
    assert.equal(response.status, 200, await response.text());
    response = await userinfo();
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { sub: 'pairwise', name: 'Alice 山田 😀' });
    const audits = () =>
      db.prepare('SELECT count(*) AS n FROM vault_claim_disclosure_audit').first<number>('n');
    assert.equal(await audits(), 1);
    const assertUnavailable = async () => {
      const result = await userinfo();
      assert.equal(result.status, 503);
      assert.equal(result.headers.get('Retry-After'), '5');
      assert.equal(result.headers.get('Cache-Control'), 'no-store');
      assert.equal(result.headers.get('WWW-Authenticate'), null);
      assert.ok(!(await result.text()).includes('Alice'));
      assert.equal(await audits(), 1, 'failure must not create disclosure evidence');
    };
    for (const failure of ['missing-secret', 'throw', 'unavailable'] as const) {
      claimFailure = failure;
      await assertUnavailable();
    }
    claimFailure = 'none';
    await blobs.put('record-blob', Buffer.from('tampered-ciphertext'));
    await assertUnavailable();
    await blobs.delete('record-blob');
    await assertUnavailable();
    await blobs.put('record-blob', Buffer.from(prepared.record.ciphertext, 'base64url'));
    const view = await db
      .prepare("SELECT sql FROM sqlite_master WHERE type='view' AND name='valid_client_session'")
      .first<string>('sql');
    assert.ok(view);
    await db.prepare('DROP VIEW valid_client_session').run();
    try {
      await assertUnavailable();
    } finally {
      await db.prepare(view).run();
    }
    const invalidToken = await op.fetch(origin + '/userinfo', {
      headers: { Authorization: `Bearer ${randomBytes(32).toString('base64url')}` },
    });
    assert.equal(invalidToken.status, 401);
    assert.match(invalidToken.headers.get('WWW-Authenticate') ?? '', /Bearer.*invalid_token/);
    assert.equal(invalidToken.headers.get('Retry-After'), null);
    assert.equal(await audits(), 1);
    let entered!: () => void;
    const enteredPromise = new Promise<void>((resolve) => (entered = resolve));
    const resume = new Promise<void>((resolve) => (releaseGate = resolve));
    beforeAudit = async () => {
      entered();
      await resume;
    };
    const pending = userinfo();
    await Promise.race([
      enteredPromise,
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error('postdecrypt gate not reached')), 5000),
      ),
    ]);
    response = await op.fetch(releases, {
      method: 'DELETE',
      headers: headers(operation(), 1),
      body: JSON.stringify({ client_id: 'rp' }),
    });
    assert.equal(response.status, 200, await response.text());
    releaseGate!();
    beforeAudit = undefined;
    assert.equal((await pending).status, 503);
    assert.equal(await audits(), 1);
    assert.deepEqual(await (await userinfo()).json(), { sub: 'pairwise' });
    consentBody.expected_release_version = 2;
    response = await consent();
    assert.equal(response.status, 200, await response.text());
    await db
      .prepare(
        "CREATE TRIGGER fail_record_audit BEFORE INSERT ON vault_claim_disclosure_audit BEGIN SELECT RAISE(ABORT,'test'); END",
      )
      .run();
    assert.equal((await userinfo()).status, 503);
    assert.equal(await audits(), 1);
    await db.prepare('DROP TRIGGER fail_record_audit').run();
    await db
      .prepare(
        "UPDATE vault_recipient_key SET state='disabled',revision=3,retired_at=unixepoch() WHERE key_id=?",
      )
      .bind(keyId)
      .run();
    assert.deepEqual(await (await userinfo()).json(), { sub: 'pairwise' });
    assert.equal(
      (await share()).status,
      200,
      'historical exact receipt remains an acknowledgement',
    );
    assert.equal(
      await db.prepare('SELECT status FROM vault_record_grant').first('status'),
      'revoked',
    );
    assert.equal(await audits(), 1);
  } finally {
    releaseGate?.();
    await browser?.close();
    await mf?.dispose();
    await rm(temporary, { recursive: true, force: true });
  }
}

test('workerd v2 recipient, real sharing CAS, selected RP consent and postdecrypt withdrawal', () =>
  qualifyRecordUserInfo(false));
test('browser v2 recipient, real sharing CAS, selected RP consent and postdecrypt withdrawal', () =>
  qualifyRecordUserInfo(true));
