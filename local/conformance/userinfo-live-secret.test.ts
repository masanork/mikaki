/** Real local Secrets Store binding and Rust claim Worker success path. */
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { chromium } from '@playwright/test';
import { build } from 'esbuild';
import { exportJWK, generateKeyPair } from 'jose';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { unstable_splitSqlQuery as splitSqlQuery } from 'wrangler';
import { activateWorkerPolicy } from '../../scripts/worker-policy-store.ts';
import { journeyRp } from './support/journey-rp.ts';
import { readProfileFromUserInfo } from './support/profile-rp.ts';

const root = fileURLToPath(new URL('../..', import.meta.url));
const claimBuild = fileURLToPath(
  new URL('../../crates/userinfo-claim-worker/build-conformance', import.meta.url),
);
const opBuild = fileURLToPath(new URL('../../crates/worker/build', import.meta.url));
const migrations = fileURLToPath(new URL('../../crates/worker/migrations', import.meta.url));
const secretName = 'VAULT_USERINFO_MLKEM_TEST';
const digest = (value: Uint8Array | string) =>
  createHash('sha256').update(value).digest('base64url');

async function createLocalSecret(state: string, storeId: string, value: string) {
  const child = spawn(
    process.execPath,
    [
      join(root, 'node_modules/wrangler/bin/wrangler.js'),
      'secrets-store',
      'secret',
      'create',
      storeId,
      '--name',
      secretName,
      '--scopes',
      'workers',
      '--persist-to',
      state,
    ],
    {
      cwd: root,
      env: { ...process.env, WRANGLER_LOG_PATH: join(state, 'wrangler.log') },
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

async function deleteLocalSecret(state: string, storeId: string, secretId: string) {
  const child = spawn(
    process.execPath,
    [
      join(root, 'node_modules/wrangler/bin/wrangler.js'),
      'secrets-store',
      'secret',
      'delete',
      storeId,
      '--secret-id',
      secretId,
      '--persist-to',
      state,
    ],
    {
      cwd: root,
      env: { ...process.env, WRANGLER_LOG_PATH: join(state, 'wrangler.log') },
      stdio: ['pipe', 'pipe', 'pipe'],
    },
  );
  child.stdin.end('y\n');
  let output = '';
  for (const stream of [child.stdout, child.stderr]) {
    stream.on('data', (chunk: Buffer) => {
      output += chunk.toString();
    });
  }
  const [exitCode] = await once(child, 'exit');
  assert.equal(exitCode, 0, `local Secrets Store deletion failed: ${output.slice(-500)}`);
}

test('live local Secrets Store decrypts consented name and writes disclosure audit', async () => {
  const temporary = await mkdtemp(join(tmpdir(), 'mikaki-userinfo-live-'));
  let mf: Miniflare | undefined;
  let browser: Awaited<ReturnType<typeof chromium.launch>> | undefined;
  try {
    const seed = randomBytes(64);
    const storeId = randomBytes(16).toString('hex');
    const secretId = await createLocalSecret(temporary, storeId, seed.toString('base64url'));
    const keys = ml_kem768.keygen(seed);
    seed.fill(0);
    const keyId = digest(keys.publicKey);
    const opKeys = await generateKeyPair('ES256', { extractable: true });
    const rpKeys = await generateKeyPair('ES256', { extractable: true });
    const opPublic = { ...(await exportJWK(opKeys.publicKey)), kid: 'op', alg: 'ES256' };
    const opPrivate = { ...(await exportJWK(opKeys.privateKey)), kid: 'op', alg: 'ES256' };
    const rpPublic = await exportJWK(rpKeys.publicKey);
    assert.ok(rpPublic.x && rpPublic.y);
    const rpSec1 = Buffer.concat([
      Buffer.from([4]),
      Buffer.from(rpPublic.x, 'base64url'),
      Buffer.from(rpPublic.y, 'base64url'),
    ]);
    let claimAvailable = true;
    let claimThrows = false;
    let beforeClaimFetch: (() => Promise<void>) | undefined;
    let beforeDisclosureAudit: (() => Promise<void>) | undefined;

    const options = convertV4MiniflareOptions({
      name: 'mikaki-userinfo-claim-worker',
      compatibilityDate: '2026-09-23',
      modules: true,
      scriptPath: join(claimBuild, 'index.js'),
      modulesRoot: claimBuild,
      resourcePersistencePath: join(temporary, 'v3'),
      bindings: { MIKAKI_ISSUER: 'https://mikaki.test' },
      d1Databases: { DB: 'mikaki-userinfo-live' },
      r2Buckets: { VAULT_BLOBS: 'mikaki-userinfo-live' },
      serviceBindings: {
        CONFORMANCE_GATE: async (request) => {
          assert.equal(new URL(request.url).pathname, '/after-decrypt');
          await beforeDisclosureAudit?.();
          return new Response(null, { status: 200 });
        },
      },
      secretsStoreSecrets: {
        [secretName]: { store_id: storeId, secret_name: secretName },
      },
    });
    options.workers[0].config.manifest!.modules['index_bg.wasm'] = {
      type: 'wasm',
      contents: new Uint8Array(await readFile(join(claimBuild, 'index_bg.wasm'))),
    };
    const opOptions = convertV4MiniflareOptions({
      name: 'mikaki-op-worker',
      compatibilityDate: '2026-09-23',
      modules: true,
      scriptPath: join(opBuild, 'index.js'),
      modulesRoot: opBuild,
      bindings: { MIKAKI_ISSUER: 'https://mikaki.test', OP_PRIVATE_JWK: JSON.stringify(opPrivate) },
      d1Databases: { DB: 'mikaki-userinfo-live' },
      r2Buckets: { VAULT_BLOBS: 'mikaki-userinfo-live' },
      serviceBindings: {
        USERINFO_CLAIMS: async (request, runtime) => {
          if (new URL(request.url).pathname === '/internal/claims/name') await beforeClaimFetch?.();
          if (claimThrows) throw new Error('simulated claim service transport failure');
          return claimAvailable
            ? (await runtime.getWorker('mikaki-userinfo-claim-worker')).fetch(request)
            : new Response(null, { status: 503 });
        },
      },
    });
    opOptions.workers[0].config.manifest!.modules['index_bg.wasm'] = {
      type: 'wasm',
      contents: new Uint8Array(await readFile(join(opBuild, 'index_bg.wasm'))),
    };
    options.workers.unshift(opOptions.workers[0]);
    mf = new Miniflare(options);
    const db = await mf.getD1Database('DB');
    for (const name of (await readdir(migrations)).filter((name) => name.endsWith('.sql')).sort()) {
      const statements = splitSqlQuery(await readFile(join(migrations, name), 'utf8'));
      await db.batch(statements.map((sql) => db.prepare(sql)));
    }
    await activateWorkerPolicy(
      db,
      JSON.parse(await readFile(join(root, 'local/generated/worker-policy.json'), 'utf8')),
      { actor: 'userinfo-live-test', reason: 'Profile RP authorization flow' },
    );

    const bundleDir = join(temporary, 'bundle');
    await build({
      entryPoints: [join(root, 'crates/worker/ui/vault-crypto.ts')],
      outdir: bundleDir,
      bundle: true,
      platform: 'node',
      format: 'esm',
      target: 'es2022',
      logLevel: 'silent',
    });
    const { sealAttribute, decodeBase64Url } = await import(
      pathToFileURL(join(bundleDir, 'vault-crypto.js')).href
    );
    const origin = 'https://mikaki.test';
    const sealed = await sealAttribute(
      new TextEncoder().encode('Alice'),
      new Uint8Array(32).fill(7),
      new Uint8Array([1, 2, 3]),
      new Uint8Array(32).fill(8),
      origin,
      'name',
      1,
    );
    const ciphertext = decodeBase64Url(sealed.ciphertext);
    const now = Math.floor(Date.now() / 1000);
    const access = randomBytes(32).toString('base64url');
    const accessHash = digest(access);
    const codeHash = digest('test-code');
    const blobs = await mf.getR2Bucket('VAULT_BLOBS');
    await blobs.put('name-object', ciphertext);
    await db.batch([
      db.prepare("INSERT INTO account_security VALUES('owner',1,1)"),
      db.prepare("INSERT INTO credential VALUES('AQID','owner',1)"),
      db.prepare(
        "INSERT INTO client(client_id,revision,active,sector_identifier) VALUES('rp',1,1,'https://rp.test')",
      ),
      db.prepare(
        "INSERT INTO client_redirect_uri(client_id,redirect_uri) VALUES('rp','https://rp.test/callback')",
      ),
      db.prepare("INSERT INTO client_key VALUES('rp','journey-rp',1,1,'ES256',?)").bind(rpSec1),
      db
        .prepare("INSERT INTO signing_key VALUES('op',1,1,'ES256',?)")
        .bind(JSON.stringify(opPublic)),
      db.prepare("INSERT INTO app_connection VALUES('owner','rp',1,1)"),
      db.prepare("INSERT INTO sso_session VALUES('sso','owner','AQID',1,?,0)").bind(now + 3600),
      db.prepare("INSERT INTO sso_context VALUES('sso',?,?)").bind(digest('cookie-secret'), now),
      db.prepare("INSERT INTO client_session VALUES('rp','sid','sso','owner','pairwise',1,0)"),
      db
        .prepare(
          "INSERT INTO authorization_code(code_hash,client_id,sid,client_revision,redirect_uri,pkce_challenge,expires_at,consumed_by,consumed_at) VALUES(?,'rp','sid',1,'https://rp.test/callback','',?,'issue',?)",
        )
        .bind(codeHash, now + 600, now),
      db
        .prepare("INSERT INTO code_context(code_hash,nonce,scope) VALUES(?,NULL,'openid profile')")
        .bind(codeHash),
      db
        .prepare(
          "INSERT INTO token_issue(code_hash,operation_id,access_hash,access_expires_at,signing_kid,issued_at,revoked) VALUES(?,'issue',?,?,'op',?,0)",
        )
        .bind(codeHash, accessHash, now + 600, now),
      db
        .prepare(
          "INSERT INTO vault_attribute_head VALUES('owner','name',1,1,'name-object',?,?,0,?)",
        )
        .bind(digest(ciphertext), sealed.owner_envelope, now),
      db
        .prepare(
          "INSERT INTO vault_recipient_key(key_id,service_id,algorithm,public_key,secret_ref,generation,state,revision,created_at) VALUES(?,'userinfo','ML-KEM-768',?,?,1,'staged',1,?)",
        )
        .bind(keyId, keys.publicKey, secretName, now),
    ]);
    await db
      .prepare(
        "UPDATE vault_recipient_key SET state='active',revision=revision+1,activated_at=? WHERE key_id=?",
      )
      .bind(now, keyId)
      .run();
    await db
      .prepare('UPDATE vault_share_policy SET enabled=1,revision=revision+1 WHERE id=1')
      .run();
    await db
      .prepare('UPDATE vault_claim_release_policy SET enabled=1,revision=revision+1 WHERE id=1')
      .run();

    const op = await mf.getWorker('mikaki-op-worker');
    const userinfo = () =>
      op.fetch('https://mikaki.test/userinfo', {
        headers: { Authorization: `Bearer ${access}` },
      });
    const beforeApproval = await userinfo();
    assert.equal(beforeApproval.status, 200);
    assert.deepEqual(await beforeApproval.json(), { sub: 'pairwise' });
    browser = await chromium.launch({ headless: true });
    const context = await browser.newContext({ locale: 'en-US' });
    await context.addCookies([
      {
        name: '__Host-op-sso',
        value: 'cookie-secret',
        url: origin,
        secure: true,
        httpOnly: true,
        sameSite: 'Lax',
      },
    ]);
    const page = await context.newPage();
    page.setDefaultTimeout(5000);
    const pageErrors: string[] = [];
    page.on('pageerror', (error) => pageErrors.push(error.message));
    await page.addInitScript(() => {
      class MockPublicKeyCredential {
        rawId = new Uint8Array([1, 2, 3]).buffer;
        getClientExtensionResults() {
          return { prf: { results: { first: new Uint8Array(32).fill(7).buffer } } };
        }
      }
      Object.defineProperty(window, 'PublicKeyCredential', { value: MockPublicKeyCredential });
      Object.defineProperty(navigator, 'credentials', {
        value: { get: async () => new MockPublicKeyCredential() },
      });
    });
    await page.route(`${origin}/**`, async (route) => {
      const request = route.request();
      const headers = { ...request.headers() };
      delete headers.host;
      delete headers['content-length'];
      if (request.method() === 'GET') delete headers.origin;
      const response = await mf!.dispatchFetch(request.url(), {
        method: request.method(),
        headers,
        redirect: 'manual',
        ...(['GET', 'HEAD'].includes(request.method())
          ? {}
          : { body: request.postDataBuffer() ?? undefined }),
      });
      await route.fulfill({
        status: response.status,
        headers: Object.fromEntries(response.headers),
        body: Buffer.from(await response.arrayBuffer()),
      });
    });
    const navigation = await page.goto(`${origin}/vault?lang=en`);
    assert.equal(navigation?.status(), 200, await page.locator('body').innerText());
    assert.deepEqual(pageErrors, []);
    await page.getByRole('button', { name: 'Unlock with passkey' }).click();
    await page.getByRole('button', { name: 'Share saved name with UserInfo service' }).click();
    await page.getByText('Your saved name is shared with the UserInfo service.').waitFor();
    const sharedWithoutRpConsent = await userinfo();
    assert.equal(sharedWithoutRpConsent.status, 200);
    assert.deepEqual(await sharedWithoutRpConsent.json(), { sub: 'pairwise' });
    await page.getByRole('button', { name: 'Allow this app to receive my name' }).click();
    await page.getByText('Name permission granted to this app.').waitFor();
    assert.deepEqual(pageErrors, []);
    assert.equal(await db.prepare('SELECT count(*) AS n FROM vault_attribute_grant').first('n'), 1);
    assert.equal(await db.prepare('SELECT count(*) AS n FROM vault_claim_release').first('n'), 1);
    assert.equal(
      await db.prepare('SELECT count(*) AS n FROM vault_attribute_share_audit').first('n'),
      1,
    );
    assert.equal(
      await db.prepare('SELECT count(*) AS n FROM vault_claim_release_audit').first('n'),
      1,
    );

    const claim = await mf.getWorker('mikaki-userinfo-claim-worker');
    const release = () =>
      claim.fetch('https://internal.invalid/internal/claims/name', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ access_hash: accessHash }),
      });
    const first = await release();
    assert.equal(first.status, 200, await first.clone().text());
    assert.deepEqual(await first.json(), { name: 'Alice' });
    assert.equal(
      await db.prepare('SELECT count(*) AS n FROM vault_claim_disclosure_audit').first('n'),
      1,
    );
    const discovery = await op.fetch('https://mikaki.test/.well-known/openid-configuration');
    assert.equal(discovery.status, 200);
    const metadata = (await discovery.json()) as {
      scopes_supported: string[];
      claims_supported: string[];
    };
    assert.ok(metadata.scopes_supported.includes('profile'));
    assert.ok(metadata.claims_supported.includes('name'));
    assert.ok(!metadata.claims_supported.includes('verified_claims'));
    const profile = await userinfo();
    assert.equal(profile.status, 200, await profile.clone().text());
    assert.deepEqual(await profile.json(), { sub: 'pairwise', name: 'Alice' });
    const rpRequest = (input: string, init?: RequestInit) =>
      op.fetch(input, init as Parameters<typeof op.fetch>[1]);
    assert.deepEqual(await readProfileFromUserInfo(origin, access, 'pairwise', rpRequest), {
      sub: 'pairwise',
      name: 'Alice',
    });
    await assert.rejects(
      readProfileFromUserInfo(origin, access, 'other-subject', async (input, init) => {
        if (String(input).endsWith('/userinfo'))
          return new Response(JSON.stringify({ sub: 'pairwise', name: 'Wrong account' }), {
            headers: { 'Content-Type': 'application/json' },
          });
        return rpRequest(input, init);
      }),
      /userinfo_subject_mismatch/,
    );
    await assert.rejects(
      readProfileFromUserInfo(
        origin,
        access,
        'pairwise',
        async () =>
          new Response(
            JSON.stringify({
              issuer: 'https://other.test',
              userinfo_endpoint: `${origin}/userinfo`,
            }),
            {
              headers: { 'Content-Type': 'application/json' },
            },
          ),
      ),
      /invalid_discovery/,
    );
    const rp = await journeyRp(
      origin,
      'https://rp.test',
      'rp',
      rpKeys.privateKey,
      opPublic,
      (url, init) => op.fetch(url, init),
      true,
    );
    async function completeRpLogin() {
      const login = await rp.handle(new Request('https://rp.test/login'));
      assert.equal(login.status, 302);
      const browserCookie = login.headers.get('set-cookie')!.split(';')[0];
      const authorizeUrl = login.headers.get('location')!;
      assert.equal(new URL(authorizeUrl).searchParams.get('scope'), 'openid profile');
      const authorize = await op.fetch(authorizeUrl, {
        headers: { Cookie: '__Host-op-sso=cookie-secret' },
        redirect: 'manual',
      });
      assert.equal(authorize.status, 302, await authorize.clone().text());
      const callbackUrl = authorize.headers.get('location')!;
      assert.equal(new URL(callbackUrl).origin, 'https://rp.test');
      const callback = await rp.handle(
        new Request(callbackUrl, { headers: { Cookie: browserCookie } }),
      );
      assert.equal(callback.status, 302, await callback.clone().text());
      assert.ok(rp.lastExchange);
    }
    await completeRpLogin();
    assert.ok(rp.lastProfile);
    assert.equal(rp.lastProfile.name, 'Alice');
    assert.ok(rp.lastProfile.sub);
    assert.equal(
      await db.prepare('SELECT count(*) AS n FROM vault_claim_disclosure_audit').first('n'),
      4,
    );
    await blobs.put('name-object', Buffer.from('tampered-ciphertext'));
    assert.equal((await release()).status, 503);
    assert.equal((await userinfo()).status, 503);
    assert.equal(
      await db.prepare('SELECT count(*) AS n FROM vault_claim_disclosure_audit').first('n'),
      4,
    );
    await blobs.put('name-object', ciphertext);
    assert.equal((await release()).status, 200);
    assert.equal(
      await db.prepare('SELECT count(*) AS n FROM vault_claim_disclosure_audit').first('n'),
      5,
    );
    await db
      .prepare(
        "CREATE TRIGGER test_fail_disclosure BEFORE INSERT ON vault_claim_disclosure_audit BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END",
      )
      .run();
    assert.equal((await release()).status, 503);
    assert.equal((await userinfo()).status, 503);
    assert.equal(
      await db.prepare('SELECT count(*) AS n FROM vault_claim_disclosure_audit').first('n'),
      5,
    );
    await db.prepare('DROP TRIGGER test_fail_disclosure').run();
    await page.getByRole('button', { name: 'Withdraw name permission' }).click();
    await page.getByText('Name permission withdrawn.').waitFor();
    assert.deepEqual(pageErrors, []);
    assert.equal(
      await db.prepare('SELECT count(*) AS n FROM vault_claim_release_audit').first('n'),
      2,
    );
    assert.equal((await release()).status, 204);
    const withdrawn = await userinfo();
    assert.equal(withdrawn.status, 200);
    assert.deepEqual(await withdrawn.json(), { sub: 'pairwise' });
    assert.deepEqual(await readProfileFromUserInfo(origin, access, 'pairwise', rpRequest), {
      sub: 'pairwise',
    });
    await completeRpLogin();
    assert.ok(rp.lastProfile);
    assert.equal(rp.lastProfile.name, undefined);
    assert.equal(
      await db.prepare('SELECT count(*) AS n FROM vault_claim_disclosure_audit').first('n'),
      5,
    );
    await page.getByRole('button', { name: 'Allow this app to receive my name' }).click();
    await page.getByText('Name permission granted to this app.').waitFor();
    assert.equal((await release()).status, 200);
    assert.equal(
      await db.prepare('SELECT count(*) AS n FROM vault_claim_disclosure_audit').first('n'),
      6,
    );
    await page.locator('#name').fill('Alice updated');
    await page.locator('#save').click();
    await page
      .locator('#status')
      .getByText('Saved. Unlock with your passkey to verify it.')
      .waitFor();
    assert.equal(
      await db
        .prepare("SELECT status FROM vault_attribute_grant WHERE account_id='owner'")
        .first('status'),
      'revoked',
    );
    assert.equal(
      await db
        .prepare("SELECT status FROM vault_claim_release WHERE account_id='owner'")
        .first('status'),
      'revoked',
    );
    assert.equal((await release()).status, 204);
    const staleRevision = await userinfo();
    assert.equal(staleRevision.status, 200);
    assert.deepEqual(await staleRevision.json(), { sub: 'pairwise' });
    await page.getByRole('button', { name: 'Unlock with passkey' }).click();
    await page.getByRole('button', { name: 'Share saved name with UserInfo service' }).click();
    await page.getByText('Your saved name is shared with the UserInfo service.').waitFor();
    await page.getByRole('button', { name: 'Allow this app to receive my name' }).click();
    await page.getByText('Name permission granted to this app.').waitFor();
    const revised = await userinfo();
    assert.equal(revised.status, 200);
    assert.deepEqual(await revised.json(), { sub: 'pairwise', name: 'Alice updated' });
    assert.equal(
      await db.prepare('SELECT count(*) AS n FROM vault_claim_disclosure_audit').first('n'),
      7,
    );
    await db.prepare("UPDATE client SET revision=2 WHERE client_id='rp'").run();
    assert.equal(
      await db
        .prepare("SELECT status FROM vault_claim_release WHERE account_id='owner'")
        .first('status'),
      'revoked',
    );
    assert.equal((await release()).status, 204);
    const oldRegistration = await userinfo();
    assert.equal(oldRegistration.status, 200);
    assert.deepEqual(await oldRegistration.json(), { sub: 'pairwise' });
    assert.equal(
      await db.prepare('SELECT count(*) AS n FROM vault_claim_disclosure_audit').first('n'),
      7,
    );
    await db.prepare("UPDATE client_key SET revision=2 WHERE client_id='rp'").run();
    await page.reload();
    await page.getByRole('button', { name: 'Unlock with passkey' }).click();
    await page.getByRole('button', { name: 'Allow this app to receive my name' }).click();
    await page.getByText('Name permission granted to this app.').waitFor();
    await completeRpLogin();
    assert.ok(rp.lastProfile);
    assert.equal(rp.lastProfile.name, 'Alice updated');
    assert.equal(
      await db.prepare('SELECT count(*) AS n FROM vault_claim_disclosure_audit').first('n'),
      8,
    );
    assert.ok(rp.lastAccessToken);
    const invalidToken = await op.fetch(`${origin}/userinfo`, {
      headers: { Authorization: `Bearer ${randomBytes(32).toString('base64url')}` },
    });
    assert.equal(invalidToken.status, 401);
    assert.match(invalidToken.headers.get('WWW-Authenticate') ?? '', /Bearer.*invalid_token/);
    assert.equal(invalidToken.headers.get('Retry-After'), null);
    const sessionView = await db
      .prepare("SELECT sql FROM sqlite_master WHERE type='view' AND name='valid_client_session'")
      .first<string>('sql');
    assert.ok(sessionView);
    await db.prepare('DROP VIEW valid_client_session').run();
    try {
      const brokenAuthority = await op.fetch(`${origin}/userinfo`, {
        headers: { Authorization: `Bearer ${rp.lastAccessToken}` },
      });
      assert.equal(brokenAuthority.status, 503);
      assert.equal(brokenAuthority.headers.get('Retry-After'), '5');
      assert.equal(
        await db.prepare('SELECT count(*) AS n FROM vault_claim_disclosure_audit').first('n'),
        8,
      );
    } finally {
      await db.prepare(sessionView).run();
    }
    const currentObject = await db
      .prepare(
        "SELECT object_key FROM vault_attribute_head WHERE account_id='owner' AND attribute_id='name'",
      )
      .first<string>('object_key');
    assert.ok(currentObject);
    const currentBlob = await blobs.get(currentObject);
    assert.ok(currentBlob);
    const currentCiphertext = await currentBlob.arrayBuffer();
    await blobs.delete(currentObject);
    const missingBlob = await op.fetch(`${origin}/userinfo`, {
      headers: { Authorization: `Bearer ${rp.lastAccessToken}` },
    });
    assert.equal(missingBlob.status, 503);
    assert.equal(
      await db.prepare('SELECT count(*) AS n FROM vault_claim_disclosure_audit').first('n'),
      8,
    );
    await blobs.put(currentObject, currentCiphertext);
    claimThrows = true;
    const transportFailure = await op.fetch(`${origin}/userinfo`, {
      headers: { Authorization: `Bearer ${rp.lastAccessToken}` },
    });
    assert.equal(transportFailure.status, 503);
    assert.equal(
      await db.prepare('SELECT count(*) AS n FROM vault_claim_disclosure_audit').first('n'),
      8,
    );
    claimThrows = false;
    claimAvailable = false;
    const claimOutage = await op.fetch(`${origin}/userinfo`, {
      headers: { Authorization: `Bearer ${rp.lastAccessToken}` },
    });
    assert.equal(claimOutage.status, 503);
    assert.equal(claimOutage.headers.get('Retry-After'), '5');
    assert.equal(claimOutage.headers.get('Cache-Control'), 'no-store');
    assert.equal(claimOutage.headers.get('WWW-Authenticate'), null);
    assert.equal(
      await db.prepare('SELECT count(*) AS n FROM vault_claim_disclosure_audit').first('n'),
      8,
    );
    claimAvailable = true;
    const restored = await op.fetch(`${origin}/userinfo`, {
      headers: { Authorization: `Bearer ${rp.lastAccessToken}` },
    });
    assert.equal(restored.status, 200);
    assert.deepEqual(await restored.json(), { sub: rp.lastProfile.sub, name: 'Alice updated' });
    assert.equal(
      await db.prepare('SELECT count(*) AS n FROM vault_claim_disclosure_audit').first('n'),
      9,
    );
    // Freeze the state after the same authority SELECT the claim Worker runs
    // before R2/Secrets Store decryption, then withdraw through the Vault UI.
    // The exact SQL used by its final audit must refuse that old snapshot.
    const claimSql = join(root, 'crates/userinfo-claim-worker/src');
    const activeRelease = await readFile(join(claimSql, 'active_name_release.sql'), 'utf8');
    const auditRelease = (await readFile(join(claimSql, 'audit_name_release.sql'), 'utf8')).replace(
      '{ACTIVE_NAME_RELEASE}',
      activeRelease,
    );
    const preDecrypt = await db
      .prepare(
        `SELECT v.account_id AS account_id,ac.client_id AS client_id,
          h.revision AS revision,r.version AS release_version,
          h.ciphertext_sha256 AS ciphertext_sha256,k.key_id AS key_id
          ${activeRelease}`,
      )
      .bind(digest(rp.lastAccessToken))
      .first<{
        account_id: string;
        client_id: string;
        revision: number;
        release_version: number;
        ciphertext_sha256: string;
        key_id: string;
      }>();
    assert.ok(preDecrypt);
    await page.getByRole('button', { name: 'Withdraw name permission' }).click();
    await page.getByText('Name permission withdrawn.').waitFor();
    const lateAudit = await db
      .prepare(auditRelease)
      .bind(
        digest(rp.lastAccessToken),
        preDecrypt.account_id,
        preDecrypt.client_id,
        preDecrypt.revision,
        preDecrypt.release_version,
        preDecrypt.ciphertext_sha256,
        preDecrypt.key_id,
      )
      .first('id');
    assert.equal(lateAudit, null);
    assert.equal(
      await db.prepare('SELECT count(*) AS n FROM vault_claim_disclosure_audit').first('n'),
      9,
    );
    await page.getByRole('button', { name: 'Allow this app to receive my name' }).click();
    await page.getByText('Name permission granted to this app.').waitFor();
    let enteredClaim!: () => void;
    const claimEntered = new Promise<void>((resolve) => (enteredClaim = resolve));
    let resumeClaim!: () => void;
    const claimResumed = new Promise<void>((resolve) => (resumeClaim = resolve));
    beforeClaimFetch = async () => {
      enteredClaim();
      await claimResumed;
    };
    const inFlight = op.fetch(`${origin}/userinfo`, {
      headers: { Authorization: `Bearer ${rp.lastAccessToken}` },
    });
    let entryTimeout: NodeJS.Timeout | undefined;
    try {
      await Promise.race([
        claimEntered,
        new Promise<void>((_, reject) => {
          entryTimeout = setTimeout(() => reject(new Error('claim service was not reached')), 5000);
        }),
      ]);
      await page.getByRole('button', { name: 'Withdraw name permission' }).click();
      await page.getByText('Name permission withdrawn.').waitFor();
    } finally {
      if (entryTimeout) clearTimeout(entryTimeout);
      resumeClaim();
      beforeClaimFetch = undefined;
    }
    const raced = await inFlight;
    assert.equal(raced.status, 200);
    assert.deepEqual(await raced.json(), { sub: rp.lastProfile.sub });
    assert.equal(
      await db.prepare('SELECT count(*) AS n FROM vault_claim_disclosure_audit').first('n'),
      9,
    );
    await page.getByRole('button', { name: 'Allow this app to receive my name' }).click();
    await page.getByText('Name permission granted to this app.').waitFor();
    await completeRpLogin();
    assert.ok(rp.lastProfile);
    assert.equal(rp.lastProfile.name, 'Alice updated');
    assert.equal(
      await db.prepare('SELECT count(*) AS n FROM vault_claim_disclosure_audit').first('n'),
      10,
    );
    let enteredAuditGate!: () => void;
    const auditGateEntered = new Promise<void>((resolve) => (enteredAuditGate = resolve));
    let resumeAuditGate!: () => void;
    const auditGateResumed = new Promise<void>((resolve) => (resumeAuditGate = resolve));
    beforeDisclosureAudit = async () => {
      enteredAuditGate();
      await auditGateResumed;
    };
    const decryptRace = op.fetch(`${origin}/userinfo`, {
      headers: { Authorization: `Bearer ${rp.lastAccessToken}` },
    });
    let auditGateTimeout: NodeJS.Timeout | undefined;
    try {
      await Promise.race([
        auditGateEntered,
        new Promise<void>((_, reject) => {
          auditGateTimeout = setTimeout(
            () => reject(new Error('post-decrypt gate not reached')),
            5000,
          );
        }),
      ]);
      await page.getByRole('button', { name: 'Withdraw name permission' }).click();
      await page.getByText('Name permission withdrawn.').waitFor();
    } finally {
      if (auditGateTimeout) clearTimeout(auditGateTimeout);
      resumeAuditGate();
      beforeDisclosureAudit = undefined;
    }
    const revokedDuringDecrypt = await decryptRace;
    assert.equal(revokedDuringDecrypt.status, 503);
    assert.equal(
      await db.prepare('SELECT count(*) AS n FROM vault_claim_disclosure_audit').first('n'),
      10,
    );
    await page.getByRole('button', { name: 'Allow this app to receive my name' }).click();
    await page.getByText('Name permission granted to this app.').waitFor();
    const afterDecryptRace = await op.fetch(`${origin}/userinfo`, {
      headers: { Authorization: `Bearer ${rp.lastAccessToken}` },
    });
    assert.equal(afterDecryptRace.status, 200);
    assert.deepEqual(await afterDecryptRace.json(), {
      sub: rp.lastProfile.sub,
      name: 'Alice updated',
    });
    assert.equal(
      await db.prepare('SELECT count(*) AS n FROM vault_claim_disclosure_audit').first('n'),
      11,
    );
    await deleteLocalSecret(temporary, storeId, secretId);
    const missingSecret = await op.fetch(`${origin}/userinfo`, {
      headers: { Authorization: `Bearer ${rp.lastAccessToken}` },
    });
    assert.equal(missingSecret.status, 503);
    assert.equal(
      await db.prepare('SELECT count(*) AS n FROM vault_claim_disclosure_audit').first('n'),
      11,
    );
    assert.equal(
      await db
        .prepare("SELECT status FROM vault_attribute_grant WHERE account_id='owner'")
        .first('status'),
      'active',
    );
    assert.equal(
      await db
        .prepare("SELECT status FROM vault_claim_release WHERE account_id='owner'")
        .first('status'),
      'active',
    );
    await db
      .prepare(
        "UPDATE vault_recipient_key SET state='disabled',revision=revision+1,retired_at=? WHERE key_id=?",
      )
      .bind(Math.floor(Date.now() / 1000), keyId)
      .run();
    assert.equal(
      await db
        .prepare("SELECT status FROM vault_attribute_grant WHERE account_id='owner'")
        .first('status'),
      'revoked',
    );
    assert.equal(
      await db
        .prepare("SELECT status FROM vault_claim_release WHERE account_id='owner'")
        .first('status'),
      'revoked',
    );
    assert.equal(
      (
        await op.fetch(`${origin}/vault/recipient-keys/userinfo`, {
          headers: { Cookie: '__Host-op-sso=cookie-secret' },
        })
      ).status,
      404,
    );
    assert.equal((await release()).status, 204);
    const disabledRecipient = await userinfo();
    assert.equal(disabledRecipient.status, 200);
    assert.deepEqual(await disabledRecipient.json(), { sub: 'pairwise' });
    await completeRpLogin();
    assert.ok(rp.lastProfile);
    assert.equal(rp.lastProfile.name, undefined);
    assert.equal(
      await db.prepare('SELECT count(*) AS n FROM vault_claim_disclosure_audit').first('n'),
      11,
    );
  } finally {
    await browser?.close();
    await mf?.dispose();
    await rm(temporary, { recursive: true, force: true });
  }
});
