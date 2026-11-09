import assert from 'node:assert/strict';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { mkdtemp, cp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateKeyPair, exportJWK } from 'jose';
import { createTestHarness } from 'wrangler';
import { activateWorkerPolicy } from './worker-policy-store.ts';
import { registerNativeClient } from './client-admin-store.ts';
const bridgeRoot = process.cwd(),
  root = process.env.MIKAKI_ACCESS_FEATURE_CHECKOUT;
if (!root) throw new Error('MIKAKI_ACCESS_FEATURE_CHECKOUT must point to the feature checkout');
const dir = await mkdtemp(join(tmpdir(), 'mikaki-bridge-'));
const migrations = join(root, 'crates/worker/migrations');
const names = [
  '0001_owner_vault_initial.sql',
  '0002_owner_key_wrap_operations.sql',
  '0003_enrollment_waitlist.sql',
  '0004_identity_age_requests.sql',
  '0005_login_connection_review.sql',
  '0006_owner_login_wrap.sql',
  '0007_passport_issuance.sql',
  '0008_dbsc_sessions.sql',
  '0009_client_secret_rotation.sql',
  '0010_verified_email.sql',
  '0011_access_email_bindings.sql',
  '0012_access_email_scope.sql',
];
for (const name of names.slice(0, 10)) await cp(join(migrations, name), join(dir, name));
const stub = join(dir, 'claims.mjs');
await writeFile(stub, 'export default { fetch(){ return new Response(null,{status:204}) } };');
const keys = await generateKeyPair('ES256', { extractable: true });
const publicJwk = { ...(await exportJWK(keys.publicKey)), kid: 'bridge-test', alg: 'ES256' };
const privateJwk = { ...(await exportJWK(keys.privateKey)), kid: 'bridge-test', alg: 'ES256' };
const ready = 'AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA';
const config = {
  name: 'bridge',
  main: join(bridgeRoot, 'crates/worker/build/worker/shim.mjs'),
  compatibility_date: '2026-09-23',
  assets: {
    directory: join(root, 'assets'),
    binding: 'FONT_ASSETS',
    run_worker_first: true,
    html_handling: 'none',
    not_found_handling: 'none',
  },
  version_metadata: { binding: 'CF_VERSION_METADATA' },
  d1_databases: [
    {
      binding: 'DB',
      database_name: 'bridge-db',
      database_id: '00000000-0000-0000-0000-000000000000',
      migrations_dir: dir,
      remote: false,
    },
  ],
  r2_buckets: [{ binding: 'VAULT_BLOBS', bucket_name: 'bridge-bucket' }],
  services: [{ binding: 'USERINFO_CLAIMS', service: 'bridge-claims' }],
  vars: {
    MIKAKI_ISSUER: 'https://bridge.example',
    OP_PRIVATE_JWK: JSON.stringify(privateJwk),
    MIKAKI_READY_TOKEN: ready,
  },
};
const harness = createTestHarness({
  root,
  workers: [
    { config },
    {
      config: {
        ...config,
        name: 'feature',
        main: join(root, 'crates/worker/build/worker/shim.mjs'),
      },
    },
    { config: { name: 'bridge-claims', main: stub, compatibility_date: '2026-09-23' } },
  ],
});
try {
  await harness.listen();
  const bridge = harness.getWorker('bridge'),
    feature = harness.getWorker('feature');
  await bridge.applyD1Migrations('DB');
  const { DB } = await bridge.getEnv();
  await activateWorkerPolicy(
    DB,
    JSON.parse(await readFile(join(root, 'local/generated/worker-policy.json'), 'utf8')),
    { actor: 'test', reason: 'bridge rehearsal' },
  );
  await DB.prepare("INSERT INTO signing_key VALUES('bridge-test',1,1,'ES256',?)")
    .bind(JSON.stringify(publicJwk))
    .run();
  await DB.prepare("INSERT INTO account_security VALUES('existing-account',1,1)").run();
  const client = randomUUID(),
    callback = 'https://app.example/callback';
  const digest = (value) => createHash('sha256').update(value).digest('base64url');
  const random = () => randomBytes(32).toString('base64url');
  await registerNativeClient(
    DB,
    { client_id: client, sector_identifier: 'app.example', redirect_uris: [callback] },
    'test',
    'bridge rehearsal',
  );
  const now = Math.floor(Date.now() / 1000);
  await DB.batch([
    DB.prepare("INSERT INTO credential VALUES('credential','existing-account',1)"),
    DB.prepare(
      "INSERT INTO app_connection(account_id,client_id,grant_version,active,reviewed_redirect_uri,reviewed_scope,reviewed_client_revision,reviewed_grant_version) VALUES('existing-account',?,1,1,?,'openid',1,1)",
    ).bind(client, callback),
    DB.prepare("INSERT INTO sso_session VALUES('sso','existing-account','credential',1,?,0)").bind(
      now + 3600,
    ),
    DB.prepare("INSERT INTO sso_context VALUES('sso',?,?)").bind(digest('cookie-secret'), now),
  ]);
  const login = async (worker) => {
    const verifier = random(),
      url = new URL('https://bridge.example/authorize');
    for (const [key, value] of Object.entries({
      response_type: 'code',
      client_id: client,
      redirect_uri: callback,
      scope: 'openid',
      state: random(),
      code_challenge: digest(verifier),
      code_challenge_method: 'S256',
    }))
      url.searchParams.set(key, value);
    const response = await worker.fetch(url.toString(), {
      headers: { Cookie: '__Host-op-sso=cookie-secret' },
      redirect: 'manual',
    });
    const location = new URL(response.headers.get('location'));
    const code = location.searchParams.get('code');
    assert.ok(code, 'authorization must succeed');
    const token = await worker.fetch('https://bridge.example/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: client,
        code,
        redirect_uri: callback,
        code_verifier: verifier,
      }).toString(),
    });
    assert.equal(token.status, 200, await token.clone().text());
  };
  const readyStatus = async (w) =>
    (
      await w.fetch('https://bridge.example/ready', {
        headers: { authorization: `Bearer ${ready}` },
      })
    ).status;
  assert.equal(await readyStatus(bridge), 204);
  assert.equal(await readyStatus(feature), 503);
  await login(bridge);
  await cp(join(migrations, names[10]), join(dir, names[10]));
  await bridge.applyD1Migrations('DB');
  assert.equal(await readyStatus(bridge), 204);
  assert.equal(await readyStatus(feature), 503);
  await login(bridge);
  const contextBefore = await DB.prepare(
    'SELECT code_hash,nonce,scope FROM code_context ORDER BY code_hash',
  ).all();
  assert.ok(contextBefore.results.length > 0, 'existing authorization contexts must be present');
  const tokenCountBefore = await DB.prepare('SELECT count(*) AS n FROM token_issue').first();
  await cp(join(migrations, names[11]), join(dir, names[11]));
  await bridge.applyD1Migrations('DB');
  const contextAfter = await DB.prepare(
    'SELECT code_hash,nonce,scope FROM code_context ORDER BY code_hash',
  ).all();
  assert.deepEqual(contextAfter.results, contextBefore.results, 'authorization contexts changed');
  assert.deepEqual(
    await DB.prepare('SELECT count(*) AS n FROM token_issue').first(),
    tokenCountBefore,
    'existing token issues changed',
  );
  assert.equal(await readyStatus(bridge), 204);
  assert.equal(await readyStatus(feature), 204);
  await login(feature);
  await login(bridge);
  assert.equal(
    (
      await DB.prepare(
        "SELECT active FROM account_security WHERE account_id='existing-account'",
      ).first()
    ).active,
    1,
  );
  process.stdout.write(
    'Bridge and feature readiness and OIDC exchange passed across 0010 → 0011 → 0012 and bridge rollback; existing account preserved. Claim readiness was mocked.\n',
  );
} finally {
  await harness.close();
  await rm(dir, { recursive: true, force: true });
}
