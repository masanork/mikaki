import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { exportJWK, generateKeyPair } from 'jose';
import { createTestHarness } from 'wrangler';
import { activateWorkerPolicy } from '../../scripts/worker-policy-store.ts';

const root = new URL('../..', import.meta.url).pathname;
const opConfig = new URL('../../crates/worker/wrangler.recipient-local.jsonc', import.meta.url)
  .pathname;
const claimConfig = new URL(
  '../../crates/userinfo-claim-worker/wrangler.local.jsonc',
  import.meta.url,
).pathname;
const readyToken = 'AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA';

test('readiness requires usable OP policy, signing key, migrations, R2 and Claim Worker', async () => {
  const keys = await generateKeyPair('ES256', { extractable: true });
  const publicJwk = {
    ...(await exportJWK(keys.publicKey)),
    kid: 'ready-op',
    alg: 'ES256',
    use: 'sig',
  };
  const privateJwk = {
    ...(await exportJWK(keys.privateKey)),
    kid: 'ready-op',
    alg: 'ES256',
    use: 'sig',
  };
  const config = JSON.parse(await readFile(opConfig, 'utf8'));
  config.main = new URL('./support/readiness-op.mjs', import.meta.url).pathname;
  config.d1_databases[0].migrations_dir = new URL(
    '../../crates/worker/migrations',
    import.meta.url,
  ).pathname;
  const harness = createTestHarness({
    root,
    workers: [
      {
        config,
        vars: { MIKAKI_ISSUER: 'https://mikaki.test' },
        secrets: {
          OP_PRIVATE_JWK: JSON.stringify(privateJwk),
          MIKAKI_READY_TOKEN: readyToken,
        },
      },
      { configPath: claimConfig },
    ],
  });
  try {
    await harness.listen();
    const op = harness.getWorker('mikaki-op-worker');
    const claim = harness.getWorker('mikaki-userinfo-claim-worker');
    const check = async (
      status: number,
      authorization: string | null = `Bearer ${readyToken}`,
      fault = '',
      dependencyFault = '',
    ) => {
      const url = new URL('https://mikaki.test/ready');
      if (fault) url.searchParams.set('r2_fault', fault);
      if (dependencyFault) url.searchParams.set('ready_fault', dependencyFault);
      const response = await op.fetch(url.href, {
        headers: authorization === null ? {} : { Authorization: authorization },
      });
      assert.equal(response.status, status);
      assert.equal(response.headers.get('Cache-Control'), 'no-store');
      assert.equal(await response.text(), '');
    };
    assert.equal((await op.fetch('https://mikaki.test/health')).status, 200);
    await check(404, null);
    await check(404, `Bearer B${readyToken.slice(1)}`);
    await check(404, `Basic ${readyToken}`);
    await check(404, 'Bearer short');
    const heads = async () =>
      (await (await op.fetch('https://mikaki.test/__test/r2-heads')).json()) as string[];
    assert.deepEqual(await heads(), [], 'Unauthorized checks must not contact R2');
    await check(503);
    assert.equal((await claim.fetch('https://internal.invalid/internal/ready')).status, 503);
    await op.applyD1Migrations('DB');
    assert.equal((await claim.fetch('https://internal.invalid/internal/ready')).status, 204);
    await check(503);
    const { DB } = await op.getEnv();
    const claimEnv = await claim.getEnv();
    assert.equal('DB' in claimEnv, false);
    assert.equal('VAULT_BLOBS' in claimEnv, false);
    assert.ok(claimEnv.CLAIM_STORE, 'readiness uses the same named OP authority as delivery');
    const policy = JSON.parse(
      await readFile(new URL('../generated/worker-policy.json', import.meta.url), 'utf8'),
    );
    await activateWorkerPolicy(DB, policy, { actor: 'test', reason: 'Readiness fixture' });
    await check(503);
    await DB.prepare("INSERT INTO signing_key VALUES('ready-op',1,1,'ES256',?)")
      .bind(JSON.stringify(publicJwk))
      .run();
    await check(204);
    const { VAULT_BLOBS } = await op.getEnv();
    assert.equal((await VAULT_BLOBS.list()).objects.length, 0, 'Probe writes no sentinel');
    await check(503, `Bearer ${readyToken}`, 'error');
    const started = performance.now();
    await check(503, `Bearer ${readyToken}`, 'pending');
    const elapsed = performance.now() - started;
    assert.ok(elapsed >= 2_500, 'Pending R2 must reach the dependency timeout');
    assert.ok(elapsed < 4_500, 'R2 must time out before the five-second whole-probe deadline');
    await check(204);
    const dependencyCalls = async () =>
      (await (await op.fetch('https://mikaki.test/__test/dependencies')).json()) as string[];
    for (const dependency of ['d1', 'claim']) {
      const before = (await dependencyCalls()).length;
      const start = performance.now();
      await check(503, `Bearer ${readyToken}`, '', dependency);
      const duration = performance.now() - start;
      assert.ok(
        duration >= 4_500 && duration < 7_500,
        `${dependency} must reach the whole-probe timeout`,
      );
      assert.equal(
        (await dependencyCalls()).slice(before).at(-1),
        dependency,
        'Injected pending dependency must actually be called',
      );
      await check(204);
      const recovered = (await dependencyCalls()).length;
      await check(404, null, '', dependency);
      assert.equal(
        (await dependencyCalls()).length,
        recovered,
        'Unauthorized checks bypass pending dependencies',
      );
    }
    const calls = (await heads()).length;
    await check(404, null, 'error');
    assert.equal((await heads()).length, calls, 'Unauthorized checks bypass even a failed R2');
    await VAULT_BLOBS.put('__mikaki_readiness__/r2-head', 'sentinel-fixture');
    await VAULT_BLOBS.put('vault-fixture-ciphertext', 'ciphertext-fixture');
    await check(204);
    assert.ok((await heads()).every((key) => key === '__mikaki_readiness__/r2-head'));
    assert.equal(
      await (await VAULT_BLOBS.get('vault-fixture-ciphertext'))!.text(),
      'ciphertext-fixture',
    );
    assert.equal((await VAULT_BLOBS.list()).objects.length, 2, 'Probe leaves objects intact');
    await check(404, null);
    const otherKeys = await generateKeyPair('ES256', { extractable: true });
    const wrongPublicJwk = {
      ...(await exportJWK(otherKeys.publicKey)),
      kid: 'ready-op',
      alg: 'ES256',
      use: 'sig',
    };
    await DB.prepare("UPDATE signing_key SET public_jwk=? WHERE kid='ready-op'")
      .bind(JSON.stringify(wrongPublicJwk))
      .run();
    await check(503);
    await DB.prepare("UPDATE signing_key SET public_jwk=? WHERE kid='ready-op'")
      .bind(JSON.stringify(publicJwk))
      .run();
    await check(204);
    await DB.prepare('DROP TABLE vault_recipient_key').run();
    await check(404, null);
    await check(503);
  } finally {
    await harness.close();
  }
});

test('readiness remains hidden when the monitoring secret is not provisioned', async () => {
  const harness = createTestHarness({
    root,
    workers: [{ configPath: opConfig }, { configPath: claimConfig }],
  });
  try {
    await harness.listen();
    const response = await harness
      .getWorker('mikaki-op-worker')
      .fetch('https://mikaki.test/ready', {
        headers: { Authorization: `Bearer ${readyToken}` },
      });
    assert.equal(response.status, 404);
    assert.equal(response.headers.get('Cache-Control'), 'no-store');
    assert.equal(await response.text(), '');
  } finally {
    await harness.close();
  }
});
