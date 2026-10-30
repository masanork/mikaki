import assert from 'node:assert/strict';
import { test } from 'node:test';
import { buildCbom } from './build_cbom.ts';

test('Chat crypto inventory is source-checked and isolated to the beta profile', async () => {
  const normal = await buildCbom();
  assert.ok(normal.components.some((item) => item.name === 'ES256 native OIDC signer'));
  assert.ok(normal.components.some((item) => item.name === 'ES256 client assertion verifier'));
  const beta = await buildCbom('worker', 'messaging-beta');
  assert.ok(beta.components.some((item) => item.name === 'AES-128-GCM Chat messages'));
  assert.ok(
    beta.components.some((item) => item.name === 'Chat issuer signing private key binding'),
  );
  assert.ok(normal.components.every((item) => !item.name.includes('Chat')));
  assert.deepEqual(beta.metadata.properties, [
    { name: 'mikaki:release-profile', value: 'messaging-beta' },
  ]);
  assert.notEqual(normal.serialNumber, beta.serialNumber);
  const claim = await buildCbom('userinfo-claim-worker');
  assert.ok(claim.components.every((item) => !item.name.includes('Chat')));
  await assert.rejects(buildCbom('userinfo-claim-worker', 'messaging-beta'), /default profile/);
});
