import assert from 'node:assert/strict';
import test from 'node:test';
import { productionWrangler, retryableWrangler } from './production-wrangler.ts';

const unavailable = { stderr: 'POST /versions -> 504 Gateway Timeout\nPRIVATE_BODY' };
const malformed = {
  stderr: 'Received a malformed response from the API\nPOST /versions -> 200 OK\nPRIVATE_BODY',
};

test('control retries permit only metadata reads and inactive version uploads', () => {
  for (const args of [
    ['versions', 'view'],
    ['deployments', 'list'],
    ['d1', 'migrations', 'list'],
    ['versions', 'upload'],
  ])
    for (const error of [unavailable, malformed])
      assert.equal(retryableWrangler(args, error), true);
  for (const args of [
    ['deploy'],
    ['versions', 'deploy'],
    ['triggers', 'deploy'],
    ['d1', 'execute'],
    ['d1', 'migrations', 'apply'],
    ['d1', 'create'],
    ['secret', 'put'],
  ])
    assert.equal(retryableWrangler(args, unavailable), false);
  for (const error of [
    new Error('timeout'),
    { stderr: ' -> 403 Forbidden' },
    { stderr: ' -> 429 Too Many Requests' },
    { stderr: 'invalid configuration' },
    { stderr: 'Received a malformed response from the API\n -> 401 Unauthorized' },
    { stderr: 'x'.repeat(65537) },
    { stderr: Buffer.from(' -> 504') },
  ])
    assert.equal(retryableWrangler(['versions', 'upload'], error), false);
});

test('bounded retry keeps the original command, validates successful output normally and preserves failure', async () => {
  const args = ['versions', 'upload', 'verified-bundle.js', '--secrets-file', 'PRIVATE_PATH'];
  const waits: number[] = [];
  let calls = 0;
  const output = await productionWrangler(
    args,
    (selected) => {
      assert.equal(selected, args);
      if (++calls < 3) throw malformed;
      return 'Worker Version ID: 11111111-1111-4111-8111-111111111111';
    },
    async (ms) => {
      waits.push(ms);
    },
  );
  assert.match(output, /Worker Version ID/);
  assert.equal(calls, 3);
  assert.deepEqual(waits, [1000, 2000]);
  calls = 0;
  await assert.rejects(
    productionWrangler(
      args,
      () => {
        calls++;
        throw unavailable;
      },
      async () => {},
    ),
    (error) => error === unavailable,
  );
  assert.equal(calls, 3);
  for (const command of [
    ['versions', 'deploy'],
    ['triggers', 'deploy'],
    ['d1', 'execute'],
  ]) {
    calls = 0;
    await assert.rejects(
      productionWrangler(
        command,
        () => {
          calls++;
          throw unavailable;
        },
        async () => {
          assert.fail('activation and DB commands must never wait or retry');
        },
      ),
      (error) => error === unavailable,
    );
    assert.equal(calls, 1);
  }
});
