import assert from 'node:assert/strict';
import test from 'node:test';
import {
  productionWrangler,
  retryableWrangler,
  uploadedVersionView,
} from './production-wrangler.ts';

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

const uploadedId = '11111111-1111-4111-8111-111111111111';
const notVisible = {
  stderr: `A request to the Cloudflare API (/accounts/ACCOUNT/workers/scripts/WORKER/versions/${uploadedId}) failed.
The requested Worker version could not be found, please check the ID being passed and try again. [code: 100146]
PRIVATE_BODY`,
};

test('freshly uploaded metadata may become visible without repeating upload or activation', async (t) => {
  const logs: string[] = [];
  t.mock.method(console, 'log', (message: string) => logs.push(message));
  const waits: number[] = [];
  let calls = 0;
  const output = JSON.stringify({ id: uploadedId, resources: { bindings: [] } });
  const observed = await uploadedVersionView(
    uploadedId,
    'PRIVATE_CONFIG',
    (args) => {
      assert.deepEqual(args, [
        'versions',
        'view',
        uploadedId,
        '--config',
        'PRIVATE_CONFIG',
        '--json',
      ]);
      if (++calls < 3) throw { stderr: `\x1b[31m${notVisible.stderr}\x1b[0m` };
      return output;
    },
    async (ms) => {
      waits.push(ms);
    },
  );
  assert.equal(
    observed,
    output,
    'Caller still receives the full response for its usual binding checks',
  );
  assert.equal(calls, 3);
  assert.deepEqual(waits, [1000, 2000]);
  assert.equal(logs.length, 2);
  assert.ok(logs.every((message) => !/PRIVATE_BODY|PRIVATE_CONFIG|ACCOUNT|WORKER/.test(message)));
  assert.equal(
    retryableWrangler(['versions', 'view', uploadedId], notVisible),
    false,
    'Ordinary historic version reads do not acquire this fresh-upload exception',
  );
});

test('a permanently unavailable uploaded version fails after five reads and fifteen seconds of backoff', async (t) => {
  t.mock.method(console, 'log', () => {});
  let calls = 0;
  const waits: number[] = [];
  await assert.rejects(
    uploadedVersionView(
      uploadedId,
      'config.jsonc',
      () => {
        calls++;
        throw notVisible;
      },
      async (ms) => {
        waits.push(ms);
      },
    ),
    (error) => error === notVisible,
  );
  assert.equal(calls, 5);
  assert.deepEqual(waits, [1000, 2000, 4000, 8000]);
});

test('other IDs, permission errors and malformed CLI failures never enter the visibility wait', async () => {
  for (const error of [
    { stderr: notVisible.stderr.replaceAll(uploadedId, '22222222-2222-4222-8222-222222222222') },
    { stderr: notVisible.stderr.replace('100146', '10000') },
    { stderr: ' -> 403 Forbidden' },
    { stderr: ' -> 429 Too Many Requests' },
    { stderr: '[code: 100146]' },
    { stderr: Buffer.from(notVisible.stderr) },
    { stderr: notVisible.stderr + 'x'.repeat(65536) },
    new Error('timeout'),
  ]) {
    let calls = 0;
    await assert.rejects(
      uploadedVersionView(
        uploadedId,
        'config.jsonc',
        () => {
          calls++;
          throw error;
        },
        async () => {
          assert.fail('Unexpected visibility retry');
        },
      ),
      (thrown) => thrown === error,
    );
    assert.equal(calls, 1);
  }
  await assert.rejects(
    uploadedVersionView('--upload', 'config.jsonc', () => {
      assert.fail('Invalid version ID must fail before executing Wrangler');
    }),
  );
});
