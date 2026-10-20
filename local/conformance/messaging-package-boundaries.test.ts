/** Exercise the emitted service packages, including every named entrypoint. */
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { parse } from 'jsonc-parser';
import { createTestHarness } from 'wrangler';

const root = new URL('../../', import.meta.url).pathname;
const entrypoints = [
  'AgentStore',
  'ClaimStore',
  'OpAuthorityAdmin',
  'WorkEffectStore',
  'WorkMintStore',
  'WorkGitStore',
  'WorkCopyStore',
];

for (const profile of ['build', 'build-messaging-beta']) {
  test(`${profile} service package preserves named authorities and closes public/raw RPC`, async () => {
    const config = parse(await readFile(`${root}crates/worker/wrangler.jsonc`, 'utf8'));
    config.main = `${root}crates/worker/${profile}/worker/service.mjs`;
    config.assets.directory = `${root}assets`;
    config.d1_databases[0].migrations_dir = `${root}crates/worker/migrations`;
    config.vars = { MIKAKI_ISSUER: 'https://mikaki.test', MESSAGING_BETA_ENABLED: 'true' };
    const harness = createTestHarness({
      root,
      workers: [
        { config },
        {
          config: {
            name: 'service-boundary-caller',
            main: config.main,
            compatibility_date: config.compatibility_date,
            services: [
              { binding: 'Public', service: config.name },
              ...entrypoints.map((entrypoint) => ({
                binding: entrypoint,
                service: config.name,
                entrypoint,
              })),
            ],
          },
        },
      ],
    });
    try {
      await harness.listen();
      const worker = harness.getWorker(config.name);
      await worker.applyD1Migrations('DB');
      const { DB } = await worker.getEnv();
      const caller = await harness.getWorker('service-boundary-caller').getEnv();
      assert.equal('DB' in caller, false);
      assert.equal('VAULT_BLOBS' in caller, false);
      for (const name of ['Public', ...entrypoints.slice(2)]) {
        for (const method of [
          'administer_op_authority',
          'administer_work_effect',
          'administer_work_copy',
        ]) {
          const denied = await caller[name][method]();
          assert.equal(denied.status, 404, `${name}.${method}`);
          assert.deepEqual(await denied.json(), { error: 'not_found' });
        }
      }
      for (const name of ['AgentStore', 'ClaimStore']) {
        for (const method of [
          'administer_op_authority',
          'administer_work_effect',
          'administer_work_copy',
        ]) {
          await assert.rejects(async () => {
            await caller[name][method]();
          }, `${name}.${method} is unavailable`);
        }
        const denied = await caller[name].fetch('https://private.invalid/authority', {
          method: 'POST',
          body: '{}',
        });
        assert.equal(denied.status, 404, `${name} has no authority HTTP access`);
        await denied.text();
      }
      for (const path of [
        '/statements',
        '/key',
        '/release',
        '/audit',
        '/authority',
        '/effect',
        '/mint-effect',
        '/git-effect',
        '/copy-job',
      ]) {
        const denied = await worker.fetch(`https://mikaki.test${path}`, {
          method: 'POST',
          body: '{}',
        });
        assert.equal(denied.status, 404, `public ${path}`);
        await denied.text();
      }
      const query = 'SELECT state FROM agent_recipient_key WHERE key_id=?';
      const key = randomBytes(32).toString('base64url');
      await DB.prepare("INSERT INTO agent_recipient_key VALUES(?,'active')").bind(key).run();
      const allowed = await caller.AgentStore.fetch('https://private.invalid/statements', {
        method: 'POST',
        body: JSON.stringify({
          statements: [
            {
              id: createHash('sha256').update(query).digest('hex'),
              values: [key],
            },
          ],
        }),
      });
      assert.equal(allowed.status, 200);
      assert.equal((await allowed.json())[0].results[0].state, 'active');
      const deniedSql = await caller.AgentStore.fetch('https://private.invalid/statements', {
        method: 'POST',
        body: JSON.stringify({
          statements: [{ id: '0'.repeat(64), values: [], sql: 'DELETE FROM credential' }],
        }),
      });
      assert.equal(deniedSql.status, 503);
      await deniedSql.text();
      const ready = await caller.ClaimStore.fetch('https://private.invalid/ready', {
        method: 'POST',
        body: '{}',
      });
      assert.equal(ready.status, 200);
      assert.deepEqual(await ready.json(), { ready: true });
      for (const [name, path, input, status] of [
        [
          'OpAuthorityAdmin',
          '/authority',
          {
            action: 'revoke-account',
            account: 'owner',
            expected_epoch: 0,
            actor: 'fixture',
            reason: 'unenrolled authority',
          },
          409,
        ],
        ['WorkEffectStore', '/effect', { action: 'initial-plan', attempt_id: key }, 409],
        ['WorkMintStore', '/mint-effect', {}, 409],
        ['WorkGitStore', '/git-effect', {}, 409],
        // Copy execution retains its independent disabled-by-default gate.
        ['WorkCopyStore', '/copy-job', { action: 'pending' }, 404],
      ] as const) {
        const response = await caller[name].fetch(`https://private.invalid${path}`, {
          method: 'POST',
          body: JSON.stringify(input),
        });
        assert.equal(response.status, status, `${name} refuses unenrolled changes`);
        await response.text();
      }
      for (const name of entrypoints.slice(2)) {
        const denied = await caller[name].fetch('https://private.invalid/statements', {
          method: 'POST',
          body: '{}',
        });
        assert.equal(denied.status, 404, name);
        await denied.text();
      }
      assert.equal(await DB.prepare('SELECT count(*) AS n FROM account_security').first('n'), 0);
    } finally {
      await harness.close();
    }
  });
}
