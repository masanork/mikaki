import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { createTestHarness } from 'wrangler';
import { agentQueries } from '../../crates/worker/service/agent-catalog.ts';

test('named OP authorities limit Agent SQL and claim release without downstream D1 or R2 bindings', async () => {
  const root = new URL('../..', import.meta.url).pathname;
  const opConfig = JSON.parse(
    (
      await readFile(
        new URL('../../crates/worker/wrangler.agent-local.jsonc', import.meta.url),
        'utf8',
      )
    ).replace(/,\s*([}\]])/g, '$1'),
  );
  opConfig.main = `${root}crates/worker/service/entrypoint.ts`;
  opConfig.d1_databases[0].migrations_dir = `${root}crates/worker/migrations`;
  const harness = createTestHarness({
    root,
    workers: [
      { config: opConfig },
      {
        config: {
          name: 'mikaki-agent-local',
          main: `${root}crates/agent-worker/worker.ts`,
          compatibility_date: '2026-09-28',
          compatibility_flags: ['nodejs_compat'],
          vars: { AGENT_RESOURCE: 'https://agent.test/mcp', AGENT_OWNER_URL: '' },
          services: [{ binding: 'AUTH_STORE', service: opConfig.name, entrypoint: 'AgentStore' }],
        },
      },
      {
        config: {
          name: 'isolated-claims',
          main: `${root}crates/userinfo-claim-worker/build/worker/shim.mjs`,
          compatibility_date: '2026-09-23',
          vars: { MIKAKI_ISSUER: 'https://mikaki.test' },
          services: [{ binding: 'CLAIM_STORE', service: opConfig.name, entrypoint: 'ClaimStore' }],
        },
      },
    ],
  });
  try {
    await harness.listen();
    const op = harness.getWorker(opConfig.name);
    await op.applyD1Migrations('DB');
    const { DB } = await op.getEnv();
    const agent = await harness.getWorker('mikaki-agent-local').getEnv();
    const claims = harness.getWorker('isolated-claims');
    const claimEnv = await claims.getEnv();
    assert.equal('DB' in agent, false);
    assert.equal('DB' in claimEnv, false);
    assert.equal('VAULT_BLOBS' in claimEnv, false);
    const key = randomBytes(32).toString('base64url');
    await DB.prepare("INSERT INTO agent_recipient_key VALUES(?,'active')").bind(key).run();
    const query = 'SELECT state FROM agent_recipient_key WHERE key_id=?';
    const id = createHash('sha256').update(query).digest('hex');
    assert.equal(agentQueries[id], query);
    const invoke = (statements: unknown[]) =>
      agent.AUTH_STORE.fetch('https://store.internal/statements', {
        method: 'POST',
        body: JSON.stringify({ statements }),
      });
    const result = await invoke([{ id, values: [key] }]);
    assert.equal(result.status, 200);
    assert.equal(
      ((await result.json()) as { results: { state: string }[] }[])[0].results[0].state,
      'active',
    );
    assert.equal((await invoke([{ id: '0'.repeat(64), values: [] }])).status, 503);
    assert.equal(
      (await invoke([{ id, values: [key], sql: 'DELETE FROM account_security' }])).status,
      503,
    );
    assert.equal(
      (await invoke(Array.from({ length: 65 }, () => ({ id, values: [key] })))).status,
      503,
    );
    assert.equal(
      (await op.fetch('https://mikaki.test/statements', { method: 'POST', body: '{}' })).status,
      404,
    );
    assert.equal(
      (await op.fetch('https://mikaki.test/release', { method: 'POST', body: '{}' })).status,
      404,
    );
    assert.equal((await claims.fetch('https://userinfo.internal/internal/ready')).status, 204);
    const noGrant = await claims.fetch('https://userinfo.internal/internal/claims/name', {
      method: 'POST',
      body: JSON.stringify({ access_hash: key }),
    });
    assert.equal(noGrant.status, 204);
    assert.equal(
      (
        await claimEnv.CLAIM_STORE.fetch('https://store.internal/statements', {
          method: 'POST',
          body: '{}',
        })
      ).status,
      404,
    );
    assert.equal(
      (
        await claimEnv.CLAIM_STORE.fetch('https://store.internal/audit', {
          method: 'POST',
          body: '{}',
        })
      ).status,
      503,
    );
    const legacyAudit = {
      access_hash: key,
      storage_version: 1,
      source_origin: 'https://mikaki.test',
      vault_id: 'vault',
      collection_id: 'personal',
      record_id: 'name',
      kind: 'name',
      envelope_id: key,
      key_generation: 1,
      owner_key_revision: 1,
      system_grant_version: 1,
      generation: 1,
      account_id: 'owner',
      client_id: 'rp',
      revision: 1,
      release_version: 1,
      ciphertext_sha256: key,
      key_id: key,
    };
    assert.equal(
      (
        await claimEnv.CLAIM_STORE.fetch('https://store.internal/audit', {
          method: 'POST',
          body: JSON.stringify(legacyAudit),
        })
      ).status,
      503,
      'the named authority rejects the retired audit protocol',
    );
    assert.equal(
      (
        await claims.fetch(
          `https://userinfo.internal/internal/recipient-keys/${key}/validate-envelope`,
          {
            method: 'POST',
            body: '{}',
          },
        )
      ).status,
      404,
      'the legacy envelope validator is retired',
    );
    assert.equal((await DB.prepare('PRAGMA foreign_key_check').all()).results.length, 0);
  } finally {
    await harness.close();
  }
});
