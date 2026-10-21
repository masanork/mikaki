/** SEC-02/18 subset: emitted AgentStore, real workerd/D1/R2, synthetic data only. */
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { createTestHarness } from 'wrangler';
import { agentQueries } from '../../crates/worker/service/agent-catalog.ts';

const root = new URL('../../', import.meta.url).pathname;
const origin = 'https://mikaki.test';
const service = `${root}crates/worker/build/worker/service.mjs`;
const query = 'SELECT state FROM agent_recipient_key WHERE key_id=?';
const deletion = 'DELETE FROM agent_oauth_guard WHERE operation=?';
const capability = (sql: string) => {
  const id = createHash('sha256').update(sql).digest('hex');
  assert.equal(agentQueries[id], sql, 'the control must be a current product capability');
  return id;
};
const read = (value = 'synthetic-recipient') => ({ id: capability(query), values: [value] });
const remove = (value = 'synthetic-guard') => ({ id: capability(deletion), values: [value] });
const batch = (statements: unknown[]) => JSON.stringify({ statements });
const entrypoints = [
  'AgentStore',
  'ClaimStore',
  'OpAuthorityAdmin',
  'WorkEffectStore',
  'WorkMintStore',
  'WorkGitStore',
  'WorkCopyStore',
];

test('SEC-02/18 packaged AgentStore capability and atomicity matrix', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'mikaki-security-service-'));
  const callerMain = join(directory, 'caller.mjs');
  // Buffer the synthetic input before invoking a real service binding. Calling
  // fetch through the host getEnv RPC can race an early-denial response against
  // that bridge's still-streaming argument upload (undici EPIPE).
  await writeFile(
    callerMain,
    `export default {
    async fetch(request, env) {
      const input = await request.arrayBuffer();
      const name = new URL(request.url).searchParams.get('binding');
      const method = request.headers.get('x-test-method') || 'POST';
      const response = await env[name].fetch('https://mikaki.test/statements', {
        method, ...(method === 'POST' ? {body: input} : {})
      });
      return new Response(await response.arrayBuffer(), {status: response.status, headers: response.headers});
    }
  };`,
  );
  const harness = createTestHarness({
    root,
    workers: [
      {
        config: {
          name: 'security-service-op',
          main: service,
          compatibility_date: '2026-09-23',
          compatibility_flags: ['global_fetch_strictly_public'],
          vars: { MIKAKI_ISSUER: origin },
          version_metadata: { binding: 'CF_VERSION_METADATA' },
          d1_databases: [
            {
              binding: 'DB',
              database_name: 'security-service-op',
              database_id: '00000000-0000-0000-0000-000000000000',
              migrations_dir: `${root}crates/worker/migrations`,
              remote: false,
            },
          ],
          r2_buckets: [
            { binding: 'VAULT_BLOBS', bucket_name: 'security-service-op', remote: false },
          ],
        },
      },
      {
        config: {
          name: 'security-service-caller',
          main: callerMain,
          compatibility_date: '2026-09-23',
          services: [
            { binding: 'Public', service: 'security-service-op' },
            ...entrypoints.map((entrypoint) => ({
              binding: entrypoint,
              service: 'security-service-op',
              entrypoint,
            })),
          ],
        },
      },
    ],
  });
  try {
    await harness.listen();
    const op = harness.getWorker('security-service-op');
    await op.applyD1Migrations('DB');
    const { DB, VAULT_BLOBS } = await op.getEnv();
    const callerWorker = harness.getWorker('security-service-caller');
    const caller = await callerWorker.getEnv();
    assert.equal('DB' in caller, false);
    assert.equal('VAULT_BLOBS' in caller, false);
    const versionResponse = await op.fetch(`${origin}/version`);
    assert.equal(versionResponse.status, 200);
    const version = (await versionResponse.json()) as {
      source_commit: string;
      source_clean: boolean;
    };
    assert.equal(
      version.source_commit,
      execFileSync('/usr/bin/git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim(),
      'rebuild the emitted service for this checkout',
    );
    t.diagnostic(
      JSON.stringify({
        scenario: ['SEC-02', 'SEC-18'],
        sourceCommit: version.source_commit,
        buildSourceClean: version.source_clean,
        profile: 'default',
        authority: 'emitted AgentStore / local workerd D1 and R2',
      }),
    );
    await DB.exec("INSERT INTO account_security VALUES('synthetic-owner',1,1)");
    await DB.exec("INSERT INTO agent_recipient_key VALUES('synthetic-recipient','active')");
    await VAULT_BLOBS.put('synthetic-owner/ciphertext', new Uint8Array([7, 11, 19, 23]));
    const seedGuard = (id = 'synthetic-guard') =>
      DB.prepare('INSERT INTO agent_oauth_guard VALUES(?,1)').bind(id).run();
    await seedGuard();

    // Snapshot every application table, schema and blob, rather than checking
    // only the expected target. Internal SQLite/Cloudflare bookkeeping is excluded.
    const snapshot = async () => {
      const schema = (
        await DB.prepare(
          "SELECT type,name,sql FROM sqlite_master WHERE type IN('table','trigger') AND name NOT GLOB 'sqlite_*' AND name NOT GLOB '_cf_*' ORDER BY name",
        ).all()
      ).results;
      const tables = [];
      for (const row of schema) {
        if (row.type !== 'table') continue;
        assert.match(row.name, /^[a-z][a-z0-9_]*$/);
        const rows = (await DB.prepare(`SELECT * FROM "${row.name}"`).all()).results;
        tables.push({
          name: row.name,
          rows: rows
            .map((value: unknown) => JSON.stringify(value))
            .sort((left: string, right: string) => left.localeCompare(right, 'en')),
        });
      }
      const listing = await VAULT_BLOBS.list();
      assert.equal(listing.truncated, false, 'the complete blob inventory must be compared');
      const blobs = [];
      for (const object of listing.objects) {
        const stored = await VAULT_BLOBS.get(object.key);
        assert.ok(stored);
        blobs.push({
          key: object.key,
          sha256: createHash('sha256')
            .update(new Uint8Array(await stored.arrayBuffer()))
            .digest('hex'),
        });
      }
      return { schema, tables, blobs };
    };
    const dispatch = (body: string | Uint8Array, binding = 'AgentStore', method = 'POST') =>
      callerWorker.fetch(`${origin}/?binding=${binding}`, {
        method: 'POST',
        headers: { 'X-Test-Method': method },
        body,
      });
    const invoke = async (body: string | Uint8Array) => {
      const response = await dispatch(body);
      const text = await response.text();
      assert.equal(response.headers.get('Cache-Control'), 'no-store');
      return { status: response.status, value: JSON.parse(text) };
    };
    const denied = async (body: string | Uint8Array) => {
      const before = await snapshot();
      assert.deepEqual(await invoke(body), {
        status: 503,
        value: { error: 'store_unavailable_or_denied' },
      });
      assert.deepEqual(
        await snapshot(),
        before,
        'denial must leave all durable application state unchanged',
      );
    };
    const controlDelete = async (body: string) => {
      const before = await snapshot();
      const response = await invoke(body);
      assert.equal(response.status, 200);
      assert.equal(response.value.at(-1).meta.changes, 1);
      assert.equal(
        await DB.prepare('SELECT valid FROM agent_oauth_guard WHERE operation=?')
          .bind('synthetic-guard')
          .first(),
        null,
      );
      await seedGuard();
      assert.deepEqual(await snapshot(), before, 'restore the positive-control fixture exactly');
    };

    await t.test('known capabilities read and mutate only their catalogued target', async () => {
      const response = await invoke(batch([read()]));
      assert.equal(response.status, 200);
      assert.deepEqual(response.value[0].results, [{ state: 'active' }]);
      await controlDelete(batch([remove()]));
    });
    await t.test(
      'public HTTP and other named roles cannot invoke a valid Agent mutation',
      async () => {
        const before = await snapshot();
        const response = await op.fetch(`${origin}/statements`, {
          method: 'POST',
          headers: { 'X-Owner-ID': 'synthetic-owner', 'X-Admin': 'true' },
          body: batch([remove()]),
        });
        assert.equal(response.status, 404);
        await response.text();
        for (const name of ['Public', ...entrypoints.filter((name) => name !== 'AgentStore')]) {
          const result = await dispatch(batch([remove()]), name);
          assert.equal(result.status, 404, name);
          await result.text();
        }
        for (const method of ['GET', 'PUT', 'OPTIONS']) {
          const result = await dispatch('', 'AgentStore', method);
          assert.equal(result.status, 404, method);
          await result.text();
        }
        assert.deepEqual(await snapshot(), before);
      },
    );
    await t.test(
      'uncatalogued OP SQL and a mixed valid/invalid batch have no effects',
      async () => {
        const sql = "UPDATE account_security SET active=0 WHERE account_id='synthetic-owner'";
        const unknown = { id: createHash('sha256').update(sql).digest('hex'), values: [] };
        assert.equal(agentQueries[unknown.id], undefined);
        await denied(batch([unknown]));
        await denied(batch([remove(), unknown]));
      },
    );
    await t.test(
      'raw SQL, owner fields and malformed values cannot widen an accepted capability',
      async () => {
        await denied(batch([{ ...remove(), sql: 'DELETE FROM account_security' }]));
        await denied(JSON.stringify({ statements: [remove()], owner_id: 'synthetic-owner' }));
        await denied(batch([{ ...remove(), owner_id: 'synthetic-owner' }]));
        await denied(batch([{ ...remove(), values: [{ account_id: 'synthetic-owner' }] }]));
        await denied(batch([{ ...remove(), values: Array.from({ length: 65 }, () => null) }]));
        await denied(
          `{"statements":[${JSON.stringify(remove())},{"id":"${capability(query)}","values":[1e400]}]}`,
        );
      },
    );
    await t.test('SQL-looking bound strings remain literal data', async () => {
      const before = await snapshot();
      const result = await invoke(batch([read("' OR 1=1; DELETE FROM account_security; --")]));
      assert.equal(result.status, 200);
      assert.deepEqual(result.value[0].results, []);
      assert.deepEqual(await snapshot(), before);
    });
    await t.test('64 statements can commit, while 65 or zero cannot', async () => {
      const reads = Array.from({ length: 63 }, () => read());
      await controlDelete(batch([...reads, remove()]));
      await denied(batch([...reads, read(), remove()]));
      await denied(batch([]));
    });
    await t.test(
      'the 65536-byte body boundary accepts a control and rejects one extra byte',
      async () => {
        const input = batch([remove()]);
        const exact = input.padEnd(65536, ' ');
        assert.equal(Buffer.byteLength(exact), 65536);
        await controlDelete(exact);
        await denied(exact + ' ');
      },
    );
    await t.test(
      'malformed JSON and invalid UTF-8 deny without echoing input or mutating storage',
      async () => {
        await denied(batch([remove()]) + 'synthetic-private-canary');
        const prefix = Buffer.from(
          `{"statements":[${JSON.stringify(remove())},{"id":"${capability(query)}","values":["`,
        );
        await denied(Buffer.concat([prefix, Buffer.from([0xc3, 0x28]), Buffer.from('"]}]}')]));
      },
    );
    await t.test(
      'a D1 failure after the first valid write rolls the entire batch back',
      async () => {
        await seedGuard('synthetic-last');
        // The actual catalogued SQL executes. Only this disposable database's
        // second DELETE is made to fail, after the first DELETE would have succeeded.
        await DB.exec(
          "CREATE TRIGGER security_abort_second BEFORE DELETE ON agent_oauth_guard WHEN OLD.operation='synthetic-last' BEGIN SELECT RAISE(ABORT,'synthetic constraint failure'); END",
        );
        try {
          await denied(batch([remove(), remove('synthetic-last')]));
        } finally {
          await DB.exec('DROP TRIGGER security_abort_second');
        }
        const response = await invoke(batch([remove(), remove('synthetic-last')]));
        assert.equal(response.status, 200);
        assert.deepEqual(
          response.value.map((row: { meta: { changes: number } }) => row.meta.changes),
          [1, 1],
        );
        await seedGuard();
      },
    );
  } finally {
    try {
      await harness.close();
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  }
});
