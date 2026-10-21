/** SEC-01/06: synthetic sessions, real packaged OP, real local D1/R2 effects. */
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { createTestHarness } from 'wrangler';
import {
  createOwnerKey,
  sealOwnerRecord,
  OWNER_KEY_SUITE,
} from '../../crates/worker/ui/vault-owner-crypto.ts';

const origin = 'https://mikaki.test';
const root = new URL('../../', import.meta.url).pathname;
const opaque = () => randomBytes(32).toString('base64url');
const hash = (value: string | Uint8Array) => createHash('sha256').update(value).digest('base64url');
const records = `${origin}/vault/records/messages`;
const recordUrl = (record = 'shared') => `${records}/${record}`;

async function fixture() {
  const directory = await mkdtemp(join(tmpdir(), 'mikaki-security-owner-'));
  // The wrapper schedules real authority changes at two asynchronous boundaries.
  // It never replaces SQL, authorization decisions, results, or stored bytes.
  await writeFile(
    join(directory, 'op.mjs'),
    `import Op from ${JSON.stringify(`${root}crates/worker/build/worker/service.mjs`)};
    export default {
      async fetch(request, env, ctx) {
        const fault = await env.DB.prepare('SELECT stage,statement FROM security_test_fault WHERE id=1').first();
        let fired = false;
        const trip = async (stage) => {
          if (fired || fault.stage !== stage) return;
          fired = true;
          await env.DB.prepare('UPDATE security_test_fault SET hits=hits+1 WHERE id=1').run();
          await env.DB.exec(fault.statement);
        };
        const statement = (target, sql) => new Proxy(target, {get(prepared, key) {
          if (key === 'constructor') return prepared.constructor;
          if (key === 'bind') return (...args) => statement(prepared.bind(...args), sql);
          if (key === 'all') return async (...args) => {
            const result = await prepared.all(...args);
            if (sql.startsWith('SELECT record_id,kind,revision,key_generation,deleted FROM vault_owner_record_head')) await trip('list');
            return result;
          };
          const value = Reflect.get(prepared, key, prepared);
          return typeof value === 'function' ? value.bind(prepared) : value;
        }});
        const db = new Proxy(env.DB, {get(target, key) {
          if (key === 'constructor') return target.constructor;
          if (key === 'prepare') return (sql) => statement(target.prepare(sql), sql);
          if (key === 'batch') return async (...args) => {
            await trip('commit');
            return target.batch(...args);
          };
          const value = Reflect.get(target, key, target);
          return typeof value === 'function' ? value.bind(target) : value;
        }});
        return new Op(ctx, {...env, DB: db}).fetch(request);
      }
    };`,
  );
  const harness = createTestHarness({
    root,
    workers: [
      {
        config: {
          name: 'mikaki-security-owner',
          main: join(directory, 'op.mjs'),
          compatibility_date: '2026-09-23',
          compatibility_flags: ['global_fetch_strictly_public'],
          vars: { MIKAKI_ISSUER: origin },
          d1_databases: [
            {
              binding: 'DB',
              database_name: 'mikaki-security-owner',
              database_id: '00000000-0000-0000-0000-000000000000',
              migrations_dir: `${root}crates/worker/migrations`,
              remote: false,
            },
          ],
          r2_buckets: [{ binding: 'VAULT_BLOBS', bucket_name: 'mikaki-security-owner' }],
        },
      },
    ],
  });
  const close = async () => {
    await harness.close();
    await rm(directory, { recursive: true, force: true });
  };
  try {
    await harness.listen();
    const worker = harness.getWorker('mikaki-security-owner');
    await worker.applyD1Migrations('DB');
    const { DB, VAULT_BLOBS } = await worker.getEnv();
    await DB.exec(
      "CREATE TABLE security_test_fault(id INTEGER PRIMARY KEY,stage TEXT,statement TEXT,hits INTEGER); INSERT INTO security_test_fault VALUES(1,'','',0)",
    );
    const arm = (stage = '', statement = '') =>
      DB.prepare('UPDATE security_test_fault SET stage=?,statement=?,hits=0 WHERE id=1')
        .bind(stage, statement)
        .run();
    const bootstrap = async (account: string) => {
      const session = opaque(),
        secret = opaque(),
        credential = opaque(),
        now = Math.floor(Date.now() / 1000);
      await DB.batch([
        DB.prepare('INSERT INTO account_security VALUES(?,1,1)').bind(account),
        DB.prepare('INSERT INTO credential VALUES(?,?,1)').bind(credential, account),
        DB.prepare('INSERT INTO sso_session VALUES(?,?,?,1,?,0)').bind(
          session,
          account,
          credential,
          now + 3600,
        ),
        DB.prepare('INSERT INTO sso_context VALUES(?,?,?)').bind(session, hash(secret), now),
      ]);
      const context = { origin, ownerId: account, vaultId: 'vault', keyGeneration: 1 };
      const created = await createOwnerKey(
        context,
        new Uint8Array(Buffer.from(credential, 'base64url')),
        new Uint8Array(randomBytes(32)),
        new Uint8Array(randomBytes(32)),
      );
      const headers = {
        Cookie: `__Host-op-sso=${secret}`,
        Origin: origin,
        'Content-Type': 'application/json',
      };
      await expectJson(
        await worker.fetch(`${origin}/vault/owner-key`, {
          method: 'PUT',
          headers: { ...headers, 'If-None-Match': '*', 'X-Operation-ID': opaque() },
          body: JSON.stringify({
            format_version: 2,
            suite: OWNER_KEY_SUITE,
            vault_id: 'vault',
            key_generation: 1,
            owner_envelope: created.envelope,
          }),
        }),
        200,
      );
      return { account, session, credential, context, headers, key: created.key };
    };
    // Include receipts and pending uploads, so an error status cannot hide a
    // committed tombstone, replay receipt, orphan upload, or changed ciphertext.
    const snapshot = async (account?: string) => {
      const where = account === undefined ? '' : ' WHERE account_id=?';
      const read = (sql: string) => {
        const statement = DB.prepare(sql);
        return (account === undefined ? statement : statement.bind(account)).all();
      };
      const heads = (
        await read(`SELECT * FROM vault_owner_record_head${where} ORDER BY account_id,record_id`)
      ).results;
      const mutations = (
        await read(
          `SELECT * FROM vault_owner_record_mutation${where} ORDER BY account_id,operation_id`,
        )
      ).results;
      const listing = await VAULT_BLOBS.list();
      assert.equal(
        listing.truncated,
        false,
        'the effect comparison must include every test object',
      );
      const keys: string[] =
        account === undefined
          ? listing.objects.map((object: { key: string }) => object.key)
          : heads.flatMap((head: { object_key: string | null }) =>
              head.object_key === null ? [] : [head.object_key],
            );
      const objects = [];
      keys.sort((a, b) => a.localeCompare(b, 'en'));
      for (const key of keys) {
        const object = await VAULT_BLOBS.get(key);
        assert.ok(object, 'a referenced object must exist');
        objects.push({ key, digest: hash(new Uint8Array(await object.arrayBuffer())) });
      }
      const candidates =
        account === undefined
          ? (await DB.prepare('SELECT * FROM vault_gc_candidate ORDER BY object_key').all()).results
          : undefined;
      return { heads, mutations, objects, candidates };
    };
    return { worker, DB, bootstrap, snapshot, arm, close };
  } catch (error) {
    await close();
    throw error;
  }
}

type Fixture = Awaited<ReturnType<typeof fixture>>;
type Owner = Awaited<ReturnType<Fixture['bootstrap']>>;
async function expectJson(
  response: {
    status: number;
    text(): Promise<string>;
    headers: { get(name: string): string | null };
  },
  status: number,
) {
  const text = await response.text();
  assert.equal(response.status, status, text);
  assert.match(response.headers.get('cache-control') ?? '', /no-store/);
  return JSON.parse(text);
}
async function candidate(owner: Owner, revision = 1, record = 'shared') {
  return JSON.stringify({
    ...(await sealOwnerRecord(
      new TextEncoder().encode(`synthetic private record for ${owner.account}`),
      owner.key,
      owner.context,
      { collectionId: 'messages', recordId: record, kind: 'message', revision },
    )),
    vault_id: 'vault',
    key_generation: 1,
    owner_key_revision: 1,
    kind: 'message',
    revision,
  });
}
const deletion = (revision = 2) =>
  JSON.stringify({
    format_version: 2,
    vault_id: 'vault',
    key_generation: 1,
    owner_key_revision: 1,
    kind: 'message',
    revision,
  });
function write(
  f: Fixture,
  owner: Owner,
  body: string,
  expected = 0,
  operation = opaque(),
  method = 'PUT',
  record = 'shared',
) {
  return f.worker.fetch(recordUrl(record), {
    method,
    headers: {
      ...owner.headers,
      'X-Operation-ID': operation,
      ...(expected === 0 ? { 'If-None-Match': '*' } : { 'If-Match': `"${expected}"` }),
    },
    body,
  });
}

test('SEC-01/06 packaged owner authorization and durable effects', async (t) => {
  const f = await fixture();
  t.after(f.close);

  await t.test(
    'SEC-01 guessed identifiers and forged owner hints disclose no other owner data',
    async () => {
      const a = await f.bootstrap('read-a'),
        b = await f.bootstrap('read-b');
      await expectJson(await write(f, a, await candidate(a)), 200);
      const before = await f.snapshot();
      const headers = { ...b.headers, 'X-Owner-ID': a.account, 'X-Account-ID': a.account };
      const missing = await expectJson(await f.worker.fetch(recordUrl(), { headers }), 404);
      assert.deepEqual(missing, { error: 'not_found' });
      const list = await expectJson(await f.worker.fetch(records, { headers }), 200);
      assert.equal(list.owner_id, b.account);
      assert.deepEqual(list.records, []);
      assert.equal(list.next_cursor, null);
      assert.deepEqual(
        await expectJson(
          await f.worker.fetch(`${records}?owner_id=${a.account}`, { headers }),
          400,
        ),
        { error: 'invalid_query' },
      );
      assert.deepEqual(await f.snapshot(), before);
    },
  );

  await t.test(
    'SEC-01 a foreign update receipt cannot acknowledge or delete a guessed record',
    async () => {
      const a = await f.bootstrap('receipt-a'),
        b = await f.bootstrap('receipt-b');
      await expectJson(await write(f, a, await candidate(a)), 200);
      const operation = opaque(),
        body = await candidate(a, 2);
      await expectJson(await write(f, a, body, 1, operation), 200);
      const before = await f.snapshot();
      for (const [method, payload, status, error] of [
        ['PUT', body, 409, 'revision_conflict'],
        ['DELETE', deletion(), 409, 'revision_conflict'],
        ['PUT', JSON.stringify({ ...JSON.parse(body), owner_id: a.account }), 400, 'invalid_body'],
      ] as const) {
        const result = await expectJson(await write(f, b, payload, 1, operation, method), status);
        assert.deepEqual(result, { error });
        assert.deepEqual(await f.snapshot(), before);
      }
    },
  );

  await t.test(
    'SEC-01 matching IDs and operation IDs mutate only the authenticated owner',
    async () => {
      const a = await f.bootstrap('collision-a'),
        b = await f.bootstrap('collision-b'),
        operation = opaque();
      await expectJson(await write(f, a, await candidate(a), 0, operation), 200);
      const before = await f.snapshot(a.account);
      await expectJson(await write(f, b, await candidate(b), 0, operation), 200);
      const update = await candidate(b, 2),
        updateId = opaque();
      await expectJson(await write(f, b, update, 1, updateId), 200);
      await expectJson(await write(f, b, deletion(3), 2, opaque(), 'DELETE'), 200);
      assert.deepEqual(await expectJson(await write(f, b, update, 1, updateId), 200), {
        revision: 2,
        deleted: false,
      });
      assert.deepEqual(
        await expectJson(await f.worker.fetch(recordUrl(), { headers: b.headers }), 404),
        { error: 'not_found', deleted: true },
      );
      assert.deepEqual(await f.snapshot(a.account), before);
      const own = await expectJson(await f.worker.fetch(recordUrl(), { headers: a.headers }), 200);
      assert.equal(own.owner_id, a.account);
      assert.equal(own.revision, 1);
      const other = await f.snapshot(b.account);
      assert.equal(other.heads[0].revision, 3);
      assert.equal(other.heads[0].deleted, 1);
      assert.equal(other.mutations.length, 3);
    },
  );

  await t.test(
    'SEC-06 absent and revoked sessions cannot read, list, write or delete',
    async () => {
      const owner = await f.bootstrap('revoked');
      await expectJson(await write(f, owner, await candidate(owner)), 200);
      await f.DB.prepare('UPDATE sso_session SET revoked=1 WHERE sso_id=?')
        .bind(owner.session)
        .run();
      const before = await f.snapshot();
      for (const cookie of ['', owner.headers.Cookie]) {
        const actor = { ...owner, headers: { ...owner.headers, Cookie: cookie } };
        for (const response of [
          await f.worker.fetch(recordUrl(), { headers: actor.headers }),
          await f.worker.fetch(records, { headers: actor.headers }),
          await write(f, actor, await candidate(owner, 2), 1),
          await write(f, actor, deletion(), 1, opaque(), 'DELETE'),
        ]) {
          assert.deepEqual(await expectJson(response, 401), { error: 'authentication_required' });
        }
        assert.deepEqual(await f.snapshot(), before);
      }
    },
  );

  const changes = [
    ['session', (o: Owner) => `UPDATE sso_session SET revoked=1 WHERE sso_id='${o.session}'`],
    [
      'epoch',
      (o: Owner) => `UPDATE account_security SET epoch=epoch+1 WHERE account_id='${o.account}'`,
    ],
    [
      'credential',
      (o: Owner) => `UPDATE credential SET active=0 WHERE credential_id='${o.credential}'`,
    ],
  ] as const;
  for (const stage of ['commit', 'list']) {
    for (const [name, change] of changes) {
      await t.test(
        `SEC-06 ${name} invalidation at ${stage} prevents effects or metadata disclosure`,
        async () => {
          const owner = await f.bootstrap(`race-${stage}-${name}`);
          await expectJson(await write(f, owner, await candidate(owner)), 200);
          const before = await f.snapshot();
          await f.arm(stage, change(owner));
          try {
            const response =
              stage === 'commit'
                ? await write(f, owner, deletion(), 1, opaque(), 'DELETE')
                : await f.worker.fetch(records, { headers: owner.headers });
            assert.deepEqual(await expectJson(response, 409), { error: 'owner_key_changed' });
            assert.equal(
              await f.DB.prepare('SELECT hits FROM security_test_fault WHERE id=1').first('hits'),
              1,
              'the authority change must actually execute at the intended boundary',
            );
            assert.deepEqual(await f.snapshot(), before);
          } finally {
            await f.arm();
          }
        },
      );
    }
  }
});
