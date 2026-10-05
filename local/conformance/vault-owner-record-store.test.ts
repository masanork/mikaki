import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHash, randomBytes } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createTestHarness } from 'wrangler';
import {
  createOwnerKey,
  openOwnerKey,
  sealOwnerRecord,
  openOwnerRecord,
  OWNER_KEY_SUITE,
  OWNER_RECORD_MAX_BYTES,
  type OwnerRecord,
} from '../../crates/worker/ui/vault-owner-crypto.ts';

const origin = 'https://mikaki.test';
const id = () => randomBytes(32).toString('base64url');
const hash = (value: string) => createHash('sha256').update(value).digest('base64url');
const bytes = (value: string) => new TextEncoder().encode(value);
const recordUrl = (collection = 'messages', record = 'one') =>
  `${origin}/vault/records/${collection}/${record}`;
const listUrl = (collection = 'messages') => `${origin}/vault/records/${collection}`;
const noncanonical = (value: string) => {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  return value.slice(0, -1) + alphabet[alphabet.indexOf(value.at(-1)!) | 1];
};
type RecordResponse = OwnerRecord & {
  owner_id: string;
  origin: string;
  vault_id: string;
  key_generation: number;
  owner_key_revision: number;
  collection_id: string;
  record_id: string;
  kind: string;
  revision: number;
};
type ListedRecord = {
  record_id: string;
  kind: string;
  revision: number;
  key_generation: number;
  deleted: boolean;
};
type ListResponse = {
  format_version: number;
  owner_id: string;
  origin: string;
  vault_id: string;
  key_generation: number;
  owner_key_revision: number;
  collection_id: string;
  records: ListedRecord[];
  next_cursor: string | null;
};

// This invokes the built Rust OP in workerd. Only the test-owned R2 binding is
// wrapped: faults happen after the real upload or full object read. A narrow D1
// proxy also exposes receipt/admission awaits; real SQL and commits still run.
test('owner-key v2 record API preserves ciphertext, exact mutations and live owner authority in workerd', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'mikaki-owner-record-'));
  const shim = new URL('../../crates/worker/build/worker/shim.mjs', import.meta.url).pathname;
  await writeFile(
    join(directory, 'op.mjs'),
    `import Op from ${JSON.stringify(shim)};
    function bindings(env, fault, request, ctx) {
      const trip = async (stage) => {
        if (fault.stage !== stage) return;
        await env.DB.prepare('UPDATE owner_record_test_fault SET hits=hits+1 WHERE id=1').run();
        if (fault.statement) await env.DB.exec(fault.statement);
        if (fault.mode === 'throw') throw new Error('injected R2 ' + stage + ' failure');
      };
      const bucket = new Proxy(env.VAULT_BLOBS, { get(target, key) {
        if (key === 'constructor') return target.constructor;
        if (key === 'put') return async (...args) => {
          if (fault.stage === 'put' && fault.mode === 'throw') await trip('put');
          if (fault.stage === 'put' && fault.mode === 'collision') await target.put(args[0], new Uint8Array([77]));
          const result = await target.put(...args);
          await trip('put');
          return result;
        };
        if (key === 'get') return async (...args) => {
          if (fault.stage === 'get' && fault.mode === 'throw') await trip('get');
          const object = await target.get(...args);
          await trip('get');
          if (!object || fault.stage !== 'body') return object;
          return new Proxy(object, { get(body, property) {
            if (property === 'constructor') return body.constructor;
            if (property === 'arrayBuffer') return async () => {
              const result = await body.arrayBuffer();
              await trip('body');
              return result;
            };
            const value = Reflect.get(body, property, body);
            return typeof value === 'function' ? value.bind(body) : value;
          }});
        };
        const value = Reflect.get(target, key, target);
        return typeof value === 'function' ? value.bind(target) : value;
      }});
      const replay = async (stage) => {
        await trip(stage);
        const response = await new Op(ctx, env).fetch(request.clone());
        if (response.status !== 200) throw new Error('replayed request failed: ' + response.status + ' ' + await response.text());
      };
      const statement = (target, sql) => new Proxy(target, { get(prepared, key) {
        if (key === 'constructor') return prepared.constructor;
        if (key === 'bind') return (...args) => statement(prepared.bind(...args), sql);
        if (key === 'first') return async (...args) => {
          if (fault.stage === 'limits' && sql.includes(' AS recent,')) await replay('limits');
          if (fault.stage === 'head' && sql.startsWith('SELECT kind,revision,')) await replay('head');
          const result = await prepared.first(...args);
          if (fault.stage === 'receipt' && result && sql.startsWith('SELECT request_hash,result_revision,')) await trip('receipt');
          if (fault.stage === 'admission' && result && sql.includes('AS observed_at')) {
            await trip('admission');
            return {...result, observed_at: result.observed_at - 301};
          }
          return result;
        };
        const value = Reflect.get(prepared, key, prepared);
        return typeof value === 'function' ? value.bind(prepared) : value;
      }});
      const db = new Proxy(env.DB, { get(target, key) {
        if (key === 'constructor') return target.constructor;
        if (key === 'prepare') return (sql) => {
          const prepared = target.prepare(sql);
          return ['limits','head','receipt','admission'].includes(fault.stage) && sql.startsWith('SELECT') ? statement(prepared, sql) : prepared;
        };
        const value = Reflect.get(target, key, target);
        return typeof value === 'function' ? value.bind(target) : value;
      }});
      return {DB: db, VAULT_BLOBS: bucket};
    }
    export default {
      async fetch(request, env, ctx) {
        const fault = await env.DB.prepare('SELECT stage,mode,statement FROM owner_record_test_fault WHERE id=1').first();
        return new Op(ctx, {...env, ...bindings(env, fault, request.clone(), ctx)}).fetch(request);
      },
      async scheduled(event, env, ctx) {
        return new Op(ctx, env).scheduled(event);
      }
    };`,
  );
  const harness = createTestHarness({
    root: new URL('../..', import.meta.url).pathname,
    workers: [
      {
        config: {
          name: 'mikaki-owner-record-test',
          main: join(directory, 'op.mjs'),
          compatibility_date: '2026-09-28',
          vars: { MIKAKI_ISSUER: origin },
          d1_databases: [
            {
              binding: 'DB',
              database_name: 'mikaki-op-dev',
              database_id: '00000000-0000-0000-0000-000000000000',
              migrations_dir: new URL('../../crates/worker/migrations/', import.meta.url).pathname,
            },
          ],
          r2_buckets: [{ binding: 'VAULT_BLOBS', bucket_name: 'mikaki-vault-dev' }],
          triggers: { crons: ['* * * * *'] },
        },
      },
    ],
  });
  try {
    await harness.listen();
    const worker = harness.getWorker('mikaki-owner-record-test');
    await worker.applyD1Migrations('DB');
    const env = await worker.getEnv();
    await env.DB.exec(
      "CREATE TABLE owner_record_test_fault (id INTEGER PRIMARY KEY, stage TEXT NOT NULL, mode TEXT NOT NULL, statement TEXT NOT NULL, hits INTEGER NOT NULL); INSERT INTO owner_record_test_fault VALUES(1,'','','',0)",
    );
    const fault = async (stage = '', statement = '', mode = '') => {
      await env.DB.prepare(
        'UPDATE owner_record_test_fault SET stage=?,statement=?,mode=?,hits=0 WHERE id=1',
      )
        .bind(stage, statement, mode)
        .run();
    };
    const hits = async () =>
      (await env.DB.prepare('SELECT hits FROM owner_record_test_fault WHERE id=1').first()).hits;
    const seedSession = async (account: string, session = account, existing = false) => {
      const secret = id(),
        credential = id(),
        now = Math.floor(Date.now() / 1000);
      if (!existing)
        await env.DB.prepare('INSERT INTO account_security VALUES(?,1,1)').bind(account).run();
      await env.DB.batch([
        env.DB.prepare('INSERT INTO credential VALUES(?,?,1)').bind(credential, account),
        env.DB.prepare('INSERT INTO sso_session VALUES(?,?,?,1,?,0)').bind(
          session,
          account,
          credential,
          now + 3600,
        ),
        env.DB.prepare('INSERT INTO sso_context VALUES(?,?,?)').bind(session, hash(secret), now),
      ]);
      return { account, session, secret, credential };
    };
    const bootstrap = async (account: string) => {
      const identity = await seedSession(account);
      const context = { origin, ownerId: account, vaultId: 'vault', keyGeneration: 1 };
      const credential = new Uint8Array(Buffer.from(identity.credential, 'base64url'));
      const output = new Uint8Array(randomBytes(32));
      const created = await createOwnerKey(
        context,
        credential,
        new Uint8Array(randomBytes(32)),
        output.slice(),
      );
      const headers = {
        Cookie: `__Host-op-sso=${identity.secret}`,
        Origin: origin,
        'Content-Type': 'application/json',
      };
      const response = await worker.fetch(`${origin}/vault/owner-key`, {
        method: 'PUT',
        headers: { ...headers, 'If-None-Match': '*', 'X-Operation-ID': id() },
        body: JSON.stringify({
          format_version: 2,
          suite: OWNER_KEY_SUITE,
          vault_id: context.vaultId,
          key_generation: 1,
          owner_envelope: created.envelope,
        }),
      });
      assert.equal(response.status, 200, await response.clone().text());
      const fetched = await worker.fetch(`${origin}/vault/owner-key`, { headers });
      assert.equal(fetched.status, 200);
      const root = (await fetched.json()) as { owner_envelope: unknown };
      const key = await openOwnerKey(root.owner_envelope, context, credential, output.slice());
      return { ...identity, context, headers, key, envelope: created.envelope };
    };
    type Owner = Awaited<ReturnType<typeof bootstrap>>;
    let failedLedgerObject: string | undefined;
    const candidate = async (
      owner: Owner,
      record = 'one',
      revision = 1,
      plaintext = bytes('新しいVaultの会話'),
      collection = 'messages',
      kind = 'message',
      ownerKeyRevision = 1,
    ) => {
      const encrypted = await sealOwnerRecord(plaintext, owner.key, owner.context, {
        collectionId: collection,
        recordId: record,
        kind,
        revision,
      });
      return JSON.stringify({
        ...encrypted,
        vault_id: owner.context.vaultId,
        key_generation: owner.context.keyGeneration,
        owner_key_revision: ownerKeyRevision,
        kind,
        revision,
      });
    };
    const deletion = (owner: Owner, revision: number, kind = 'message', ownerKeyRevision = 1) =>
      JSON.stringify({
        format_version: 2,
        vault_id: owner.context.vaultId,
        key_generation: owner.context.keyGeneration,
        owner_key_revision: ownerKeyRevision,
        kind,
        revision,
      });
    const mutate = (
      owner: Owner,
      body: string,
      expected = 0,
      operation = id(),
      method = 'PUT',
      collection = 'messages',
      record = 'one',
      overrides: Record<string, string> = {},
    ) =>
      worker.fetch(recordUrl(collection, record), {
        method,
        headers: {
          ...owner.headers,
          'X-Operation-ID': operation,
          ...(expected === 0 ? { 'If-None-Match': '*' } : { 'If-Match': `"${expected}"` }),
          ...overrides,
        },
        body,
      });
    const get = (owner: Owner, collection = 'messages', record = 'one') =>
      worker.fetch(recordUrl(collection, record), { headers: owner.headers });
    const list = (owner: Owner, query = '', collection = 'messages') =>
      worker.fetch(listUrl(collection) + query, { headers: owner.headers });
    const head = (owner: Owner, collection = 'messages', record = 'one') =>
      env.DB.prepare(
        `SELECT * FROM vault_owner_record_head
        WHERE account_id=? AND vault_id=? AND collection_id=? AND record_id=?`,
      )
        .bind(owner.account, owner.context.vaultId, collection, record)
        .first();
    const ledgerCount = async (owner: Owner) =>
      (
        await env.DB.prepare(
          'SELECT count(*) AS n FROM vault_owner_record_mutation WHERE account_id=?',
        )
          .bind(owner.account)
          .first()
      ).n;
    const decrypt = async (owner: Owner, collection = 'messages', record = 'one') => {
      const response = await get(owner, collection, record);
      assert.equal(response.status, 200, await response.clone().text());
      assert.equal(response.headers.get('cache-control'), 'no-store');
      const value = (await response.json()) as RecordResponse;
      assert.equal(response.headers.get('etag'), `"${value.revision}"`);
      assert.deepEqual(
        [
          value.owner_id,
          value.origin,
          value.vault_id,
          value.key_generation,
          value.collection_id,
          value.record_id,
        ],
        [owner.account, origin, owner.context.vaultId, 1, collection, record],
      );
      const plaintext = await openOwnerRecord(
        {
          format_version: value.format_version,
          ciphertext: value.ciphertext,
          key_envelope: value.key_envelope,
        },
        owner.key,
        owner.context,
        {
          collectionId: collection,
          recordId: record,
          kind: value.kind,
          revision: value.revision,
        },
      );
      return { value, plaintext };
    };

    await t.test(
      'real bootstrap and recovered owner key round-trip empty, Unicode and maximum records',
      async () => {
        const owner = await bootstrap('roundtrip');
        const missing = await get(owner);
        assert.equal(missing.status, 404);
        assert.equal(missing.headers.get('etag'), null);
        assert.deepEqual(await missing.json(), { error: 'not_found' });
        const values = [
          new Uint8Array(),
          bytes('会話の保存 🗾'),
          new Uint8Array(OWNER_RECORD_MAX_BYTES - 29).fill(0x9a),
        ];
        for (const [index, plaintext] of values.entries()) {
          const record = `size-${index}`;
          const body = await candidate(owner, record, 1, plaintext);
          const result = await mutate(owner, body, 0, id(), 'PUT', 'messages', record);
          assert.equal(result.status, 200, await result.clone().text());
          assert.equal(result.headers.get('etag'), '"1"');
          assert.equal(result.headers.get('cache-control'), 'no-store');
          assert.deepEqual(await result.json(), { revision: 1, deleted: false });
          const opened = await decrypt(owner, 'messages', record);
          assert.deepEqual(opened.plaintext, plaintext);
          assert.equal(opened.value.owner_key_revision, 1);
          const stored = await head(owner, 'messages', record);
          const object = await env.VAULT_BLOBS.get(stored.object_key);
          assert.match(stored.object_key, /^vault-owner-record\/[A-Za-z0-9_-]{43}$/);
          assert.deepEqual(
            Buffer.from(await object.arrayBuffer()),
            Buffer.from(opened.value.ciphertext, 'base64url'),
          );
        }
        assert.equal((await head(owner, 'messages', 'size-0')).revision, 1);
        assert.equal(await ledgerCount(owner), 3);
      },
    );

    await t.test(
      'owner, collection and record isolation; SSO and the active credential wrapper are required',
      async () => {
        const owner = await bootstrap('isolation'),
          other = await bootstrap('isolation-other');
        const body = await candidate(owner);
        assert.equal((await mutate(owner, body)).status, 200);
        assert.equal((await get(other)).status, 404);
        assert.equal((await get(owner, 'different')).status, 404);
        assert.equal((await get(owner, 'messages', 'different')).status, 404);
        assert.equal((await worker.fetch(recordUrl())).status, 401);
        for (const endpoint of [recordUrl(), listUrl()]) {
          assert.equal(
            (await worker.fetch(endpoint, { headers: { Authorization: `Bearer ${id()}` } })).status,
            401,
          );
        }
        assert.equal(
          (
            await worker.fetch(recordUrl(), {
              method: 'PUT',
              headers: {
                Origin: origin,
                'Content-Type': 'application/json',
                'X-Operation-ID': id(),
                'If-None-Match': '*',
                Authorization: `Bearer ${id()}`,
              },
              body,
            })
          ).status,
          401,
        );
        const unwrapped = await seedSession(owner.account, 'unwrapped', true);
        const headers = { ...owner.headers, Cookie: `__Host-op-sso=${unwrapped.secret}` };
        for (const endpoint of [recordUrl(), listUrl()]) {
          const response = await worker.fetch(endpoint, { headers });
          assert.equal(response.status, 409);
          assert.deepEqual(await response.json(), { error: 'owner_key_unavailable' });
        }
        assert.equal(
          (await mutate(owner, body, 0, id(), 'PUT', 'messages', 'two', headers)).status,
          409,
        );
        const noRoot = await seedSession('no-root');
        assert.equal(
          (
            await worker.fetch(recordUrl(), {
              headers: { Cookie: `__Host-op-sso=${noRoot.secret}` },
            })
          ).status,
          409,
        );
        const otherBody = await candidate(other);
        assert.equal((await mutate(other, otherBody)).status, 200);
        assert.notEqual((await head(owner)).object_key, (await head(other)).object_key);
        const otherOpened = await decrypt(other);
        await assert.rejects(
          openOwnerRecord(
            {
              format_version: 2,
              ciphertext: otherOpened.value.ciphertext,
              key_envelope: otherOpened.value.key_envelope,
            },
            owner.key,
            owner.context,
            { collectionId: 'messages', recordId: 'one', kind: 'message', revision: 1 },
          ),
        );
        const collectionBody = await candidate(
          owner,
          'one',
          1,
          bytes('separate collection'),
          'notes',
        );
        assert.equal((await mutate(owner, collectionBody, 0, id(), 'PUT', 'notes')).status, 200);
        assert.equal(
          new TextDecoder().decode((await decrypt(owner, 'notes')).plaintext),
          'separate collection',
        );
        assert.equal(await ledgerCount(owner), 2);
      },
    );

    await t.test(
      'strict body, canonical frame, path, origin, context and precondition validation does not touch storage',
      async () => {
        const owner = await bootstrap('validation');
        const body = await candidate(owner),
          valid = JSON.parse(body) as Record<string, unknown>;
        const malformed = [
          'not-json',
          'null',
          '[]',
          '{}',
          body.replace('{', '{"format_version":2,'),
          JSON.stringify({ ...valid, format_version: 1 }),
          JSON.stringify({ ...valid, extra: true }),
          JSON.stringify({ ...valid, ciphertext: null }),
          JSON.stringify({ ...valid, key_envelope: 2 }),
          JSON.stringify({ ...valid, ciphertext: `${valid.ciphertext}=` }),
          JSON.stringify({ ...valid, key_envelope: `${valid.key_envelope}=` }),
          JSON.stringify({ ...valid, key_envelope: noncanonical(valid.key_envelope as string) }),
          JSON.stringify({ ...valid, ciphertext: Buffer.alloc(28, 2).toString('base64url') }),
          JSON.stringify({
            ...valid,
            ciphertext: Buffer.alloc(OWNER_RECORD_MAX_BYTES + 1, 2).toString('base64url'),
          }),
          JSON.stringify({ ...valid, ciphertext: Buffer.alloc(29, 1).toString('base64url') }),
          JSON.stringify({ ...valid, key_envelope: Buffer.alloc(60, 2).toString('base64url') }),
          JSON.stringify({ ...valid, key_envelope: Buffer.alloc(61, 1).toString('base64url') }),
          ...[0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1].map((key_generation) =>
            JSON.stringify({ ...valid, key_generation }),
          ),
          JSON.stringify({ ...valid, owner_key_revision: 0 }),
          JSON.stringify({ ...valid, revision: 2 }),
          JSON.stringify({ ...valid, kind: '' }),
          JSON.stringify({ ...valid, kind: 'wrong kind' }),
          JSON.stringify({ ...valid, vault_id: 'x'.repeat(129) }),
        ];
        const before = (await env.VAULT_BLOBS.list()).objects.length;
        for (const invalid of malformed) {
          const response = await mutate(owner, invalid);
          assert.equal(
            response.status,
            400,
            `body ${invalid.slice(0, 120)}: ${await response.text()}`,
          );
        }
        for (const change of [
          { vault_id: 'unknown' },
          { key_generation: 2 },
          { owner_key_revision: 2 },
        ])
          assert.equal((await mutate(owner, JSON.stringify({ ...valid, ...change }))).status, 409);
        assert.equal((await mutate(owner, 'x'.repeat(36 * 1024 + 1))).status, 413);
        assert.equal(
          (
            await mutate(owner, body, 0, id(), 'PUT', 'messages', 'one', {
              'Content-Type': 'text/plain',
            })
          ).status,
          415,
        );
        assert.equal(
          (
            await mutate(owner, body, 0, id(), 'PUT', 'messages', 'one', {
              Origin: 'https://evil.test',
            })
          ).status,
          403,
        );
        assert.equal(
          (await worker.fetch(recordUrl(), { method: 'PUT', headers: owner.headers, body })).status,
          428,
        );
        for (const condition of ['1', 'W/"1"', '"0"', '"01"', '"+1"', '"9007199254740991"'])
          assert.equal(
            (
              await worker.fetch(recordUrl(), {
                method: 'PUT',
                headers: {
                  ...owner.headers,
                  'X-Operation-ID': id(),
                  'If-Match': condition,
                },
                body,
              })
            ).status,
            428,
          );
        assert.equal(
          (await mutate(owner, body, 0, id(), 'PUT', 'messages', 'one', { 'If-Match': '"1"' }))
            .status,
          428,
        );
        for (const operation of ['', 'bad', `${id()}=`, noncanonical(id())])
          assert.equal((await mutate(owner, body, 0, operation)).status, 400);
        for (const collection of ['bad%20id', 'x'.repeat(129)])
          assert.equal((await mutate(owner, body, 0, id(), 'PUT', collection)).status, 400);
        assert.equal((await mutate(owner, deletion(owner, 1), 0, id(), 'DELETE')).status, 428);
        assert.equal((await mutate(owner, 'x'.repeat(1025), 1, id(), 'DELETE')).status, 413);
        assert.equal(
          (
            await mutate(
              owner,
              JSON.stringify({ ...JSON.parse(deletion(owner, 2)), ciphertext: 'extra' }),
              1,
              id(),
              'DELETE',
            )
          ).status,
          400,
        );
        assert.equal((await env.VAULT_BLOBS.list()).objects.length, before);
        assert.equal(await head(owner), null);
        assert.equal(await ledgerCount(owner), 0);
      },
    );

    await t.test(
      'lost success and exact retries acknowledge historical outcomes without restoring newer heads',
      async () => {
        const owner = await bootstrap('retries');
        const first = await candidate(owner),
          operation = id();
        // Discard the first successful response as if the transport lost it.
        assert.equal((await mutate(owner, first, 0, operation)).status, 200);
        const original = await head(owner),
          objects = (await env.VAULT_BLOBS.list()).objects.length;
        const retry = await mutate(owner, first, 0, operation);
        assert.equal(retry.status, 200);
        assert.deepEqual(await retry.json(), { revision: 1, deleted: false });
        assert.equal((await env.VAULT_BLOBS.list()).objects.length, objects);
        assert.equal(await ledgerCount(owner), 1);
        for (const altered of [first + '\n', await candidate(owner)])
          assert.equal((await mutate(owner, altered, 0, operation)).status, 409);
        assert.equal((await mutate(owner, first, 0, operation, 'PUT', 'other')).status, 409);
        const second = await candidate(owner, 'one', 2, bytes('newer value'));
        assert.equal((await mutate(owner, second, 1)).status, 200);
        assert.equal(
          (
            await mutate(
              owner,
              await candidate(owner, 'one', 2, bytes('wrong kind'), 'messages', 'different'),
              1,
            )
          ).status,
          409,
        );
        const old = await mutate(owner, first, 0, operation);
        assert.equal(old.status, 200);
        assert.equal(old.headers.get('etag'), '"1"');
        assert.equal(new TextDecoder().decode((await decrypt(owner)).plaintext), 'newer value');
        assert.notEqual((await head(owner)).object_key, original.object_key);
        assert.equal(await ledgerCount(owner), 2);
        // Registry revisions are distinct from content revisions. Historical success
        // is still an acknowledgment, even when the root registry is newer.
        await env.DB.prepare('UPDATE vault_owner_key_head SET revision=2 WHERE account_id=?')
          .bind(owner.account)
          .run();
        assert.equal((await mutate(owner, first, 0, operation)).status, 200);
        assert.equal((await decrypt(owner)).value.owner_key_revision, 2);
        assert.equal((await mutate(owner, await candidate(owner, 'one', 3), 2)).status, 409);
        assert.equal(
          (
            await mutate(
              owner,
              await candidate(owner, 'one', 3, bytes('registry-aware'), 'messages', 'message', 2),
              2,
            )
          ).status,
          200,
        );
      },
    );

    await t.test(
      'simultaneous same-operation and different-operation mutations retain a single linear head',
      async () => {
        const owner = await bootstrap('concurrency');
        const initial = await candidate(owner),
          operation = id();
        const same = await Promise.all([
          mutate(owner, initial, 0, operation),
          mutate(owner, initial, 0, operation),
        ]);
        for (const response of same)
          assert.equal(response.status, 200, await response.clone().text());
        assert.equal(await ledgerCount(owner), 1);
        assert.equal((await head(owner)).revision, 1);
        const a = await candidate(owner, 'one', 2, bytes('a')),
          b = await candidate(owner, 'one', 2, bytes('b'));
        const different = await Promise.all([mutate(owner, a, 1), mutate(owner, b, 1)]);
        assert.deepEqual(different.map((r) => r.status).sort(), [200, 409]);
        assert.equal(await ledgerCount(owner), 2);
        const winner = different[0]!.status === 200 ? 'a' : 'b';
        assert.equal(new TextDecoder().decode((await decrypt(owner)).plaintext), winner);
        const update = await candidate(owner, 'one', 3, bytes('edit versus delete'));
        const race = await Promise.all([
          mutate(owner, update, 2),
          mutate(owner, deletion(owner, 3), 2, id(), 'DELETE'),
        ]);
        assert.deepEqual(race.map((r) => r.status).sort(), [200, 409]);
        assert.equal((await head(owner)).revision, 3);
        assert.equal(await ledgerCount(owner), 3);
        if (race[0]!.status === 200)
          assert.equal((await mutate(owner, deletion(owner, 4), 3, id(), 'DELETE')).status, 200);
        const tombstoneRevision = (await head(owner)).revision as number;
        const recreate = await candidate(owner, 'one', tombstoneRevision + 1, bytes('recreated'));
        const recreateRace = await Promise.all([
          mutate(owner, recreate, tombstoneRevision),
          mutate(owner, deletion(owner, tombstoneRevision + 1), tombstoneRevision, id(), 'DELETE'),
        ]);
        assert.deepEqual(
          recreateRace.map((r) => r.status),
          [200, 409],
        );
        assert.equal(new TextDecoder().decode((await decrypt(owner)).plaintext), 'recreated');
        const now = tombstoneRevision + 1,
          deleteOp = id(),
          deleteBody = deletion(owner, now + 1);
        const duplicateDelete = await Promise.all([
          mutate(owner, deleteBody, now, deleteOp, 'DELETE'),
          mutate(owner, deleteBody, now, deleteOp, 'DELETE'),
        ]);
        for (const response of duplicateDelete)
          assert.equal(response.status, 200, await response.clone().text());
        assert.equal((await head(owner)).revision, now + 1);
      },
    );

    await t.test(
      'tombstones retain revision and kind; only explicit fresh-ciphertext PUT recreates',
      async () => {
        const owner = await bootstrap('tombstones');
        assert.equal((await mutate(owner, await candidate(owner))).status, 200);
        const op = id(),
          body = deletion(owner, 2);
        const removed = await mutate(owner, body, 1, op, 'DELETE');
        assert.equal(removed.status, 200);
        assert.deepEqual(await removed.json(), { revision: 2, deleted: true });
        const tombstone = await get(owner);
        assert.equal(tombstone.status, 404);
        assert.equal(tombstone.headers.get('etag'), '"2"');
        assert.deepEqual(await tombstone.json(), { error: 'not_found', deleted: true });
        const stored = await head(owner);
        assert.deepEqual(
          [stored.object_key, stored.ciphertext_sha256, stored.key_envelope],
          [null, null, null],
        );
        assert.equal((await mutate(owner, body, 1, op, 'DELETE')).status, 200);
        assert.equal((await mutate(owner, deletion(owner, 3), 2, id(), 'DELETE')).status, 409);
        assert.equal((await mutate(owner, await candidate(owner))).status, 409);
        assert.equal(
          (
            await mutate(
              owner,
              await candidate(owner, 'one', 3, bytes('wrong kind'), 'messages', 'changed'),
              2,
            )
          ).status,
          409,
        );
        assert.equal(
          (await mutate(owner, await candidate(owner, 'one', 3, bytes('recreated')), 2)).status,
          200,
        );
        assert.equal((await mutate(owner, body, 1, op, 'DELETE')).status, 200);
        assert.equal((await decrypt(owner)).value.revision, 3);
        assert.equal(await ledgerCount(owner), 3);
      },
    );

    await t.test(
      'R2 errors, missing/tampered objects and failed ledger insertion never publish partial mutations',
      async () => {
        const owner = await bootstrap('failures');
        const body = await candidate(owner),
          operation = id();
        await fault('put', '', 'throw');
        try {
          assert.equal((await mutate(owner, body, 0, operation)).status, 503);
          assert.equal(await hits(), 1);
          assert.equal(await head(owner), null);
          assert.equal(await ledgerCount(owner), 0);
        } finally {
          await fault();
        }
        const beforeCollision = new Set(
          (await env.VAULT_BLOBS.list()).objects.map((object: { key: string }) => object.key),
        );
        await fault('put', '', 'collision');
        try {
          assert.equal((await mutate(owner, body, 0, operation)).status, 503);
          assert.equal(await hits(), 1);
          assert.equal(await head(owner), null);
          assert.equal(await ledgerCount(owner), 0);
          const collided = (await env.VAULT_BLOBS.list()).objects.find(
            (object: { key: string }) => !beforeCollision.has(object.key),
          );
          assert.ok(collided);
          assert.deepEqual(
            Buffer.from(await (await env.VAULT_BLOBS.get(collided.key)).arrayBuffer()),
            Buffer.from([77]),
            'conditional upload must not overwrite an existing random-key collision',
          );
        } finally {
          await fault();
        }
        const beforeLedgerFailure = new Set(
          (await env.VAULT_BLOBS.list()).objects.map((object: { key: string }) => object.key),
        );
        await env.DB.exec(
          `CREATE TRIGGER reject_owner_record_ledger BEFORE INSERT ON vault_owner_record_mutation WHEN NEW.account_id='failures' BEGIN SELECT RAISE(ABORT,'injected ledger failure'); END`,
        );
        try {
          assert.equal((await mutate(owner, body, 0, operation)).status, 503);
          assert.equal(await head(owner), null);
          assert.equal(await ledgerCount(owner), 0);
        } finally {
          await env.DB.exec('DROP TRIGGER reject_owner_record_ledger');
        }
        failedLedgerObject = (await env.VAULT_BLOBS.list()).objects.find(
          (object: { key: string }) => !beforeLedgerFailure.has(object.key),
        )?.key;
        assert.ok(failedLedgerObject, 'failed D1 publication leaves an R2 orphan for delayed GC');
        assert.equal((await mutate(owner, body, 0, operation)).status, 200);
        const stored = await head(owner),
          ciphertext = Buffer.from(JSON.parse(body).ciphertext, 'base64url');
        const update = await candidate(owner, 'one', 2),
          updateOp = id();
        await env.DB.exec(
          `CREATE TRIGGER reject_owner_record_update BEFORE INSERT ON vault_owner_record_mutation WHEN NEW.account_id='failures' BEGIN SELECT RAISE(ABORT,'injected update ledger failure'); END`,
        );
        try {
          assert.equal((await mutate(owner, update, 1, updateOp)).status, 503);
          assert.deepEqual(await head(owner), stored);
          assert.equal(await ledgerCount(owner), 1);
          assert.equal((await mutate(owner, deletion(owner, 2), 1, id(), 'DELETE')).status, 503);
          assert.deepEqual(await head(owner), stored);
        } finally {
          await env.DB.exec('DROP TRIGGER reject_owner_record_update');
        }
        for (const stage of ['get', 'body']) {
          await fault(stage, '', 'throw');
          try {
            const response = await get(owner);
            assert.equal(response.status, 503);
            // Consume the body before another harness RPC can trigger GC of
            // Miniflare's original undici Response and cancel its shared stream.
            assert.deepEqual(await response.json(), { error: 'storage_unavailable' });
            assert.equal(await hits(), 1);
          } finally {
            await fault();
          }
        }
        await env.VAULT_BLOBS.delete(stored.object_key);
        assert.equal((await get(owner)).status, 503);
        const changed = Buffer.from(ciphertext);
        changed[changed.length - 1]! ^= 1;
        for (const corrupt of [
          changed,
          Buffer.alloc(28, 2),
          Buffer.alloc(OWNER_RECORD_MAX_BYTES + 1, 2),
        ]) {
          await env.VAULT_BLOBS.put(stored.object_key, corrupt);
          const response = await get(owner);
          assert.equal(response.status, 503);
          assert.deepEqual(await response.json(), { error: 'storage_unavailable' });
        }
        await env.VAULT_BLOBS.put(stored.object_key, ciphertext);
        assert.equal((await decrypt(owner)).value.revision, 1);
        // The server validates opaque envelope structure; authentication remains
        // the owner's job and must fail for an otherwise well-formed swapped wrap.
        const alternate = JSON.parse(await candidate(owner));
        await env.DB.prepare('UPDATE vault_owner_record_head SET key_envelope=? WHERE account_id=?')
          .bind(alternate.key_envelope, owner.account)
          .run();
        await assert.rejects(decrypt(owner));
        await env.DB.prepare('UPDATE vault_owner_record_head SET key_envelope=? WHERE account_id=?')
          .bind(stored.key_envelope, owner.account)
          .run();
        assert.equal((await decrypt(owner)).value.revision, 1);
        assert.equal((await mutate(owner, update, 1, updateOp)).status, 200);
      },
    );

    // Each case owns its account, so one revoked authority cannot mask another.
    const changes = [
      [
        'session-revoked',
        (owner: Owner) => `UPDATE sso_session SET revoked=1 WHERE sso_id='${owner.session}'`,
      ],
      [
        'session-expired',
        (owner: Owner) =>
          `UPDATE sso_session SET expires_at=unixepoch()-1 WHERE sso_id='${owner.session}'`,
      ],
      [
        'credential-inactive',
        (owner: Owner) =>
          `UPDATE credential SET active=0 WHERE credential_id='${owner.credential}'`,
      ],
      [
        'account-inactive',
        (owner: Owner) =>
          `UPDATE account_security SET active=0 WHERE account_id='${owner.account}'`,
      ],
      [
        'epoch-changed',
        (owner: Owner) =>
          `UPDATE account_security SET epoch=epoch+1 WHERE account_id='${owner.account}'`,
      ],
      [
        'wrapper-removed',
        (owner: Owner) => `DELETE FROM vault_owner_key_wrap WHERE account_id='${owner.account}'`,
      ],
      [
        'registry-revision',
        (owner: Owner) =>
          `UPDATE vault_owner_key_head SET revision=revision+1 WHERE account_id='${owner.account}'`,
      ],
      [
        'registry-origin',
        (owner: Owner) =>
          `UPDATE vault_owner_key_head SET origin='https://other.test' WHERE account_id='${owner.account}'`,
      ],
      [
        'registry-suite',
        (owner: Owner) =>
          `UPDATE vault_owner_key_head SET suite='unknown-suite' WHERE account_id='${owner.account}'`,
      ],
      [
        'registry-generation',
        (owner: Owner) =>
          `DELETE FROM vault_owner_key_wrap WHERE account_id='${owner.account}'; UPDATE vault_owner_key_head SET key_generation=2 WHERE account_id='${owner.account}'; INSERT INTO vault_owner_key_wrap VALUES('${owner.account}',2,'${owner.credential}','${JSON.stringify(owner.envelope)}')`,
      ],
    ] as const;
    for (const stage of ['put', 'get', 'body']) {
      for (const [name, statement] of changes) {
        await t.test(
          `live ${name} during R2 ${stage} prevents publication or disclosure`,
          async () => {
            const owner = await bootstrap(`${stage}-${name}`);
            assert.equal((await mutate(owner, await candidate(owner))).status, 200);
            const before = await head(owner),
              beforeLedger = await ledgerCount(owner);
            const update = await candidate(owner, 'one', 2);
            await fault(stage, statement(owner));
            try {
              const response = stage === 'put' ? await mutate(owner, update, 1) : await get(owner);
              assert.equal(response.status, 409, await response.clone().text());
              assert.equal(await hits(), 1, 'the test fault must actually run');
              const result = (await response.json()) as Record<string, unknown>;
              assert.equal('ciphertext' in result, false);
              assert.equal('key_envelope' in result, false);
              assert.deepEqual(await head(owner), before);
              assert.equal(await ledgerCount(owner), beforeLedger);
            } finally {
              await fault();
            }
          },
        );
      }
    }

    await t.test(
      'a concurrent record-head change after R2 body completion cannot disclose the stale selected ciphertext',
      async () => {
        const owner = await bootstrap('body-head-race');
        assert.equal((await mutate(owner, await candidate(owner))).status, 200);
        await fault(
          'body',
          `UPDATE vault_owner_record_head SET revision=2,deleted=1,object_key=NULL,ciphertext_sha256=NULL,key_envelope=NULL WHERE account_id='${owner.account}'`,
        );
        try {
          const response = await get(owner);
          assert.equal(response.status, 409);
          assert.deepEqual(await response.json(), { error: 'record_changed' });
          assert.equal(await hits(), 1);
        } finally {
          await fault();
        }
        assert.equal((await get(owner)).status, 404);
      },
    );

    await t.test(
      'bounded listing returns only metadata, stable cursors and tombstones within one owner/collection',
      async () => {
        const owner = await bootstrap('listing'),
          other = await bootstrap('listing-other');
        for (const record of ['d', 'b', 'c', 'a'])
          assert.equal(
            (
              await mutate(
                owner,
                await candidate(owner, record),
                0,
                id(),
                'PUT',
                'messages',
                record,
              )
            ).status,
            200,
          );
        assert.equal(
          (await mutate(owner, deletion(owner, 2), 1, id(), 'DELETE', 'messages', 'b')).status,
          200,
        );
        assert.equal(
          (
            await mutate(
              owner,
              await candidate(owner, 'hidden', 1, bytes('hidden'), 'other'),
              0,
              id(),
              'PUT',
              'other',
              'hidden',
            )
          ).status,
          200,
        );
        const firstResponse = await list(owner, '?limit=2');
        assert.equal(firstResponse.status, 200, await firstResponse.clone().text());
        assert.equal(firstResponse.headers.get('cache-control'), 'no-store');
        const first = (await firstResponse.json()) as ListResponse;
        assert.deepEqual(
          Object.keys(first).sort(),
          [
            'collection_id',
            'format_version',
            'key_generation',
            'next_cursor',
            'origin',
            'owner_id',
            'owner_key_revision',
            'records',
            'vault_id',
          ].sort(),
        );
        assert.deepEqual(
          [
            first.owner_id,
            first.origin,
            first.vault_id,
            first.key_generation,
            first.owner_key_revision,
            first.collection_id,
          ],
          [owner.account, origin, 'vault', 1, 1, 'messages'],
        );
        assert.equal(first.format_version, 2);
        assert.deepEqual(first.records, [
          { record_id: 'a', kind: 'message', revision: 1, key_generation: 1, deleted: false },
          { record_id: 'b', kind: 'message', revision: 2, key_generation: 1, deleted: true },
        ]);
        assert.equal(first.next_cursor, 'b');
        const second = (await (
          await list(owner, `?limit=2&after=${first.next_cursor}`)
        ).json()) as ListResponse;
        assert.deepEqual(
          second.records.map((row) => row.record_id),
          ['c', 'd'],
        );
        assert.equal(second.next_cursor, null);
        const all = (await (await list(owner)).json()) as ListResponse;
        assert.equal(all.records.length, 4);
        assert.equal(all.next_cursor, null);
        const empty = (await (await list(other)).json()) as ListResponse;
        assert.deepEqual(empty.records, []);
        assert.equal(empty.next_cursor, null);
        for (const query of [
          '?limit=0',
          '?limit=51',
          '?limit=01',
          '?limit=-1',
          '?limit=1.5',
          '?limit=1&limit=2',
          '?after=',
          '?after=bad%20id',
          '?after=a&after=b',
          '?unknown=x',
        ])
          assert.equal((await list(owner, query)).status, 400, query);
        assert.equal(
          ((await (await list(owner, '?after=z')).json()) as ListResponse).records.length,
          0,
        );
        // Exercise the default 50 boundary without making this read-only list test
        // depend on write-rate timing. All seeded entries are legitimate tombstones.
        await env.DB.batch(
          Array.from({ length: 51 }, (_, i) =>
            env.DB.prepare(
              `INSERT INTO vault_owner_record_head VALUES(?,?,?,?,'message',1,1,2,NULL,NULL,NULL,1,unixepoch())`,
            ).bind(owner.account, 'vault', 'large', `r${String(i).padStart(3, '0')}`),
          ),
        );
        const bounded = (await (await list(owner, '', 'large')).json()) as ListResponse;
        assert.equal(bounded.records.length, 50);
        assert.equal(bounded.next_cursor, 'r049');
        assert.ok(bounded.records.every((row) => row.deleted));
        const last = (await (await list(owner, '?after=r049', 'large')).json()) as ListResponse;
        assert.deepEqual(
          last.records.map((row) => row.record_id),
          ['r050'],
        );
        assert.equal(last.next_cursor, null);
      },
    );

    await t.test(
      'final receipt lookup rechecks live authority after both committed and historical results',
      async () => {
        for (const historical of [false, true]) {
          const owner = await bootstrap(`receipt-${historical}`);
          const body = await candidate(owner),
            operation = id();
          if (historical) assert.equal((await mutate(owner, body, 0, operation)).status, 200);
          await fault(
            'receipt',
            `UPDATE sso_session SET revoked=1 WHERE sso_id='${owner.session}'`,
          );
          try {
            const response = await mutate(owner, body, 0, operation);
            assert.equal(response.status, 409, await response.clone().text());
            assert.equal(await hits(), 1);
            assert.deepEqual(await response.json(), { error: 'owner_key_changed' });
            assert.equal((await head(owner)).revision, 1);
            assert.equal(await ledgerCount(owner), 1);
          } finally {
            await fault();
          }
        }
      },
    );

    await t.test(
      'matching concurrent operations reconcile at the last rate slot and last record slot',
      async () => {
        for (const boundary of ['rate', 'slots']) {
          const owner = await bootstrap(`boundary-${boundary}`);
          if (boundary === 'rate')
            await env.DB.batch(
              Array.from({ length: 19 }, () =>
                env.DB.prepare(
                  'INSERT INTO vault_owner_record_mutation VALUES(?,?,?,1,0,unixepoch())',
                ).bind(owner.account, id(), id()),
              ),
            );
          else
            await env.DB.batch(
              Array.from({ length: 255 }, (_, i) =>
                env.DB.prepare(
                  `INSERT INTO vault_owner_record_head VALUES(?,?,'filled',?,'message',1,1,2,NULL,NULL,NULL,1,unixepoch())`,
                ).bind(owner.account, 'vault', `slot-${i}`),
              ),
            );
          const body = await candidate(owner),
            operation = id();
          // A second real, identical HTTP request commits while the first request
          // is awaiting its optimistic quota read, deterministically consuming the
          // final capacity. Both callers must observe that same durable result.
          await fault('limits');
          try {
            const response = await mutate(owner, body, 0, operation);
            assert.equal(response.status, 200, await response.clone().text());
            assert.deepEqual(await response.json(), { revision: 1, deleted: false });
            assert.equal(await hits(), 1);
            assert.equal((await head(owner)).revision, 1);
            assert.equal(await ledgerCount(owner), boundary === 'rate' ? 20 : 1);
          } finally {
            await fault();
          }
        }
      },
    );

    await t.test(
      'an exact concurrent DELETE reconciles when the current-head await first observes its tombstone',
      async () => {
        const owner = await bootstrap('delete-head-race');
        assert.equal((await mutate(owner, await candidate(owner))).status, 200);
        await fault('head');
        try {
          const response = await mutate(owner, deletion(owner, 2), 1, id(), 'DELETE');
          assert.equal(response.status, 200, await response.clone().text());
          assert.deepEqual(await response.json(), { revision: 2, deleted: true });
          assert.equal(await hits(), 1);
          assert.equal(await ledgerCount(owner), 2);
        } finally {
          await fault();
        }
      },
    );

    await t.test(
      'an upload that outlives the five-minute database admission window cannot commit',
      async () => {
        const owner = await bootstrap('admission-timeout');
        const body = await candidate(owner),
          operation = id();
        const objects = (await env.VAULT_BLOBS.list()).objects.length;
        // Move only the database-observed admission timestamp into the past. The
        // real commit SQL must enforce its deadline; no request body supplies it.
        await fault('admission');
        try {
          const response = await mutate(owner, body, 0, operation);
          assert.equal(response.status, 409, await response.clone().text());
          assert.ok((await hits()) >= 1);
          assert.equal(await head(owner), null);
          assert.equal(await ledgerCount(owner), 0);
          assert.equal((await env.VAULT_BLOBS.list()).objects.length, objects + 1);
        } finally {
          await fault();
        }
        assert.equal((await mutate(owner, body, 0, operation)).status, 200);
      },
    );

    await t.test(
      'HTTP write-rate exhaustion rejects a new operation but preserves exact acknowledgments',
      async () => {
        const owner = await bootstrap('rate-limit');
        const body = await candidate(owner),
          operation = id();
        assert.equal((await mutate(owner, body, 0, operation)).status, 200);
        await env.DB.batch(
          Array.from({ length: 19 }, () =>
            env.DB.prepare(
              'INSERT INTO vault_owner_record_mutation VALUES(?,?,?,1,0,unixepoch())',
            ).bind(owner.account, id(), id()),
          ),
        );
        const before = await head(owner),
          objects = (await env.VAULT_BLOBS.list()).objects.length;
        const response = await mutate(owner, await candidate(owner, 'one', 2), 1);
        assert.equal(response.status, 429);
        assert.deepEqual(await response.json(), { error: 'write_rate_exceeded' });
        assert.equal((await mutate(owner, body, 0, operation)).status, 200);
        assert.deepEqual(await head(owner), before);
        assert.equal(await ledgerCount(owner), 20);
        assert.equal((await env.VAULT_BLOBS.list()).objects.length, objects);
      },
    );

    await t.test(
      'v2 GC retains young/current objects, removes old v2 orphans and expired ledger rows',
      async () => {
        const owner = await bootstrap('garbage-collection');
        assert.equal((await mutate(owner, await candidate(owner))).status, 200);
        const oldHead = await head(owner);
        assert.equal((await mutate(owner, await candidate(owner, 'one', 2), 1)).status, 200);
        const current = await head(owner);
        const orphan = `vault-owner-record/${id()}`;
        await env.VAULT_BLOBS.put(orphan, 'v2 orphan');
        const expiredOperation = id(),
          activeOperation = id();
        await env.DB.batch([
          env.DB.prepare(
            'INSERT INTO vault_owner_record_mutation VALUES(?,?,?,1,0,unixepoch()-7776001)',
          ).bind(owner.account, expiredOperation, id()),
          env.DB.prepare(
            'INSERT INTO vault_owner_record_mutation VALUES(?,?,?,1,0,unixepoch())',
          ).bind(owner.account, activeOperation, id()),
        ]);
        await worker.scheduled({ cron: '* * * * *', scheduledTime: new Date() });
        assert.ok(await env.VAULT_BLOBS.get(orphan), 'young orphan is retained');
        assert.ok(failedLedgerObject);
        assert.ok(
          await env.VAULT_BLOBS.get(failedLedgerObject),
          'young failed-commit upload is retained',
        );
        assert.ok(
          await env.VAULT_BLOBS.get(oldHead.object_key),
          'young superseded ciphertext is retained',
        );
        assert.ok(await env.VAULT_BLOBS.get(current.object_key));
        assert.equal(
          await env.DB.prepare(
            'SELECT 1 FROM vault_owner_record_mutation WHERE account_id=? AND operation_id=?',
          )
            .bind(owner.account, expiredOperation)
            .first(),
          null,
        );
        assert.ok(
          await env.DB.prepare(
            'SELECT 1 FROM vault_owner_record_mutation WHERE account_id=? AND operation_id=?',
          )
            .bind(owner.account, activeOperation)
            .first(),
        );
        await worker.scheduled({
          cron: '*/10 * * * *',
          scheduledTime: new Date(Date.now() + 2 * 86400000),
        });
        assert.equal(await env.VAULT_BLOBS.get(orphan), null);
        assert.equal(
          await env.VAULT_BLOBS.get(failedLedgerObject),
          null,
          'old failed-commit upload is collected',
        );
        assert.equal(await env.VAULT_BLOBS.get(oldHead.object_key), null);
        assert.ok(
          await env.VAULT_BLOBS.get(current.object_key),
          'old referenced ciphertext is retained',
        );
        assert.equal((await decrypt(owner)).value.revision, 2);
        assert.equal(
          (
            await env.DB.prepare(
              'SELECT cursor FROM vault_owner_record_gc_cursor WHERE id=1',
            ).first()
          ).cursor,
          null,
        );
      },
    );
  } finally {
    await harness.close();
    await rm(directory, { recursive: true, force: true });
  }
});
