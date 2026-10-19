import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { build } from 'esbuild';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { unstable_splitSqlQuery as splitSqlQuery } from 'wrangler';
import { gcPermitHash, settleReviewedAuthGc } from '../../scripts/settle-reviewed-auth-gc.ts';
import type { GcDatabase, GcPermit, GcRecoveryIO } from '../../scripts/settle-reviewed-auth-gc.ts';

async function fixture() {
  const checkpointCode = (
    await build({
      entryPoints: ['crates/work-checkpoint-worker/worker.ts'],
      bundle: true,
      write: false,
      format: 'esm',
      platform: 'browser',
      external: ['cloudflare:workers'],
    })
  ).outputFiles[0]!.text;
  const mf = new Miniflare(
    convertV4MiniflareOptions({
      workers: [
        {
          name: 'checkpoint',
          modules: true,
          script: checkpointCode,
          compatibilityDate: '2026-10-19',
          bindings: { WORK_AUTHORITY_ID: 'local-gc-recovery' },
          durableObjects: { CHECKPOINTS: { className: 'WorkCheckpoint', useSQLite: true } },
        },
        {
          name: 'operator',
          modules: true,
          compatibilityDate: '2026-10-19',
          d1Databases: { DB: 'local-gc-primary' },
          serviceBindings: {
            BOOT: { name: 'checkpoint', entrypoint: 'WorkCheckpointBootstrap' },
            ADMIN: { name: 'checkpoint', entrypoint: 'WorkCheckpointAdmin' },
            SERVICE: { name: 'checkpoint', entrypoint: 'WorkCheckpointService' },
          },
          script: `export default {async fetch(request,env){
            const path=new URL(request.url).pathname;
            if(path==='/inspect') return new Response(await env.BOOT.inspect());
            if(path==='/admin') {
              const {method,args}=await request.json();
              await env.ADMIN[method](...args); return new Response(null,{status:204});
            }
            return env.SERVICE.fetch(new Request('https://private.invalid/checkpoint',request));
          }};`,
        },
      ],
    }),
  );
  try {
    const operator = await mf.getWorker('operator');
    const DB = await mf.getD1Database('DB', 'operator');
    const migration = await readFile(
      new URL(
        '../../crates/worker/work-migrations/0011_work_authority_checkpoint.sql',
        import.meta.url,
      ),
      'utf8',
    );
    await DB.batch(splitSqlQuery(migration).map((sql) => DB.prepare(sql)));
    await DB.batch([
      DB.prepare('CREATE TABLE work_authority_frame(id INTEGER PRIMARY KEY)'),
      DB.prepare(
        'CREATE TABLE work_transition_guard(guard_id TEXT PRIMARY KEY,passed INTEGER NOT NULL CHECK(passed=1))',
      ),
      DB.prepare('CREATE TABLE business_counter(value INTEGER NOT NULL)'),
      DB.prepare('INSERT INTO business_counter VALUES(0)'),
      DB.prepare('INSERT INTO work_authority_checkpoint VALUES(1,?,?,0,?)').bind(
        'local-gc-recovery',
        'a'.repeat(64),
        'b'.repeat(64),
      ),
    ]);
    const initial = {
      authority: 'local-gc-recovery',
      epoch: 'a'.repeat(64),
      sequence: 0,
      tip: 'b'.repeat(64),
    };
    async function admin(method: string, ...args: unknown[]) {
      const r = await operator.fetch('https://local.invalid/admin', {
        method: 'POST',
        body: JSON.stringify({ method, args }),
      });
      assert.equal(r.status, 204);
    }
    async function service(input: unknown) {
      const r = await operator.fetch('https://local.invalid/service', {
        method: 'POST',
        body: JSON.stringify(input),
      });
      assert.equal(r.status, 200);
      return r.json();
    }
    await admin('bootstrap', initial, 1);
    const p = (await service({
      action: 'begin',
      expected: initial,
      operation: 'local-gc',
      release: 1,
    })) as GcPermit;
    const events: Record<string, unknown>[] = [];
    const io: GcRecoveryIO = {
      DB,
      inspect: async () => (await operator.fetch('https://local.invalid/inspect')).text(),
      commit: (permit, observed) => service({ action: 'commit', release: 1, permit, observed }),
      journal: async (event) => {
        events.push(event);
      },
    };
    const inspection = JSON.parse(await io.inspect());
    const review = {
      authority: initial.authority,
      object_id: inspection.object_id,
      permit_sha256: gcPermitHash(p),
      previous_sequence: 0,
    };
    async function originalBatch() {
      return DB.batch([
        DB.prepare(
          'UPDATE work_authority_checkpoint SET sequence=?,tip=? WHERE id=1 AND authority=? AND epoch=? AND sequence=? AND tip=?',
        ).bind(
          p.next.sequence,
          p.next.tip,
          p.previous.authority,
          p.previous.epoch,
          p.previous.sequence,
          p.previous.tip,
        ),
        DB.prepare(
          'INSERT INTO work_transition_guard VALUES(?,CASE WHEN changes()=1 THEN 1 ELSE 0 END)',
        ).bind('original'),
        DB.prepare('UPDATE business_counter SET value=value+1'),
        DB.prepare('DELETE FROM work_transition_guard WHERE guard_id=?').bind('original'),
      ]);
    }
    return { io, review, DB, p, admin, events, originalBatch, close: () => mf.dispose() };
  } catch (error) {
    await mf.dispose();
    throw error;
  }
}

test('read-only plan leaves both stores unchanged; settlement fences a late original batch', async () => {
  const f = await fixture();
  try {
    assert.equal((await settleReviewedAuthGc(f.io, f.review)).status, 'ready');
    assert.equal(
      await f.DB.prepare('SELECT sequence FROM work_authority_checkpoint').first('sequence'),
      0,
    );
    assert.ok(JSON.parse(await f.io.inspect()).state.pending);
    assert.equal(f.events.length, 0);
    assert.equal((await settleReviewedAuthGc(f.io, f.review, true)).status, 'settled');
    await assert.rejects(f.originalBatch());
    assert.equal(await f.DB.prepare('SELECT value FROM business_counter').first('value'), 0);
    const state = JSON.parse(await f.io.inspect()).state;
    assert.equal(state.pending, null);
    assert.deepEqual(state.checkpoint, f.p.next);
    assert.equal(f.events.at(-1)?.phase, 'reviewed-gc-settled');
    assert.equal((await settleReviewedAuthGc(f.io, f.review, true)).status, 'already-settled');
  } finally {
    await f.close();
  }
});

test('an original batch that wins is acknowledged without replaying its business SQL', async () => {
  const f = await fixture();
  try {
    await settleReviewedAuthGc(
      {
        ...f.io,
        journal: async (event) => {
          if (event.phase === 'reviewed-gc-settlement-started') await f.originalBatch();
          await f.io.journal(event);
        },
      },
      f.review,
      true,
    );
    assert.equal(await f.DB.prepare('SELECT value FROM business_counter').first('value'), 1);
  } finally {
    await f.close();
  }
});

test('lost D1 fence response can resume only at the exact next marker', async () => {
  const f = await fixture();
  try {
    const db: GcDatabase = {
      prepare(sql) {
        const wrap = (s: ReturnType<GcDatabase['prepare']>): ReturnType<GcDatabase['prepare']> => ({
          bind: (...values) => wrap(s.bind(...values)),
          first: <T>() => s.first<T>(),
          run: async () => {
            await s.run();
            throw new Error('lost-D1-response');
          },
        });
        return sql.startsWith('UPDATE ') ? wrap(f.io.DB.prepare(sql)) : f.io.DB.prepare(sql);
      },
    };
    await assert.rejects(
      settleReviewedAuthGc({ ...f.io, DB: db }, f.review, true),
      /lost-D1-response/,
    );
    assert.ok(JSON.parse(await f.io.inspect()).state.pending);
    await settleReviewedAuthGc(f.io, f.review, true);
    await assert.rejects(f.originalBatch());
    assert.equal(await f.DB.prepare('SELECT value FROM business_counter').first('value'), 0);
  } finally {
    await f.close();
  }
});

test('lost commit response is idempotent and journal failure prevents mutation', async () => {
  const f = await fixture();
  try {
    await assert.rejects(
      settleReviewedAuthGc(
        {
          ...f.io,
          journal: async () => {
            throw new Error('journal-unavailable');
          },
        },
        f.review,
        true,
      ),
      /journal-unavailable/,
    );
    assert.equal(
      await f.DB.prepare('SELECT sequence FROM work_authority_checkpoint').first('sequence'),
      0,
    );
    await assert.rejects(
      settleReviewedAuthGc(
        {
          ...f.io,
          commit: async (p, c) => {
            await f.io.commit(p, c);
            throw new Error('lost-commit-response');
          },
        },
        f.review,
        true,
      ),
      /lost-commit-response/,
    );
    assert.equal((await settleReviewedAuthGc(f.io, f.review, true)).status, 'already-settled');
  } finally {
    await f.close();
  }
});

for (const refusal of ['permit', 'object', 'primary', 'frozen', 'floor', 'open-frame'] as const) {
  test(`refuses ${refusal} mismatch without advancing the primary`, async () => {
    const f = await fixture();
    try {
      const review = { ...f.review };
      if (refusal === 'permit') review.permit_sha256 = '0'.repeat(64);
      if (refusal === 'object') review.object_id = '0'.repeat(64);
      if (refusal === 'primary')
        await f.DB.prepare('UPDATE work_authority_checkpoint SET sequence=1,tip=?')
          .bind('c'.repeat(64))
          .run();
      if (refusal === 'frozen') await f.admin('freeze');
      if (refusal === 'floor') await f.admin('raiseFloor', 2);
      if (refusal === 'open-frame')
        await f.DB.prepare('INSERT INTO work_authority_frame VALUES(1)').run();
      const before = await f.DB.prepare(
        'SELECT sequence,tip FROM work_authority_checkpoint',
      ).first();
      await assert.rejects(settleReviewedAuthGc(f.io, review, true));
      assert.deepEqual(
        await f.DB.prepare('SELECT sequence,tip FROM work_authority_checkpoint').first(),
        before,
      );
      assert.deepEqual(f.events, []);
      assert.ok(JSON.parse(await f.io.inspect()).state.pending);
    } finally {
      await f.close();
    }
  });
}
