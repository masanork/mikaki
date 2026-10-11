import assert from 'node:assert/strict';
import { cp, mkdtemp, readFile, readdir, realpath, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { build } from 'esbuild';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { unstable_splitSqlQuery as splitSqlQuery } from 'wrangler';
import type { D1Database } from '@cloudflare/workers-types';
import type {
  BootstrapPlan,
  BootstrapInspection,
} from '../../crates/work-checkpoint-worker/bootstrap.ts';
import {
  bootstrapAuthority,
  bootstrapAuthorityJournal,
  inspectBootstrap,
  primaryBootstrapSnapshot,
  primaryBootstrapStore,
  bootstrapOperatorConfig,
  validateIsolatedBootstrapPlan,
  bootstrapRpcData,
} from '../../scripts/work-authority-bootstrap.ts';
import type { BootstrapIO } from '../../scripts/work-authority-bootstrap.ts';
import {
  AUTHORITY_ACCOUNT,
  AUTHORITY_TARGET,
  packetFile,
} from '../../scripts/work-authority-packet.ts';

/** Disposable local identities. They are never provider allocation receipts. */
async function fixture(packetPin: string | null = '1'.repeat(64)) {
  const directory = await realpath(await mkdtemp(join(tmpdir(), 'mikaki-authority-bootstrap-')));
  const migrations = join(directory, 'migrations');
  await cp(new URL('../../crates/worker/migrations/', import.meta.url), migrations, {
    recursive: true,
  });
  for (const name of (
    await readdir(new URL('../../crates/worker/work-migrations/', import.meta.url))
  ).filter((n) => n.endsWith('.sql')))
    await cp(
      new URL(`../../crates/worker/work-migrations/${name}`, import.meta.url),
      join(migrations, name),
    );
  const snapshot = await primaryBootstrapSnapshot(migrations);
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
  const options = {
    ...convertV4MiniflareOptions({
      workers: [
        {
          name: AUTHORITY_TARGET.checkpoint,
          modules: true,
          script: checkpointCode,
          compatibilityDate: '2026-10-10',
          bindings: {
            WORK_AUTHORITY_ID: AUTHORITY_TARGET.authority,
            ...(packetPin ? { WORK_BOOTSTRAP_PACKET_SHA256: packetPin } : {}),
          },
          durableObjects: { CHECKPOINTS: { className: 'WorkCheckpoint', useSQLite: true } },
        },
        {
          name: 'local-bootstrap-operator',
          modules: true,
          // Test-only transport: actual named RPCs run inside a workerd event scope.
          // It is never packaged in the product or operator deployment.
          script: `export default { async fetch(request,env) {
            const path=new URL(request.url).pathname;
            if(path==='/bootstrap-http') return env.CHECKPOINT_BOOTSTRAP.fetch(request);
            if(path==='/service') return env.CHECKPOINT_SERVICE.fetch(new Request('https://private.invalid/checkpoint',request));
            if(request.method!=='POST'||path!=='/rpc') return new Response(null,{status:404});
            const {binding,method,args}=await request.json();
            if(!['CHECKPOINT_BOOTSTRAP','CHECKPOINT_ADMIN'].includes(binding)||
               !['inspect','enroll','bootstrap','begin','commit','freeze','raiseFloor','lookupEffect','enrollAuthority'].includes(method))
              return new Response(null,{status:400});
            let result;
            try {
              result=await env[binding][method](...args);
              return Response.json(result??null);
            } catch {return Response.json({error:'local_rpc_refused'},{status:409});}
            finally {if(result&&typeof result==='object')result[Symbol.dispose]?.();}
          }};`,
          compatibilityDate: '2026-10-10',
          d1Databases: { DB: 'local-bootstrap-d1' },
          serviceBindings: {
            CHECKPOINT_BOOTSTRAP: {
              name: AUTHORITY_TARGET.checkpoint,
              entrypoint: 'WorkCheckpointBootstrap',
            },
            CHECKPOINT_SERVICE: {
              name: AUTHORITY_TARGET.checkpoint,
              entrypoint: 'WorkCheckpointService',
            },
            CHECKPOINT_ADMIN: {
              name: AUTHORITY_TARGET.checkpoint,
              entrypoint: 'WorkCheckpointAdmin',
            },
          },
        },
      ],
    }),
    resourcePersistencePath: join(directory, 'state'),
  };
  let mf = new Miniflare(options);
  const connect = async () => {
    const operator = await mf.getWorker('local-bootstrap-operator');
    const DB = await mf.getD1Database('DB', 'local-bootstrap-operator');
    async function rpc(binding: string, method: string, ...args: unknown[]) {
      const response = await operator.fetch('https://local.invalid/rpc', {
        method: 'POST',
        body: JSON.stringify({ binding, method, args }),
      });
      const value = await response.json();
      if (response.status !== 200) throw new Error('local_rpc_refused');
      return bootstrapRpcData(Promise.resolve(value));
    }
    const rawBootstrap = new Proxy(
      {},
      {
        get:
          (_target, method) =>
          (...args: unknown[]) =>
            rpc('CHECKPOINT_BOOTSTRAP', String(method), ...args),
      },
    );
    const rawAdmin = {
      bootstrap: (i: unknown, floor: number) => rpc('CHECKPOINT_ADMIN', 'bootstrap', i, floor),
      freeze: () => rpc('CHECKPOINT_ADMIN', 'freeze'),
      raiseFloor: (floor: number) => rpc('CHECKPOINT_ADMIN', 'raiseFloor', floor),
    };
    return {
      DB,
      rawBootstrap,
      checkpoint: {
        inspect: () => rpc('CHECKPOINT_BOOTSTRAP', 'inspect'),
        enroll: (p: BootstrapPlan) => rpc('CHECKPOINT_BOOTSTRAP', 'enroll', p),
        fetch: async (_url: string) => await operator.fetch('https://local.invalid/bootstrap-http'),
      },
      service: {
        fetch: (_input: string, init?: Parameters<typeof operator.fetch>[1]) =>
          operator.fetch('https://local.invalid/service', init),
      },
      admin: {
        bootstrap: async (i: unknown, floor: number) => await rawAdmin.bootstrap(i, floor),
        freeze: async () => {
          await rawAdmin.freeze();
        },
        raiseFloor: async (floor: number) => {
          await rawAdmin.raiseFloor(floor);
        },
      },
      primary: primaryBootstrapStore(DB as unknown as D1Database, snapshot),
    };
  };
  try {
    let connection = await connect();
    await connection.DB.prepare(
      'CREATE TABLE d1_migrations(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT UNIQUE NOT NULL,applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)',
    ).run();
    for (const name of snapshot.migrations) {
      const sql = (await packetFile(join(migrations, name))).toString('utf8');
      await connection.DB.batch([
        ...splitSqlQuery(sql).map((s) => connection.DB.prepare(s)),
        connection.DB.prepare('INSERT INTO d1_migrations(name) VALUES(?)').bind(name),
      ]);
    }
    const initialInspection = (await connection.checkpoint.inspect()) as BootstrapInspection;
    const plan: BootstrapPlan = {
      format_version: 1,
      packet_sha256: '1'.repeat(64),
      allocation_sha256: '2'.repeat(64),
      ownership_review_sha256: '3'.repeat(64),
      quiescence_review_sha256: '4'.repeat(64),
      account_id: AUTHORITY_ACCOUNT,
      database_id: '11111111-1111-4111-8111-111111111111',
      checkpoint_namespace_id: '5'.repeat(32),
      checkpoint_object_id: initialInspection.object_id,
      checkpoint_version_id: '22222222-2222-4222-8222-222222222222',
      initial: {
        authority: AUTHORITY_TARGET.authority,
        epoch: '6'.repeat(64),
        sequence: 0,
        tip: '7'.repeat(64),
      },
      release_floor: 1,
    };
    const events: Record<string, unknown>[] = [];
    return {
      directory,
      plan,
      events,
      get DB() {
        return connection.DB;
      },
      get checkpoint() {
        return connection.checkpoint;
      },
      get rawBootstrap() {
        return connection.rawBootstrap;
      },
      get primary() {
        return connection.primary;
      },
      get service() {
        return connection.service;
      },
      get admin() {
        return connection.admin;
      },
      get io(): BootstrapIO {
        return {
          checkpoint: connection.checkpoint,
          primary: connection.primary,
          record: async (e) => {
            events.push(e);
          },
        };
      },
      async restart() {
        await mf.dispose();
        mf = new Miniflare(options);
        connection = await connect();
      },
      async close() {
        await mf.dispose();
        await rm(directory, { recursive: true, force: true });
      },
    };
  } catch (error) {
    await mf.dispose();
    await rm(directory, { recursive: true, force: true });
    throw error;
  }
}

test('bounded primary SQL inserts exactly one marker into the verified initial D1', async () => {
  const f = await fixture();
  try {
    assert.equal((await f.primary.inspect(f.plan)).pristine, true);
    await f.primary.insert(f.plan);
    assert.equal((await f.primary.inspect(f.plan)).initial_only, true);
    await assert.rejects(f.primary.insert(f.plan), /primary_not_admitted/);
  } finally {
    await f.close();
  }
});

test('actual D1/SQLite DO bootstrap agrees at sequence zero and exposes only private operator methods', async () => {
  const f = await fixture();
  try {
    const config = bootstrapOperatorConfig(f.plan);
    assert.equal(config.services[0]!.entrypoint, 'WorkCheckpointBootstrap');
    assert.equal(config.d1_databases[0]!.database_id, f.plan.database_id);
    assert.equal(config.workers_dev, false);
    const journal = join(f.directory, 'bootstrap.jsonl');
    const lastEvent = async () =>
      JSON.parse((await readFile(journal, 'utf8')).trim().split('\n').at(-1)!);
    const io = {
      ...f.io,
      checkpoint: {
        inspect: () => f.checkpoint.inspect(),
        enroll: async (p: BootstrapPlan) => {
          assert.equal((await lastEvent()).event, 'checkpoint-intent');
          assert.equal((await stat(journal)).mode & 0o777, 0o600);
          return f.checkpoint.enroll(p);
        },
      },
      primary: {
        inspect: (p: BootstrapPlan) => f.primary.inspect(p),
        insert: async (p: BootstrapPlan) => {
          assert.equal((await lastEvent()).event, 'primary-intent');
          await f.primary.insert(p);
        },
      },
    };
    const result = await bootstrapAuthorityJournal(f.plan, f.directory, io);
    assert.equal(result.matching_initial, true);
    assert.equal((await lastEvent()).writers_enabled, false);
    assert.deepEqual(result.primary.marker, f.plan.initial);
    assert.equal(await f.DB.prepare('SELECT count(*) AS n FROM account_security').first('n'), 0);
    assert.equal(await f.DB.prepare('SELECT count(*) AS n FROM atomic_guard').first('n'), 0);
    await assert.rejects(bootstrapAuthorityJournal(f.plan, f.directory, f.io), /EEXIST/);
    await assert.rejects(f.checkpoint.enroll(f.plan));
    await assert.rejects(f.admin.bootstrap(f.plan.initial, 1));
    assert.equal(
      (
        await (f.checkpoint as unknown as { fetch(url: string): Promise<Response> }).fetch(
          'https://private.invalid/',
        )
      ).status,
      404,
    );
    for (const method of [
      'bootstrap',
      'begin',
      'commit',
      'freeze',
      'raiseFloor',
      'lookupEffect',
      'enrollAuthority',
    ])
      await assert.rejects(
        async () =>
          await (
            f.rawBootstrap as unknown as Record<string, (...args: unknown[]) => Promise<unknown>>
          )[method]!(),
      );
    assert.equal(
      (
        await f.service.fetch('https://private.invalid/checkpoint', {
          method: 'POST',
          body: JSON.stringify({ action: 'enroll', plan: f.plan }),
        })
      ).status,
      400,
    );
    await f.restart();
    assert.equal((await inspectBootstrap(f.plan, f.io)).matching_initial, true);
    await assert.rejects(f.checkpoint.enroll(f.plan));
  } finally {
    await f.close();
  }
});

test('lost checkpoint reply retains provenance across restart and never dispatches primary SQL or reenrollment', async () => {
  const f = await fixture();
  try {
    let calls = 0;
    const io = {
      ...f.io,
      checkpoint: {
        inspect: () => f.checkpoint.inspect(),
        enroll: async (p: BootstrapPlan) => {
          calls++;
          await f.checkpoint.enroll(p);
          throw new Error('local-lost-reply');
        },
      },
    };
    await assert.rejects(
      bootstrapAuthorityJournal(f.plan, f.directory, io),
      /checkpoint-write-unknown/,
    );
    assert.equal(calls, 1);
    await f.restart();
    const observed = await inspectBootstrap(f.plan, f.io);
    assert.deepEqual(observed.checkpoint.enrollment, f.plan);
    assert.equal(observed.primary.pristine, true);
    assert.equal(observed.matching_initial, false);
    await assert.rejects(bootstrapAuthorityJournal(f.plan, f.directory, io), /EEXIST/);
    await assert.rejects(bootstrapAuthority(f.plan, f.io), /preflight/);
    await assert.rejects(
      f.checkpoint.enroll({ ...f.plan, initial: { ...f.plan.initial, epoch: '8'.repeat(64) } }),
    );
    assert.deepEqual(((await f.checkpoint.inspect()) as BootstrapInspection).enrollment, f.plan);
  } finally {
    await f.close();
  }
});

test('lost primary reply can be inspected as exact matching state without repeating either write', async () => {
  const f = await fixture();
  try {
    let inserts = 0;
    const io = {
      ...f.io,
      primary: {
        inspect: (p: BootstrapPlan) => f.primary.inspect(p),
        insert: async (p: BootstrapPlan) => {
          inserts++;
          await f.primary.insert(p);
          throw new Error('local-lost-reply');
        },
      },
    };
    await assert.rejects(
      bootstrapAuthorityJournal(f.plan, f.directory, io),
      /primary-write-unknown/,
    );
    assert.equal((await inspectBootstrap(f.plan, f.io)).matching_initial, true);
    await f.restart();
    assert.equal((await inspectBootstrap(f.plan, f.io)).matching_initial, true);
    await assert.rejects(bootstrapAuthorityJournal(f.plan, f.directory, io), /EEXIST/);
    await assert.rejects(bootstrapAuthority(f.plan, f.io), /preflight/);
    assert.equal(inserts, 1);
  } finally {
    await f.close();
  }
});

test('absence after an unknown checkpoint call does not reopen its exclusive journal', async () => {
  const f = await fixture();
  try {
    let calls = 0;
    const io = {
      ...f.io,
      checkpoint: {
        inspect: () => f.checkpoint.inspect(),
        enroll: async () => {
          calls++;
          throw new Error('local-unknown-before-write');
        },
      },
    };
    await assert.rejects(
      bootstrapAuthorityJournal(f.plan, f.directory, io),
      /checkpoint-write-unknown/,
    );
    assert.equal((await inspectBootstrap(f.plan, f.io)).checkpoint.state, null);
    await assert.rejects(bootstrapAuthorityJournal(f.plan, f.directory, io), /EEXIST/);
    assert.equal(calls, 1);
    assert.equal((await inspectBootstrap(f.plan, f.io)).primary.marker, null);
  } finally {
    await f.close();
  }
});

test('primary transaction catches seed/schema/ledger changes after preflight and leaves the independent enrollment retained', async () => {
  for (const mutation of [
    'UPDATE bootstrap_state SET closed=1',
    'CREATE TABLE unexpected_authority(id INTEGER PRIMARY KEY)',
    'DELETE FROM d1_migrations WHERE id=14',
    "INSERT INTO account_security VALUES('local-racing-owner',0,1)",
  ]) {
    const f = await fixture();
    try {
      const io = {
        ...f.io,
        primary: {
          inspect: (p: BootstrapPlan) => f.primary.inspect(p),
          insert: async (p: BootstrapPlan) => {
            await f.DB.prepare(mutation).run();
            await f.primary.insert(p);
          },
        },
      };
      await assert.rejects(bootstrapAuthority(f.plan, io), /primary-write-unknown/);
      assert.equal(
        await f.DB.prepare('SELECT count(*) AS n FROM work_authority_checkpoint').first('n'),
        0,
        mutation,
      );
      assert.deepEqual(((await f.checkpoint.inspect()) as BootstrapInspection).enrollment, f.plan);
      await assert.rejects(f.primary.insert(f.plan), /primary_not_admitted/);
    } finally {
      await f.close();
    }
  }
});

test('already populated, partly migrated, or substituted primary targets fail before any independent write', async () => {
  for (const mutation of [
    'UPDATE bootstrap_state SET closed=1',
    'DELETE FROM d1_migrations WHERE id=14',
    'CREATE TABLE unexpected_authority(id INTEGER PRIMARY KEY)',
  ]) {
    const f = await fixture();
    try {
      await f.DB.prepare(mutation).run();
      await assert.rejects(bootstrapAuthority(f.plan, f.io), /preflight/);
      assert.equal(((await f.checkpoint.inspect()) as BootstrapInspection).state, null);
      assert.equal(
        f.events.some((e) => e.event === 'checkpoint-intent'),
        false,
      );
    } finally {
      await f.close();
    }
  }
});

test('legacy initial state is observable but cannot be adopted as packet enrollment', async () => {
  const f = await fixture();
  try {
    await f.admin.bootstrap(f.plan.initial, 1);
    const cp = (await f.checkpoint.inspect()) as BootstrapInspection;
    assert.equal(cp.enrollment, null);
    assert.deepEqual(cp.state!.checkpoint, f.plan.initial);
    await assert.rejects(bootstrapAuthority(f.plan, f.io), /preflight/);
    await assert.rejects(f.checkpoint.enroll(f.plan));
    assert.equal(
      await f.DB.prepare('SELECT count(*) AS n FROM work_authority_checkpoint').first('n'),
      0,
    );
  } finally {
    await f.close();
  }
});

test('frozen or pending initialization never completes; inspection remains available without floor bypass', async () => {
  for (const mutation of ['pending', 'floor', 'freeze-after-primary']) {
    const f = await fixture();
    try {
      const io = { ...f.io };
      if (mutation === 'freeze-after-primary')
        io.primary = {
          inspect: (p) => f.primary.inspect(p),
          insert: async (p) => {
            await f.primary.insert(p);
            await f.admin.freeze();
          },
        };
      else
        io.checkpoint = {
          inspect: () => f.checkpoint.inspect(),
          enroll: async (p) => {
            const ack = await f.checkpoint.enroll(p);
            if (mutation === 'floor') await f.admin.raiseFloor(2);
            else
              assert.equal(
                (
                  await f.service.fetch('https://private.invalid/checkpoint', {
                    method: 'POST',
                    body: JSON.stringify({
                      action: 'begin',
                      release: 1,
                      expected: p.initial,
                      operation: 'local-interleaved-pending',
                    }),
                  })
                ).status,
                200,
              );
            return ack;
          },
        };
      await assert.rejects(bootstrapAuthority(f.plan, io));
      assert.equal((await inspectBootstrap(f.plan, f.io)).matching_initial, false);
      assert.equal(
        f.events.some((e) => e.event === 'complete'),
        false,
      );
    } finally {
      await f.close();
    }
  }
});

test('closed plan, scope/object/pin checks and concurrent one-time admission preserve the original record', async () => {
  const f = await fixture();
  try {
    for (const plan of [
      { ...f.plan, extra: true },
      { ...f.plan, initial: { ...f.plan.initial, sequence: 1 } },
      { ...f.plan, packet_sha256: '8'.repeat(64) },
      { ...f.plan, checkpoint_object_id: '9'.repeat(64) },
      { ...f.plan, initial: { ...f.plan.initial, authority: 'different' } },
    ])
      await assert.rejects(f.checkpoint.enroll(plan as BootstrapPlan));
    assert.equal(((await f.checkpoint.inspect()) as BootstrapInspection).state, null);
    assert.throws(
      () =>
        validateIsolatedBootstrapPlan({
          ...f.plan,
          database_id: 'd0258938-0d27-4110-8aa9-c82e20f3885b',
        }),
      /production_denied/,
    );
    const attempts = await Promise.allSettled([
      f.checkpoint.enroll(f.plan),
      f.checkpoint.enroll(f.plan),
    ]);
    assert.equal(attempts.filter((a) => a.status === 'fulfilled').length, 1);
    assert.deepEqual(((await f.checkpoint.inspect()) as BootstrapInspection).enrollment, f.plan);
  } finally {
    await f.close();
  }
  const unpinned = await fixture(null);
  try {
    await assert.rejects(unpinned.checkpoint.enroll(unpinned.plan));
  } finally {
    await unpinned.close();
  }
});
