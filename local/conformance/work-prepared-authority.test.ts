import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { unstable_splitSqlQuery as splitSqlQuery } from 'wrangler';
import { preparationFixture } from './support/work-preparation-fixture.ts';
import { gitFixture } from '../../scripts/work-git-fixture.ts';
import { prepareGitDisclosure } from '../../scripts/work-git-disclosure.ts';
import {
  workPreparationSchema,
  checkWorkDestinations,
  type WorkView,
} from '../../crates/worker/ui/work-view.ts';

async function fixture(throughMigration?: string) {
  const directory = await mkdtemp(join(tmpdir(), 'mikaki-prepared-authority-'));
  const code = await gitFixture(directory, 'code', { 'README.md': 'Synthetic code\n' });
  const context = await gitFixture(directory, 'context', { 'writing.md': 'Synthetic context\n' });
  const selected = await prepareGitDisclosure(
    { repository: 'code', gitDir: code.dir, commit: code.commit },
    [
      {
        repository: 'personal',
        gitDir: context.dir,
        commit: context.commit,
        paths: ['writing.md'],
      },
    ],
    directory,
    'snapshot',
  );
  const f = await preparationFixture(directory);
  try {
    const p = await f.initialize(selected.input, throughMigration);
    const plan = JSON.parse(p.body).data.plan;
    const request = {
      profile: 'mikaki-managed-work-v1',
      request_id: 'prepared-work',
      revision: 1,
      goal: 'Fix the synthetic flow',
      acceptance: 'Review the exact diff',
      code_repository: 'code',
      base_commit: code.commit,
      disclosure_digest: plan.binding.disclosure,
      recipient: 'launcher-client',
      workload: 'managed-agent',
      task_repository: 'synthetic-task',
      adoption_repository: 'field',
      adoption_ref: 'refs/heads/trial',
      expected_head: code.commit,
      operations: ['repo.proposal.submit'],
      deadline: plan.binding.expires_at - 60,
    };
    async function verify(id = p.id, task = 'remote-code', snapshot = 'remote-context') {
      await f.call({ action: 'dispatch-preparation', id });
      return f.call({
        action: 'verify-preparation',
        id,
        preparation_evidence: {
          for_operation: id,
          task_repo_id: task,
          snapshot_repo_id: snapshot,
          payload_receipt: '1'.repeat(64),
          credential_receipt: '2'.repeat(64),
        },
      });
    }
    async function count(table: string) {
      // Only fixed test-internal names, never fixture input.
      return Number(await f.DB.prepare(`SELECT count(*) AS n FROM ${table}`).first('n'));
    }
    let stopped = false;
    async function stop() {
      if (!stopped) {
        await f.close();
        stopped = true;
      }
    }
    return {
      ...f,
      p,
      request,
      verify,
      count,
      directory,
      input: selected.input,
      stop,
      async close() {
        await stop();
        await rm(directory, { recursive: true, force: true });
      },
    };
  } catch (error) {
    await f.close();
    await rm(directory, { recursive: true, force: true });
    throw error;
  }
}
async function sql(name: string) {
  return readFile(new URL(`../../crates/worker/sql/work/${name}.sql`, import.meta.url), 'utf8');
}
async function bindRequest(f: Awaited<ReturnType<typeof fixture>>, body: string) {
  const digest = JSON.parse(body).data.digest;
  const projection = await f.DB.prepare(
    'SELECT projection_revision FROM runtime_policy_active WHERE id=1',
  ).first('projection_revision');
  return f.DB.batch([
    f.DB.prepare(await sql('save-request')).bind(body, projection, f.session),
    f.DB.prepare(await sql('guard')).bind('request-guard'),
    f.DB.prepare(await sql('save-head')).bind(digest),
    f.DB.prepare(await sql('guard')).bind('head-guard'),
    f.DB.prepare(await sql('bind-disclosure')).bind(
      digest,
      f.request.disclosure_digest,
      f.account,
      f.session,
    ),
    f.DB.prepare(await sql('guard')).bind('disclosure-guard'),
    f.DB.prepare(await sql('bind-preparation')).bind(digest, f.p.id),
    f.DB.prepare(await sql('guard')).bind('preparation-guard'),
  ]);
}

test('owner preparation transport scopes status and exact destination commitment to live SSO without private receipts', async () => {
  const f = await fixture();
  const path = `/work/preparations/${f.p.id}`;
  try {
    const get = async () => {
      const r = await f.ownerRead(path);
      assert.equal(r.status, 200, JSON.stringify(r.body));
      assert.equal(r.headers.get('Cache-Control'), 'no-store');
      const p = workPreparationSchema.parse(
        (r.body['record'] as Record<string, unknown>)['preparation'],
      );
      // This uses the browser's independent encoding of the native commitment.
      await checkWorkDestinations({ preparation: p } as WorkView);
      for (const privateField of [
        'body',
        'evidence',
        'payload_receipt',
        'credential_receipt',
        'owner_id',
        'token',
      ])
        assert.equal(JSON.stringify(r.body).includes(privateField), false);
      return p;
    };
    const reserved = await get();
    assert.equal(reserved.state, 'reserved');
    assert.equal(reserved.current_authority, false);
    assert.equal(reserved.destination_digest, null);
    await f.call({ action: 'dispatch-preparation', id: f.p.id });
    assert.equal((await get()).state, 'dispatched');
    await f.verify();
    const verified = await get();
    assert.equal(verified.state, 'verified');
    assert.equal(verified.materialized, false);
    assert.equal(verified.current_authority, false);
    assert.equal(verified.task.repository_id, 'remote-code');
    await assert.rejects(
      checkWorkDestinations({
        preparation: { ...verified, task: { ...verified.task, repository_id: 'substituted-code' } },
      } as WorkView),
    );
    await f.call({ action: 'materialize-preparation', id: f.p.id });
    const active = await get();
    assert.equal(active.current_authority, true);
    const saved = await f.call({ action: 'prepared-request', request: f.request });
    const request = await f.ownerRead(`/work/requests/${saved.digest}`);
    assert.equal(request.status, 200);
    assert.deepEqual((request.body['record'] as Record<string, unknown>)['preparation'], active);
    await f.DB.prepare("UPDATE work_source_head SET active=0 WHERE source_id='personal'").run();
    const fenced = await get();
    assert.equal(fenced.state, 'verified');
    assert.equal(fenced.current_authority, false);
    assert.equal(fenced.destination_digest, active.destination_digest);
    await f.call({ action: 'cleanup-preparation', id: f.p.id });
    const pending = await get();
    assert.equal(pending.state, 'cleanup_pending');
    assert.equal(pending.current_authority, false);
    assert.equal(pending.destination_digest, active.destination_digest);
    await f.call({ action: 'cleaned-preparation', id: f.p.id, receipt: '3'.repeat(64) });
    assert.equal((await get()).state, 'cleaned');
    assert.equal((await f.ownerRead(path, null)).status, 401);
    assert.equal(
      (await f.ownerRead(path, undefined, { headers: { Origin: 'https://foreign.test' } })).status,
      403,
    );
    assert.equal((await f.ownerRead(path, undefined, { method: 'POST' })).status, 404);
    assert.equal((await f.ownerRead(`${path}?owner=foreign`)).status, 400);
    assert.equal((await f.ownerRead('/work/preparations/encoded%252fid')).status, 400);
    const now = Math.floor(Date.now() / 1000),
      cookie = 'foreign-owner-cookie';
    await f.DB.batch([
      f.DB.prepare("INSERT INTO account_security VALUES('foreign',0,1)"),
      f.DB.prepare("INSERT INTO credential VALUES('foreign-credential','foreign',1)"),
      f.DB.prepare(
        "INSERT INTO sso_session VALUES('foreign-sso','foreign','foreign-credential',0,?,0)",
      ).bind(now + 3600),
      f.DB.prepare("INSERT INTO sso_context VALUES('foreign-sso',?,?)").bind(
        createHash('sha256').update(cookie).digest('base64url'),
        now,
      ),
    ]);
    const foreign = await f.ownerRead(path, cookie),
      missing = await f.ownerRead('/work/preparations/missing', cookie);
    assert.equal(foreign.status, 404);
    assert.deepEqual(foreign.body, missing.body);
    await f.DB.prepare(
      "UPDATE credential SET active=0 WHERE credential_id='delivery-credential'",
    ).run();
    assert.equal((await f.ownerRead(path)).status, 401);
  } finally {
    await f.close();
  }
});

test('verified preparation binds immutable destinations and one request thread, with exact retries', async () => {
  const f = await fixture();
  try {
    await f.call({ action: 'prepared-request', request: f.request }, 409);
    await f.call({ action: 'materialize-preparation', id: f.p.id }, 409);
    await f.verify();
    await Promise.all([
      f.call({ action: 'materialize-preparation', id: f.p.id }),
      f.call({ action: 'materialize-preparation', id: f.p.id }),
    ]);
    const mapping = await f.DB.prepare('SELECT * FROM work_prepared_task').first();
    assert.equal(mapping!.preparation_id, f.p.id);
    assert.equal(mapping!.preparation_digest, f.p.digest);
    assert.equal(mapping!.task_repo_id, 'remote-code');
    assert.equal(mapping!.snapshot_repo_id, 'remote-context');
    assert.equal(mapping!.payload_receipt, '1'.repeat(64));
    const saved = await f.call({ action: 'prepared-request', request: f.request });
    const audit = await f.count('work_audit');
    assert.equal(
      (await f.call({ action: 'prepared-request', request: f.request })).digest,
      saved.digest,
    );
    await f.call({ action: 'materialize-preparation', id: f.p.id });
    assert.equal(await f.count('work_audit'), audit);
    await f.call(
      { action: 'prepared-request', request: { ...f.request, request_id: 'different-thread' } },
      409,
    );
    assert.equal(await f.count('work_request'), 1);
    assert.equal(await f.count('work_audit'), audit);
    for (const statement of [
      "UPDATE work_prepared_task SET task_repo_id='substitute'",
      'DELETE FROM work_prepared_task',
      'DELETE FROM work_request_preparation',
      "UPDATE work_task_repository SET recipient='substitute',revision=2",
      "UPDATE work_preparation SET task_namespace='substitute',revision=revision+1",
    ])
      await assert.rejects(f.DB.prepare(statement).run());
    const revised = { ...f.request, revision: 2, goal: 'Review revised work' };
    const outcomes = await Promise.allSettled([
      f.call({ action: 'prepared-request', request: revised }),
      f.call({ action: 'prepared-request', request: { ...revised, goal: 'Competing revision' } }),
    ]);
    assert.equal(outcomes.filter((o) => o.status === 'fulfilled').length, 1);
    assert.equal(await f.count('work_request_preparation'), 2);
  } finally {
    await f.close();
  }
});

test('cleanup revokes production atomically, rejects captured SQL and preserves human adoption', async () => {
  const f = await fixture();
  try {
    await f.verify();
    await f.call({ action: 'materialize-preparation', id: f.p.id });
    const w = await f.call({ action: 'prepared-request', request: f.request });
    await f.call({ action: 'grant', id: 'grant', digest: w.digest });
    await f.call({ action: 'run', grant: 'grant', run: 'run' });
    const g = await f.call({ action: 'grant-body', id: 'captured-grant', digest: w.digest });
    const r = await f.call({ action: 'run-body', grant: 'grant', run: 'captured-run' });
    const c = await f.call({
      action: 'candidate',
      grant: 'grant',
      run: 'run',
      candidate: {
        commit: 'a'.repeat(40),
        tree: 'b'.repeat(40),
        evidence: 'c'.repeat(64),
      },
    });
    await f.DB.prepare('INSERT INTO work_code_target VALUES(?,?,?,?,1,1)')
      .bind('field', 'refs/heads/trial', f.account, f.request.expected_head)
      .run();
    await f.DB.prepare(
      "CREATE TRIGGER fail_cleanup_audit BEFORE INSERT ON work_audit WHEN NEW.action='preparation.cleanup' BEGIN SELECT RAISE(ABORT,'synthetic audit outage'); END",
    ).run();
    const audit = await f.count('work_audit');
    await f.call({ action: 'cleanup-preparation', id: f.p.id }, 500);
    assert.equal((await f.call({ action: 'get-preparation', id: f.p.id })).state, 'verified');
    assert.equal(
      await f.DB.prepare("SELECT revoked FROM work_grant WHERE grant_id='grant'").first('revoked'),
      0,
    );
    assert.equal(await f.count('work_audit'), audit);
    await f.DB.prepare('DROP TRIGGER fail_cleanup_audit').run();
    await f.call({ action: 'cleanup-preparation', id: f.p.id });
    assert.equal(
      await f.DB.prepare("SELECT revoked FROM work_grant WHERE grant_id='grant'").first('revoked'),
      1,
    );
    assert.equal(await f.count('work_live_run'), 0);
    await f.call({ action: 'grant', id: 'late', digest: w.digest }, 409);
    await f.call({ action: 'run', grant: 'grant', run: 'late' }, 409);
    await f.call(
      {
        action: 'candidate',
        grant: 'grant',
        run: 'run',
        candidate: { commit: 'a'.repeat(40), tree: 'b'.repeat(40), evidence: 'c'.repeat(64) },
      },
      409,
    );
    assert.equal(
      (
        await f.DB.prepare(await sql('save-grant'))
          .bind(g.body, f.session, f.request.disclosure_digest)
          .run()
      ).meta.changes,
      0,
    );
    assert.equal(
      (
        await f.DB.prepare(await sql('save-run'))
          .bind(r.body, r.actor_expires_at!, f.request.disclosure_digest)
          .run()
      ).meta.changes,
      0,
    );
    await f.call({ action: 'prepared-request', request: { ...f.request, revision: 2 } }, 409);
    await f.call({ action: 'approve', id: 'fresh-owner-approval', digest: c.digest });
    assert.equal(await f.count('work_adoption_authority'), 1);
    assert.equal(await f.count('work_request_preparation'), 1);
    // Metadata alone cannot establish that adoption's Git payload survived.
    await f.call({ action: 'cleaned-preparation', id: f.p.id, receipt: '3'.repeat(64) }, 409);
    const retainedAudit = await f.count('work_audit');
    await f.call({ action: 'cleanup-preparation', id: f.p.id });
    assert.equal(await f.count('work_audit'), retainedAudit);
    assert.equal(await f.count('work_candidate'), 1);
    assert.equal(await f.count('work_prepared_task'), 1);
    // Actual Worker/D1 restart keeps history and the closed gate.
    await f.stop();
    const restarted = await preparationFixture(f.directory);
    try {
      assert.equal(
        (await restarted.call({ action: 'get-preparation', id: f.p.id })).state,
        'cleanup_pending',
      );
    } finally {
      await restarted.close();
    }
  } finally {
    await f.close();
  }
});

test('materialization repeats source guards and rolls back task, mapping and audit together', async () => {
  const f = await fixture();
  try {
    await f.verify();
    const audit = await f.count('work_audit');
    await f.DB.prepare(
      "CREATE TRIGGER fail_materialize_audit BEFORE INSERT ON work_audit WHEN NEW.action='preparation.materialize' BEGIN SELECT RAISE(ABORT,'synthetic audit outage'); END",
    ).run();
    await f.call({ action: 'materialize-preparation', id: f.p.id }, 500);
    assert.equal(await f.count('work_task_repository'), 0);
    assert.equal(await f.count('work_prepared_task'), 0);
    assert.equal(await f.count('work_audit'), audit);
    await f.DB.prepare('DROP TRIGGER fail_materialize_audit').run();
    await f.DB.prepare(
      "UPDATE work_source_access SET active=0,access_revision=2 WHERE source_id='personal'",
    ).run();
    await assert.rejects(
      f.DB.batch([
        f.DB.prepare(await sql('materialize-task')).bind(f.p.id),
        f.DB.prepare(await sql('guard')).bind('materialize-guard'),
        f.DB.prepare(await sql('materialize-prepared-task')).bind(f.p.id),
      ]),
    );
    await f.call({ action: 'materialize-preparation', id: f.p.id }, 409);
    assert.equal(await f.count('work_task_repository'), 0);
    assert.equal(await f.count('work_audit'), audit);
  } finally {
    await f.close();
  }
});

test('source or task fences stop current native and SQL producer authority', async () => {
  for (const change of ['source', 'task']) {
    const f = await fixture();
    try {
      await f.verify();
      await f.call({ action: 'materialize-preparation', id: f.p.id });
      const w = await f.call({ action: 'prepared-request', request: f.request });
      await f.call({ action: 'grant', id: 'grant', digest: w.digest });
      await f.call({ action: 'run', grant: 'grant', run: 'run' });
      const g = await f.call({ action: 'grant-body', id: 'captured-grant', digest: w.digest });
      const r = await f.call({ action: 'run-body', grant: 'grant', run: 'captured-run' });
      if (change === 'source')
        await f.DB.prepare(
          "UPDATE work_source_access SET active=0,access_revision=2 WHERE source_id='personal'",
        ).run();
      else await f.DB.prepare('UPDATE work_task_repository SET revision=2').run();
      const audit = await f.count('work_audit');
      await f.call({ action: 'grant', id: 'late', digest: w.digest }, 409);
      await f.call({ action: 'run', grant: 'grant', run: 'late' }, 409);
      await f.call({ action: 'prepared-request', request: { ...f.request, revision: 2 } }, 409);
      assert.equal(
        (
          await f.DB.prepare(await sql('save-grant'))
            .bind(g.body, f.session, f.request.disclosure_digest)
            .run()
        ).meta.changes,
        0,
      );
      assert.equal(
        (
          await f.DB.prepare(await sql('save-run'))
            .bind(r.body, r.actor_expires_at!, f.request.disclosure_digest)
            .run()
        ).meta.changes,
        0,
      );
      assert.equal(await f.count('work_live_run'), 0);
      assert.equal(await f.count('work_grant'), 1);
      assert.equal(await f.count('work_run'), 1);
      assert.equal(await f.count('work_audit'), audit);
    } finally {
      await f.close();
    }
  }
});

test('new materialization respects audit budgets while cleanup survives missing creation policy', async () => {
  const f = await fixture();
  try {
    await f.verify();
    const audit = await f.count('work_audit');
    await f.DB.prepare('UPDATE work_resource_policy SET new_audits_per_owner=? WHERE id=1')
      .bind(audit)
      .run();
    await f.call({ action: 'materialize-preparation', id: f.p.id }, 409);
    assert.equal(await f.count('work_task_repository'), 0);
    assert.equal(await f.count('work_prepared_task'), 0);
    assert.equal(await f.count('work_audit'), audit);
    await f.DB.prepare('DELETE FROM work_preparation_policy').run();
    await f.call({ action: 'materialize-preparation', id: f.p.id }, 409);
    assert.equal(
      (await f.call({ action: 'cleanup-preparation', id: f.p.id })).state,
      'cleanup_pending',
    );
    assert.equal(await f.count('work_audit'), audit + 1);
  } finally {
    await f.close();
  }
});

test('captured request plans cannot commit after cleanup, source loss or policy change', async () => {
  for (const change of ['cleanup', 'source', 'policy']) {
    const f = await fixture();
    try {
      await f.verify();
      await f.call({ action: 'materialize-preparation', id: f.p.id });
      const body = await f.call({ action: 'request-body', request: f.request });
      if (change === 'cleanup') await f.call({ action: 'cleanup-preparation', id: f.p.id });
      else if (change === 'source')
        await f.DB.prepare(
          "UPDATE work_source_access SET active=0,access_revision=2 WHERE source_id='personal'",
        ).run();
      else
        await f.DB.prepare(
          'UPDATE runtime_policy_active SET generation=generation+1 WHERE id=1',
        ).run();
      const audit = await f.count('work_audit');
      await assert.rejects(bindRequest(f, body.body));
      for (const table of [
        'work_request',
        'work_request_head',
        'work_request_disclosure',
        'work_request_preparation',
        'work_transition_guard',
      ])
        assert.equal(await f.count(table), 0);
      assert.equal(await f.count('work_audit'), audit);
      await f.call({ action: 'prepared-request', request: f.request }, 409);
    } finally {
      await f.close();
    }
  }
});

test('pre-existing weak rows cannot be silently promoted; missing prepared association cannot issue', async () => {
  const f = await fixture();
  try {
    await f.verify();
    await f.DB.prepare('INSERT INTO work_task_repository VALUES(?,?,1,?,?,?,?,?)')
      .bind(
        'synthetic-task',
        f.account,
        f.request.disclosure_digest,
        'launcher-client',
        'managed-agent',
        'code',
        f.request.base_commit,
      )
      .run();
    await f.call({ action: 'materialize-preparation', id: f.p.id }, 409);
    assert.equal(await f.count('work_prepared_task'), 0);
  } finally {
    await f.close();
  }
  const g = await fixture();
  try {
    await g.verify();
    await g.call({ action: 'materialize-preparation', id: g.p.id });
    const old = await g.call({ action: 'resolved-request', request: g.request });
    await g.call({ action: 'prepared-request', request: g.request }, 409);
    assert.equal(await g.count('work_request_preparation'), 0);
    assert.equal(await g.count('work_live_request'), 0);
    await g.call({ action: 'grant', id: 'unbound', digest: old.digest }, 409);
    // Retained/imported matching bodies must not bypass association checks via
    // the immutable put retry. These direct inserts are test-only legacy facts.
    const grant = await g.call({ action: 'grant-body', id: 'unbound', digest: old.digest });
    const gd = JSON.parse(grant.body).data;
    await g.DB.prepare(
      'INSERT INTO work_grant(grant_id,request_digest,task_revision,expires_at,body) VALUES(?,?,?,?,?)',
    )
      .bind(gd.id, gd.request, gd.task_revision, gd.expires_at, grant.body)
      .run();
    await g.call({ action: 'grant', id: 'unbound', digest: old.digest }, 409);
    const run = await g.call({ action: 'run-body', grant: 'unbound', run: 'unbound-run' });
    const rd = JSON.parse(run.body).data;
    await g.DB.prepare(
      'INSERT INTO work_run(run_id,grant_id,request_digest,expires_at,body) VALUES(?,?,?,?,?)',
    )
      .bind(rd.id, rd.grant, rd.request, rd.expires_at, run.body)
      .run();
    await g.call({ action: 'run', grant: 'unbound', run: 'unbound-run' }, 409);
    await g.call(
      {
        action: 'candidate',
        grant: 'unbound',
        run: 'unbound-run',
        candidate: { commit: 'a'.repeat(40), tree: 'b'.repeat(40), evidence: 'c'.repeat(64) },
      },
      409,
    );
    assert.equal(await g.count('work_live_run'), 0);
    assert.equal(await g.count('work_candidate'), 0);
  } finally {
    await g.close();
  }
});

test('0006 preserves legacy OP/work rows without backfill and rejects remote identity reuse', async () => {
  const f = await fixture('0005');
  try {
    await f.call({ action: 'resolved-request', request: f.request });
    const tables = (
      await f.DB.prepare(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_cf_%' ORDER BY name",
      ).all<{ name: string }>()
    ).results.map((r) => r.name);
    const rows = async (name: string) =>
      (await f.DB.prepare(`SELECT * FROM "${name.replaceAll('"', '""')}"`).all()).results
        .map((r) => JSON.stringify(r))
        .sort();
    const before = await Promise.all(tables.map(rows));
    const migration = await readFile(
      new URL(
        '../../crates/worker/work-migrations/0006_work_prepared_authority.sql',
        import.meta.url,
      ),
      'utf8',
    );
    await f.DB.batch(splitSqlQuery(migration).map((s) => f.DB.prepare(s)));
    for (const [i, name] of tables.entries()) assert.deepEqual(await rows(name), before[i], name);
    assert.equal(await f.count('work_prepared_task'), 0);
    assert.equal(await f.count('work_request_preparation'), 0);
    await f.call({ action: 'prepared-request', request: f.request }, 409);
    await f.verify();
    await f.call({ action: 'materialize-preparation', id: f.p.id });
    const d = await f.call({
      action: 'disclosure',
      disclosure: f.input,
      expires_at: f.request.deadline - 30,
    });
    const p = await f.call({
      action: 'reserve-preparation',
      digest: d.digest,
      task_repository: 'another-task',
      task_namespace: 'mikaki-dev',
      snapshot_namespace: 'mikaki-dev',
    });
    // Swapping roles is also reuse in the same namespace.
    await f.verify(p.id, 'remote-context', 'other-context');
    const audit = await f.count('work_audit');
    await f.call({ action: 'materialize-preparation', id: p.id }, 409);
    assert.equal(await f.count('work_task_repository'), 1);
    assert.equal(await f.count('work_prepared_task'), 1);
    assert.equal(await f.count('work_audit'), audit);
  } finally {
    await f.close();
  }
});
