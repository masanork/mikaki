import { applyWorkMigrations } from './support/work-migrations.ts';
/** Actual product Rust WorkStore through Wasm/workerd + D1. No crypto or Git claims. */
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { readdir } from 'node:fs/promises';
import { DatabaseSync } from 'node:sqlite';
import { test } from 'node:test';
import { createTestHarness } from 'wrangler';
import { activateWorkerPolicy } from '../../scripts/worker-policy-store.ts';

test('Rust managed-work authority on real workerd/D1', async (t) => {
  const root = new URL('../..', import.meta.url).pathname;
  const config = {
    name: 'work-a',
    main: `${root}/local/generated/work-store-main/worker.mjs`,
    compatibility_date: '2026-10-03',
    vars: { LOCAL_WORK_QUALIFICATION: 'true' },
    d1_databases: [
      {
        binding: 'DB',
        database_name: 'work-test',
        database_id: '00000000-0000-0000-0000-000000000047',
        migrations_dir: `${root}/crates/worker/migrations`,
      },
    ],
  };
  const harness = createTestHarness({
    root,
    workers: [
      { config },
      { config: { ...config, name: 'work-b' } },
      {
        config: { ...config, name: 'work-disabled', vars: { LOCAL_WORK_QUALIFICATION: 'false' } },
      },
    ],
  });
  try {
    await harness.listen();
    const a = harness.getWorker('work-a');
    const b = harness.getWorker('work-b');
    await a.applyD1Migrations('DB');
    const { DB } = await a.getEnv();
    await applyWorkMigrations(DB);
    const policy = JSON.parse(
      await readFile(new URL('../generated/worker-policy.json', import.meta.url), 'utf8'),
    );
    await activateWorkerPolicy(DB, policy, { actor: 'work-test', reason: 'local qualification' });
    const clock = () => Math.floor(Date.now() / 1000);
    async function owner(label: string) {
      await DB.batch([
        DB.prepare('INSERT INTO account_security VALUES(?,0,1)').bind(label),
        DB.prepare('INSERT INTO credential VALUES(?,?,1)').bind(`credential-${label}`, label),
        DB.prepare('INSERT INTO sso_session VALUES(?,?,?,0,?,0)').bind(
          `sso-${label}`,
          label,
          `credential-${label}`,
          clock() + 3600,
        ),
        DB.prepare('INSERT INTO sso_context VALUES(?,?,?)').bind(
          `sso-${label}`,
          `session-${label}`,
          clock(),
        ),
      ]);
      return `session-${label}`;
    }
    const session = await owner('owner-a');
    const foreign = await owner('owner-b');
    await t.test(
      'qualification ingress requires its flag and a fixed POST fixture route',
      async () => {
        for (const [target, path, method] of [
          [harness.getWorker('work-disabled'), '/fixture', 'POST'],
          [a, '/fixture', 'GET'],
          [a, '/unknown', 'POST'],
          [a, '/work/requests', 'POST'],
        ] as const) {
          assert.equal((await target.fetch(`https://work.test${path}`, { method })).status, 404);
        }
      },
    );

    async function call(input: Record<string, unknown>, target = a, status = 200): Promise<any> {
      const response = await target.fetch('https://work.test/fixture', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session, ...input }),
      });
      const body = await response.json();
      assert.equal(response.status, status, JSON.stringify({ input, body }));
      return body;
    }
    const denied = (input: Record<string, unknown>, target = a) => call(input, target, 409);
    async function base(label: string) {
      const request = {
        profile: 'mikaki-managed-work-v1',
        request_id: label,
        revision: 1,
        goal: 'Fix the flow',
        acceptance: 'Checks pass',
        code_repository: `source:${label}`,
        base_commit: 'a'.repeat(40),
        disclosure_digest: 'c'.repeat(64),
        recipient: 'launcher-client',
        workload: 'managed-agent',
        task_repository: `task:${label}`,
        adoption_repository: `field:${label}`,
        adoption_ref: 'refs/heads/trial',
        expected_head: 'a'.repeat(40),
        operations: ['repo.proposal.submit'],
        deadline: clock() + 600,
      };
      await DB.batch([
        DB.prepare('INSERT INTO work_task_repository VALUES(?,?,1,?,?,?,?,?)').bind(
          request.task_repository,
          'owner-a',
          request.disclosure_digest,
          request.recipient,
          request.workload,
          request.code_repository,
          request.base_commit,
        ),
        DB.prepare('INSERT INTO work_code_target VALUES(?,?,?,?,1,1)').bind(
          request.adoption_repository,
          request.adoption_ref,
          'owner-a',
          request.expected_head,
        ),
      ]);
      const { digest } = await call({ action: 'request', request });
      const grant = `grant:${label}`;
      const run = `run:${label}`;
      const approval = `approval:${label}`;
      await call({ action: 'grant', id: grant, digest });
      await call({ action: 'run', grant, run });
      const candidate = { commit: 'd'.repeat(40), tree: 'e'.repeat(40), evidence: '6'.repeat(64) };
      const saved = await call({ action: 'candidate', grant, run, candidate });
      await call({ action: 'approve', id: approval, digest: saved.digest });
      return {
        request,
        digest,
        grant,
        run,
        approval,
        candidate,
        candidateDigest: saved.digest,
        id: `operation:${label}`,
      };
    }
    const count = async (table: string, where = '1', values: unknown[] = []) =>
      DB.prepare(`SELECT count(*) AS n FROM ${table} WHERE ${where}`)
        .bind(...values)
        .first('n');

    await t.test('cross-isolate reload, one-time approval and one-winner dispatch', async () => {
      const f = await base('concurrent');
      const prepares = await Promise.all(
        [a, b].map(async (target, index) => {
          const response = await target.fetch('https://work.test/fixture', {
            method: 'POST',
            body: JSON.stringify({
              action: 'prepare',
              id: `${f.id}:${index}`,
              approval: f.approval,
            }),
          });
          return { status: response.status, body: (await response.json()) as any };
        }),
      );
      assert.deepEqual(prepares.map((x) => x.status).sort(), [200, 409]);
      const id = prepares.find((x) => x.status === 200)!.body.id;
      assert.equal(await count('work_code_operation', 'approval_id=?', [f.approval]), 1);
      assert.equal(
        (await call({ action: 'prepare', id, approval: f.approval }, b)).state,
        'prepared',
      );
      const dispatches = await Promise.all(
        [a, b, a, b].map((target) => call({ action: 'dispatch', id }, target)),
      );
      assert.equal(dispatches.filter((x) => x.started).length, 1);
      assert.equal((await call({ action: 'get', id }, b)).state, 'dispatched');
      assert.equal(
        await count('work_audit', "entity_id=? AND action='operation.dispatch'", [id]),
        1,
      );
      assert.equal(await count('work_transition_guard'), 0);
    });

    await t.test(
      'different approvals cannot dispatch the same target; unknown holds the claim',
      async () => {
        const f = await base('target');
        const second = `${f.approval}:2`;
        await call({ action: 'approve', id: second, digest: f.candidateDigest });
        await call({ action: 'prepare', id: f.id, approval: f.approval });
        const other = `${f.id}:2`;
        await call({ action: 'prepare', id: other, approval: second });
        const results = await Promise.all(
          [f.id, other].map(async (id, index) => {
            const target = index ? b : a;
            const r = await target.fetch('https://work.test/fixture', {
              method: 'POST',
              body: JSON.stringify({ action: 'dispatch', id }),
            });
            return { id, status: r.status, body: (await r.json()) as any };
          }),
        );
        assert.deepEqual(results.map((x) => x.status).sort(), [200, 409]);
        const winner = results.find((x) => x.status === 200)!.id;
        const loser = results.find((x) => x.status === 409)!.id;
        await call({ action: 'outcome', id: winner, outcome: 'unknown' });
        assert.equal((await call({ action: 'dispatch', id: winner }, b)).started, false);
        await denied({ action: 'cancel', id: winner });
        await denied({ action: 'dispatch', id: loser });
        assert.equal(await count('work_target_claim', 'operation_id=?', [winner]), 1);
        await call({ action: 'revoke-grant', id: f.grant });
        await call({ action: 'revoke-run', id: f.run });
        const applied = await call(
          { action: 'outcome', id: winner, outcome: 'applied', receipt: 'receipt:target' },
          b,
        );
        assert.equal(applied.state, 'applied');
        assert.deepEqual(
          await call({
            action: 'outcome',
            id: winner,
            outcome: 'applied',
            receipt: 'receipt:target',
          }),
          applied,
        );
        await denied({
          action: 'outcome',
          id: winner,
          outcome: 'rejected',
          receipt: 'receipt:target',
        });
        await denied({
          action: 'outcome',
          id: winner,
          outcome: 'applied',
          receipt: 'receipt:different',
        });
        assert.equal(await count('work_target_claim', 'operation_id=?', [winner]), 0);
        assert.equal(
          await DB.prepare('SELECT writable FROM work_code_target WHERE repository_id=?')
            .bind(f.request.adoption_repository)
            .first('writable'),
          0,
        );
        assert.equal((await call({ action: 'dispatch', id: winner })).started, false);
      },
    );

    await t.test(
      'audit and terminal-fence failures roll back approval consumption, dispatch and outcome',
      async () => {
        const f = await base('rollback');
        await DB.prepare(
          "CREATE TRIGGER fail_work_audit BEFORE INSERT ON work_audit BEGIN SELECT RAISE(ABORT,'injected audit failure'); END",
        ).run();
        await call({ action: 'prepare', id: f.id, approval: f.approval }, a, 500);
        assert.equal(await count('work_code_operation', 'approval_id=?', [f.approval]), 0);
        assert.equal(await count('work_transition_guard'), 0);
        await DB.prepare('DROP TRIGGER fail_work_audit').run();
        await call({ action: 'prepare', id: f.id, approval: f.approval });
        await DB.prepare(
          "CREATE TRIGGER fail_work_audit BEFORE INSERT ON work_audit BEGIN SELECT RAISE(ABORT,'injected audit failure'); END",
        ).run();
        await call({ action: 'dispatch', id: f.id }, a, 500);
        assert.equal((await call({ action: 'get', id: f.id })).state, 'prepared');
        assert.equal(await count('work_target_claim', 'operation_id=?', [f.id]), 0);
        await DB.prepare('DROP TRIGGER fail_work_audit').run();
        assert.equal((await call({ action: 'dispatch', id: f.id })).started, true);
        await DB.prepare(
          "CREATE TRIGGER fail_work_fence BEFORE UPDATE ON work_code_target BEGIN SELECT RAISE(ABORT,'injected fence failure'); END",
        ).run();
        await call(
          { action: 'outcome', id: f.id, outcome: 'applied', receipt: 'receipt:rollback' },
          a,
          500,
        );
        assert.equal((await call({ action: 'get', id: f.id })).state, 'dispatched');
        assert.equal(await count('work_target_claim', 'operation_id=?', [f.id]), 1);
        assert.equal(
          await count('work_audit', "entity_id=? AND action='operation.outcome'", [f.id]),
          0,
        );
        await DB.prepare('DROP TRIGGER fail_work_fence').run();
        assert.equal(
          (
            await call({
              action: 'outcome',
              id: f.id,
              outcome: 'applied',
              receipt: 'receipt:rollback',
            })
          ).state,
          'applied',
        );
      },
    );

    await t.test(
      'revoked producer invalidates old approval; fresh human review adopts retained candidate',
      async () => {
        const f = await base('revoked');
        await call({ action: 'prepare', id: f.id, approval: f.approval });
        await call({ action: 'revoke-grant', id: f.grant }, b);
        await call({ action: 'revoke-run', id: f.run });
        await denied({ action: 'dispatch', id: f.id });
        await denied({ action: 'candidate', grant: f.grant, run: f.run, candidate: f.candidate });
        const fresh = `${f.approval}:fresh`;
        await call({ action: 'approve', id: fresh, digest: f.candidateDigest });
        const id = `${f.id}:fresh`;
        await call({ action: 'prepare', id, approval: fresh }, b);
        assert.equal((await call({ action: 'dispatch', id })).started, true);
        assert.equal(
          await count('work_grant', 'grant_id=? AND revoked=1 AND revision=2', [f.grant]),
          1,
        );
        assert.equal(await count('work_run', 'run_id=? AND revoked=1 AND revision=2', [f.run]), 1);
        assert.equal(
          await count('work_audit', "entity_id=? AND action='grant.revoked'", [f.grant]),
          1,
        );
      },
    );

    await t.test('edited request and task mapping revoke old grants atomically', async () => {
      const f = await base('edited');
      const edited = { ...f.request, revision: 2, goal: 'Changed goal' };
      await DB.prepare(
        "CREATE TRIGGER fail_work_audit BEFORE INSERT ON work_audit BEGIN SELECT RAISE(ABORT,'injected audit failure'); END",
      ).run();
      await call({ action: 'request', request: edited }, a, 500);
      assert.equal(await count('work_grant', 'grant_id=? AND revoked=0', [f.grant]), 1);
      assert.equal(await count('work_request', 'request_id=?', [f.request.request_id]), 1);
      await DB.prepare('DROP TRIGGER fail_work_audit').run();
      await call({ action: 'request', request: edited });
      assert.equal(await count('work_grant', 'grant_id=? AND revoked=1', [f.grant]), 1);
      await denied({ action: 'candidate', grant: f.grant, run: f.run, candidate: f.candidate });
      const task = await base('taskchanged');
      await DB.prepare(
        'UPDATE work_task_repository SET revision=revision+1,disclosure_digest=? WHERE repository_id=?',
      )
        .bind('f'.repeat(64), task.request.task_repository)
        .run();
      assert.equal(await count('work_grant', 'grant_id=? AND revoked=1', [task.grant]), 1);
      await denied({ action: 'prepare', id: task.id, approval: task.approval });
    });

    await t.test('exact target, approval revocation and owner isolation are enforced', async () => {
      const f = await base('stalehead');
      await call({ action: 'prepare', id: f.id, approval: f.approval });
      await DB.prepare(
        'UPDATE work_code_target SET revision=revision+1,head=? WHERE repository_id=?',
      )
        .bind('b'.repeat(40), f.request.adoption_repository)
        .run();
      await denied({ action: 'dispatch', id: f.id });
      const g = await base('approvalstop');
      await denied({ action: 'revoke-grant', id: g.grant, session: foreign });
      await denied({
        action: 'approve',
        id: 'foreign:approval',
        digest: g.candidateDigest,
        session: foreign,
      });
      await call({ action: 'prepare', id: g.id, approval: g.approval });
      await denied({ action: 'cancel', id: g.id, session: foreign });
      await call({ action: 'revoke-approval', id: g.approval });
      await denied({ action: 'dispatch', id: g.id });
      assert.equal((await call({ action: 'cancel', id: g.id })).state, 'cancelled');
      await denied({ action: 'prepare', id: `${g.id}:replacement`, approval: g.approval });
      assert.equal(
        (await call({ action: 'prepare', id: g.id, approval: g.approval })).state,
        'cancelled',
      );
    });

    await t.test(
      'key/client/issuer substitution, expired proof and unsupported actions fail closed',
      async () => {
        const f = await base('identity');
        for (const substitution of [
          { key: '5'.repeat(64) },
          { client: 'other-client' },
          { issuer: 'other-issuer' },
          { issuer_revision: 2 },
          { workload: 'other-agent' },
          { grant: 'other-grant' },
          { expires_at: clock() - 1 },
        ]) {
          await denied({
            action: 'candidate',
            grant: f.grant,
            run: f.run,
            candidate: f.candidate,
            ...substitution,
          });
        }
        await denied({ action: 'mint-token' });
        await denied({
          action: 'request',
          request: { ...f.request, revision: 2, operations: ['repo.change.adopt'] },
        });
        await denied({
          action: 'approve',
          id: 'expired-approval',
          digest: f.candidateDigest,
          expires_at: clock() - 1,
        });
      },
    );

    await t.test(
      'schema rejects immutable record mutation/reactivation and retains referenced tombstones',
      async () => {
        const f = await base('immutable');
        await call({ action: 'revoke-grant', id: f.grant });
        await assert.rejects(
          DB.prepare('UPDATE work_grant SET revoked=0,revision=1 WHERE grant_id=?')
            .bind(f.grant)
            .run(),
          /reactivated/,
        );
        await assert.rejects(
          DB.prepare(
            "UPDATE work_request SET body=json_set(body,'$.data.input.goal','Forged') WHERE digest=?",
          )
            .bind(f.digest)
            .run(),
          /immutable/,
        );
        await assert.rejects(
          DB.prepare('DELETE FROM work_run WHERE run_id=?').bind(f.run).run(),
          /retention/,
        );
        assert.equal(await count('work_transition_guard'), 0);
        assert.equal((await DB.prepare('PRAGMA foreign_key_check').all()).results.length, 0);
      },
    );

    await t.test(
      'primary SQL guards reject a stale read set and an altered projection at the same generation',
      async () => {
        const f = await base('sqlguard');
        await call({ action: 'prepare', id: f.id, approval: f.approval });
        const row = (await DB.prepare(
          'SELECT body,revision FROM work_code_operation WHERE operation_id=?',
        )
          .bind(f.id)
          .first()) as { body: string; revision: number };
        await call({ action: 'revoke-grant', id: f.grant });
        const sql = async (name: string) =>
          readFile(new URL(`../../crates/worker/sql/work/${name}.sql`, import.meta.url), 'utf8');
        await assert.rejects(
          DB.batch([
            DB.prepare(await sql('claim-target')).bind(f.id, row.revision, row.body),
            DB.prepare(await sql('guard')).bind('stale-sql-guard'),
            DB.prepare(await sql('dispatch')).bind(f.id, row.revision, row.body),
            DB.prepare(await sql('guard')).bind('stale-dispatch-guard'),
          ]),
          /work_guard_passed/,
        );
        assert.equal((await call({ action: 'get', id: f.id })).state, 'prepared');
        assert.equal(await count('work_target_claim', 'operation_id=?', [f.id]), 0);
        assert.equal(await count('work_transition_guard'), 0);
        const p = await base('projection');
        await call({ action: 'prepare', id: p.id, approval: p.approval });
        const prior = (await DB.prepare(
          'SELECT projection_revision FROM runtime_policy_active WHERE id=1',
        ).first('projection_revision')) as string;
        await DB.prepare(
          'INSERT INTO runtime_policy_version SELECT ?,policy_revision,projection_json,created_at FROM runtime_policy_version WHERE projection_revision=?',
        )
          .bind('f'.repeat(64), prior)
          .run();
        await DB.prepare('UPDATE runtime_policy_active SET projection_revision=? WHERE id=1')
          .bind('f'.repeat(64))
          .run();
        assert.equal(
          (await denied({ action: 'dispatch', id: p.id })).error,
          'work_denied:StaleAuthority',
        );
        await DB.prepare(
          'UPDATE runtime_policy_active SET projection_revision=?,generation=generation+1 WHERE id=1',
        )
          .bind(prior)
          .run();
      },
    );

    await t.test('cancellation retries converge and never release consumed approval', async () => {
      const f = await base('cancel');
      await call({ action: 'prepare', id: f.id, approval: f.approval });
      const results = await Promise.all(
        [a, b, a, b].map((target) => call({ action: 'cancel', id: f.id }, target)),
      );
      assert.ok(results.every((x) => x.state === 'cancelled'));
      assert.equal(
        await count('work_audit', "entity_id=? AND action='operation.cancel'", [f.id]),
        1,
      );
      await denied({ action: 'prepare', id: `${f.id}:new`, approval: f.approval });
      assert.equal((await call({ action: 'dispatch', id: f.id })).started, false);
    });

    await t.test(
      'account epoch and policy generation stop new dispatch but cannot erase an external outcome',
      async () => {
        const f = await base('epoch');
        await call({ action: 'prepare', id: f.id, approval: f.approval });
        await DB.prepare(
          "UPDATE account_security SET epoch=epoch+1 WHERE account_id='owner-a'",
        ).run();
        await denied({ action: 'dispatch', id: f.id });
        await denied({ action: 'request', request: { ...f.request, revision: 2 } });
        await DB.prepare("UPDATE sso_session SET epoch=1 WHERE account_id='owner-a'").run();
        const p = await base('policy');
        await call({ action: 'prepare', id: p.id, approval: p.approval });
        const inFlight = await base('inflight');
        await call({ action: 'prepare', id: inFlight.id, approval: inFlight.approval });
        await call({ action: 'dispatch', id: inFlight.id });
        await DB.prepare(
          'UPDATE runtime_policy_active SET generation=generation+1 WHERE id=1',
        ).run();
        await denied({ action: 'dispatch', id: p.id });
        await DB.prepare("UPDATE account_security SET active=0 WHERE account_id='owner-a'").run();
        assert.equal(
          (
            await call(
              {
                action: 'outcome',
                id: inFlight.id,
                outcome: 'rejected',
                receipt: 'receipt:inflight',
              },
              b,
            )
          ).state,
          'rejected',
        );
      },
    );
    await t.test(
      'enrolled authority refuses new writes when its independent binding is absent',
      async () => {
        const activeSession = await owner('owner-enrolled');
        const request = {
          profile: 'mikaki-managed-work-v1',
          request_id: 'enrolled-request',
          revision: 1,
          goal: 'Check the authority floor',
          acceptance: 'No unfenced write',
          code_repository: 'source:enrolled',
          base_commit: 'a'.repeat(40),
          disclosure_digest: 'c'.repeat(64),
          recipient: 'launcher-client',
          workload: 'managed-agent',
          task_repository: 'task:enrolled',
          adoption_repository: 'field:enrolled',
          adoption_ref: 'refs/heads/trial',
          expected_head: 'a'.repeat(40),
          operations: ['repo.proposal.submit'],
          deadline: clock() + 600,
        };
        await call({ action: 'request', session: activeSession, request });
        const before = await DB.prepare('SELECT * FROM work_request_head WHERE request_id=?')
          .bind(request.request_id)
          .first();
        const auditBefore = await count('work_audit');
        await DB.prepare('INSERT INTO work_authority_checkpoint VALUES(1,?,?,0,?)')
          .bind('work-qualification-authority', 'a'.repeat(64), 'b'.repeat(64))
          .run();
        assert.equal(
          (
            await denied({
              action: 'request',
              session: activeSession,
              request: { ...request, revision: 2 },
            })
          ).error,
          'work_denied:StaleAuthority',
        );
        assert.deepEqual(
          await DB.prepare('SELECT * FROM work_request_head WHERE request_id=?')
            .bind(request.request_id)
            .first(),
          before,
        );
        assert.equal(await count('work_audit'), auditBefore);
        // The enrolled marker is retained; never reset the authority to regain the local exemption.
        assert.equal(await count('work_authority_checkpoint'), 1);
      },
    );
  } finally {
    await harness.close();
  }
});

test('complete opt-in work chain preserves the fresh Owner Vault baseline and every existing schema definition', async () => {
  const directory = new URL('../../crates/worker/migrations/', import.meta.url);
  const names = (await readdir(directory)).filter((x) => x.endsWith('.sql')).sort();
  assert.equal(new Set(names.map((x) => x.slice(0, 4))).size, names.length);
  const db = new DatabaseSync(':memory:');
  try {
    db.exec('PRAGMA foreign_keys=ON');
    for (const name of names) db.exec(await readFile(new URL(name, directory), 'utf8'));
    const now = Math.floor(Date.now() / 1000);
    db.exec(
      "INSERT INTO account_security VALUES('owner',0,1); INSERT INTO credential VALUES('passkey','owner',1)",
    );
    db.prepare("INSERT INTO sso_session VALUES('session','owner','passkey',0,?,0)").run(now + 600);
    db.prepare("INSERT INTO sso_context VALUES('session','hash',?)").run(now);
    db.prepare('INSERT INTO vault_owner_key_head VALUES(?,?,?,?,?,?,?,?,?,?)').run(
      'owner',
      'vault',
      'https://issuer.test',
      1,
      1,
      2,
      'fixture-cipher-suite',
      'a'.repeat(43),
      'b'.repeat(43),
      1,
    );
    db.prepare('INSERT INTO vault_owner_key_wrap VALUES(?,?,?,?)').run(
      'owner',
      1,
      'passkey',
      'existing-ciphertext',
    );
    db.prepare(
      'INSERT INTO enrollment_waitlist(id,email,locale,created_at,confirmation_hash,confirmation_expires_at,confirmation_sent_at) VALUES(?,?,?,?,?,?,?)',
    ).run('c'.repeat(43), 'waiting@example.test', 'ja', now, 'd'.repeat(43), 0, now);
    const tables = [
      'account_security',
      'credential',
      'sso_session',
      'sso_context',
      'vault_owner_key_head',
      'vault_owner_key_wrap',
      'enrollment_waitlist',
      'enrollment_waitlist_policy',
    ];
    const rows = tables.map((table) => db.prepare(`SELECT * FROM ${table}`).all());
    const schema = db
      .prepare("SELECT name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY name")
      .all();
    db.exec('BEGIN IMMEDIATE');
    const workDirectory = new URL('../../crates/worker/work-migrations/', import.meta.url);
    for (const name of (await readdir(workDirectory)).filter((x) => x.endsWith('.sql')).sort())
      db.exec(await readFile(new URL(name, workDirectory), 'utf8'));
    db.exec('COMMIT');
    tables.forEach((table, index) =>
      assert.deepEqual(db.prepare(`SELECT * FROM ${table}`).all(), rows[index]),
    );
    for (const item of schema)
      assert.equal(
        db.prepare('SELECT sql FROM sqlite_master WHERE name=?').get(item.name as string)!.sql,
        item.sql,
      );
    assert.equal(db.prepare('PRAGMA integrity_check').get()!.integrity_check, 'ok');
    assert.deepEqual(db.prepare('PRAGMA foreign_key_check').all(), []);
    assert.equal(db.prepare('SELECT count(*) AS n FROM work_code_operation').get()!.n, 0);
  } finally {
    db.close();
  }
});
