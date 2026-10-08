import { applyWorkMigrations, applySqliteBaseline } from './support/work-migrations.ts';
/** Real Git objects -> native digest -> product D1 binding/admission/retention.
 * OP sessions, task mapping and managed actors remain synthetic qualification facts. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { test } from 'node:test';
import { createTestHarness } from 'wrangler';
import { prepareGitDisclosure } from '../../scripts/work-git-disclosure.ts';
import { gitFixture } from '../../scripts/work-git-fixture.ts';
import { activateWorkerPolicy } from '../../scripts/worker-policy-store.ts';

// Independent wire encoder; JSON key order and text character count are irrelevant.
function digestManifest(d: any) {
  const h = createHash('sha256');
  const n = (value: number) => {
    const b = Buffer.alloc(8);
    b.writeBigUInt64BE(BigInt(value));
    h.update(b);
  };
  const bytes = (b: Buffer) => {
    n(b.length);
    h.update(b);
  };
  const s = (value: string) => bytes(Buffer.from(value));
  const hex = (value: string) => bytes(Buffer.from(value, 'hex'));
  s(d.format_version === 2 ? 'mikaki.work-disclosure.v2' : 'mikaki.work-disclosure.v1');
  s(d.owner);
  n(d.owner_epoch);
  n(d.policy_revision);
  s(d.recipient);
  s(d.workload);
  n(d.expires_at);
  s(d.code.repository);
  s(d.code.commit);
  s(d.code.tree);
  n(d.code.commits);
  hex(d.code.history_digest);
  n(d.code.objects);
  n(d.code.object_bytes);
  n(d.code.head_files);
  n(d.contexts.length);
  for (const c of d.contexts) {
    s(c.repository);
    s(c.commit);
    s(c.tree);
    n(c.files.length);
    for (const f of c.files) {
      s(f.path);
      s(f.snapshot_path);
      s(f.blob);
      s(f.mode);
      n(f.bytes);
      hex(f.sha256);
    }
  }
  s(d.snapshot.repository);
  s(d.snapshot.commit);
  s(d.snapshot.tree);
  n(d.selected_bytes);
  if (d.format_version === 2) {
    n(d.registered_sources.length);
    for (const source of d.registered_sources) {
      s(source.source_id);
      n(source.source_revision);
      n(source.access_revision);
      s(source.role);
    }
    hex(d.policy_projection);
  }
  return h.digest('hex');
}

// Independent preparation encoding: distinct from the disclosure v2 domain.
function digestPreparation(p: any) {
  const h = createHash('sha256');
  const n = (v: number) => {
    const b = Buffer.alloc(8);
    b.writeBigUInt64BE(BigInt(v));
    h.update(b);
  };
  const bytes = (b: Buffer) => {
    n(b.length);
    h.update(b);
  };
  const s = (v: string) => bytes(Buffer.from(v));
  const hex = (v: string) => bytes(Buffer.from(v, 'hex'));
  s('mikaki.work-preparation.v1');
  s(p.operation_id);
  s(p.binding.owner);
  n(p.binding.owner_epoch);
  n(p.binding.policy_revision);
  hex(p.binding.policy_projection);
  hex(p.binding.disclosure);
  n(p.binding.expires_at);
  n(p.binding.reserved_bytes);
  n(p.binding.source_ids.length);
  for (const id of p.binding.source_ids) s(id);
  s(p.binding.snapshot_repository);
  s(p.task_repository);
  s(p.task_namespace);
  s(p.snapshot_namespace);
  s(p.task_name);
  s(p.snapshot_name);
  return h.digest('hex');
}

test('Git disclosure and bounded authority lifecycle on actual Rust/workerd/D1', async (t) => {
  const root = new URL('../..', import.meta.url).pathname;
  const parent = await mkdtemp(join(tmpdir(), 'mikaki-disclosure-d1-'));
  const config = {
    name: 'disclosure-a',
    main: `${root}/local/generated/work-store/worker.mjs`,
    compatibility_date: '2026-10-03',
    vars: { LOCAL_WORK_QUALIFICATION: 'true', WORK_OWNER_API_ENABLED: 'true' },
    d1_databases: [
      {
        binding: 'DB',
        database_name: 'work-disclosure',
        database_id: '00000000-0000-0000-0000-000000000049',
        migrations_dir: `${root}/crates/worker/migrations`,
      },
    ],
  };
  const harness = createTestHarness({
    root,
    workers: [{ config }, { config: { ...config, name: 'disclosure-b' } }],
  });
  try {
    const code = await gitFixture(
      parent,
      'code',
      { 'README.md': 'Public code fixture\n' },
      'Earlier code\n',
    );
    const context = await gitFixture(
      parent,
      'context',
      { 'writing.md': '結論から書く。\n', 'other.md': 'SYNTHETIC_UNSELECTED\n' },
      'SYNTHETIC_HISTORY\n',
    );
    const { input } = await prepareGitDisclosure(
      { repository: 'code', gitDir: code.dir, commit: code.commit },
      [
        {
          repository: 'personal',
          gitDir: context.dir,
          commit: context.commit,
          paths: ['writing.md'],
        },
      ],
      parent,
      'snapshot',
    );
    const project = await gitFixture(
      parent,
      'project',
      { 'plan.md': 'Synthetic project plan\n' },
      'Earlier project plan\n',
    );
    const multi = (
      await prepareGitDisclosure(
        { repository: 'code', gitDir: code.dir, commit: code.commit },
        [
          {
            repository: 'personal',
            gitDir: context.dir,
            commit: context.commit,
            paths: ['writing.md'],
          },
          {
            repository: 'project',
            gitDir: project.dir,
            commit: project.commit,
            paths: ['plan.md'],
          },
        ],
        parent,
        'multi-snapshot',
      )
    ).input;
    await harness.listen();
    const a = harness.getWorker('disclosure-a'),
      b = harness.getWorker('disclosure-b');
    await a.applyD1Migrations('DB');
    const { DB } = await a.getEnv();
    await applyWorkMigrations(DB);
    await activateWorkerPolicy(
      DB,
      JSON.parse(
        await readFile(new URL('../generated/worker-policy.json', import.meta.url), 'utf8'),
      ),
      { actor: 'work-disclosure-test', reason: 'local qualification' },
    );
    const clock = () => Math.floor(Date.now() / 1000),
      expiry = clock() + 900;
    async function registerSource(source: Record<string, unknown>) {
      const response = await a.fetch('https://work.test/fixture', {
        method: 'POST',
        body: JSON.stringify({ action: 'source-body', source }),
      });
      assert.equal(response.status, 200);
      const { body } = (await response.json()) as { body: string };
      await DB.batch([
        DB.prepare('INSERT INTO work_source_version VALUES(?,?,?)').bind(
          source.source_id,
          source.source_revision,
          body,
        ),
        DB.prepare('INSERT INTO work_source_head VALUES(?,?,1)').bind(
          source.source_id,
          source.source_revision,
        ),
      ]);
    }
    await registerSource({
      source_id: 'code',
      source_revision: 1,
      role: 'code',
      label: 'Synthetic code',
      repo_name: 'code-repo',
      commit: input.code.commit,
      tree: input.code.tree,
      files: [],
      code: {
        commits: input.code.commits.length,
        history_digest: createHash('sha256')
          .update(input.code.commits.join('\n') + '\n')
          .digest('hex'),
        objects: input.code.objects,
        object_bytes: input.code.object_bytes,
        head_files: input.code.head_files,
      },
    });
    await registerSource({
      source_id: 'personal',
      source_revision: 1,
      role: 'personal',
      label: 'Synthetic context',
      repo_name: 'personal-repo',
      commit: input.contexts[0]!.commit,
      tree: input.contexts[0]!.tree,
      code: null,
      files: input.contexts[0]!.files.map((f) => ({
        path: f.path,
        blob: f.blob,
        mode: f.mode,
        bytes: Buffer.byteLength(f.content),
        sha256: createHash('sha256').update(f.content).digest('hex'),
      })),
    });
    await registerSource({
      source_id: 'project',
      source_revision: 1,
      role: 'project',
      label: 'Synthetic project',
      repo_name: 'project-repo',
      commit: multi.contexts[1]!.commit,
      tree: multi.contexts[1]!.tree,
      code: null,
      files: multi.contexts[1]!.files.map((f) => ({
        path: f.path,
        blob: f.blob,
        mode: f.mode,
        bytes: Buffer.byteLength(f.content),
        sha256: createHash('sha256').update(f.content).digest('hex'),
      })),
    });
    async function owner(account: string) {
      const cookie = `synthetic-disclosure:${account}`,
        hash = createHash('sha256').update(cookie).digest('base64url');
      await DB.batch([
        DB.prepare('INSERT INTO account_security VALUES(?,0,1)').bind(account),
        DB.prepare('INSERT INTO credential VALUES(?,?,1)').bind(`credential:${account}`, account),
        DB.prepare('INSERT INTO sso_session VALUES(?,?,?,0,?,0)').bind(
          `sso:${account}`,
          account,
          `credential:${account}`,
          clock() + 3600,
        ),
        DB.prepare('INSERT INTO sso_context VALUES(?,?,?)').bind(`sso:${account}`, hash, clock()),
        DB.prepare("INSERT INTO work_source_access VALUES(?,'code',0,1,1)").bind(account),
        DB.prepare("INSERT INTO work_source_access VALUES(?,'personal',0,1,1)").bind(account),
        DB.prepare("INSERT INTO work_source_access VALUES(?,'project',0,1,1)").bind(account),
      ]);
      return { account, cookie, hash };
    }
    type Owner = Awaited<ReturnType<typeof owner>>;
    async function call(
      o: Owner,
      values: Record<string, unknown>,
      status = 200,
      target = a,
    ): Promise<any> {
      const response = await target.fetch('https://work.test/fixture', {
        method: 'POST',
        body: JSON.stringify({ session: o.hash, ...values }),
      });
      const text = await response.text();
      assert.equal(response.status, status, text);
      return response.headers.get('Content-Type')?.includes('application/json')
        ? JSON.parse(text)
        : text;
    }
    const disclosure = (o: Owner, name = 'snapshot', status = 200, target = a) =>
      call(
        o,
        {
          action: 'disclosure',
          disclosure: { ...input, snapshot: { ...input.snapshot, repository: name } },
          expires_at: expiry,
        },
        status,
        target,
      );
    const count = async (table: string, where = '', values: unknown[] = []) =>
      Number(
        await DB.prepare(`SELECT count(*) AS n FROM ${table} ${where}`)
          .bind(...values)
          .first('n'),
      );
    const policy = (await DB.prepare(
      'SELECT * FROM work_resource_policy WHERE id=1',
    ).first()) as Record<string, number>;
    async function resetPolicy() {
      const fields = Object.keys(policy).filter((k) => k !== 'id');
      await DB.prepare(
        `UPDATE work_resource_policy SET ${fields.map((k) => `${k}=?`).join(',')} WHERE id=1`,
      )
        .bind(...fields.map((k) => policy[k]))
        .run();
    }
    const original = await owner('disclosure-owner'),
      foreign = await owner('disclosure-foreign');
    const d = await disclosure(original);
    const record = JSON.parse(d.body),
      manifest = record.data.data;
    function request(label: string, digest = d.digest) {
      return {
        profile: 'mikaki-managed-work-v1',
        request_id: label,
        revision: 1,
        goal: 'Fix the reviewed flow',
        acceptance: 'Review the exact diff',
        code_repository: 'code',
        base_commit: code.commit,
        disclosure_digest: digest,
        recipient: 'launcher-client',
        workload: 'managed-agent',
        task_repository: `task:${label}`,
        adoption_repository: `field:${label}`,
        adoption_ref: 'refs/heads/trial',
        expected_head: code.commit,
        operations: ['repo.proposal.submit'],
        deadline: expiry - 60,
      };
    }
    const r = request('qualified');
    const saved = await call(original, { action: 'resolved-request', request: r });
    const projection = (await DB.prepare(
      'SELECT projection_revision FROM runtime_policy_active WHERE id=1',
    ).first('projection_revision')) as string;
    const saveDisclosureSql = await readFile(
      new URL('../../crates/worker/sql/work/save-disclosure.sql', import.meta.url),
      'utf8',
    );
    const reserveSql = await readFile(
      new URL('../../crates/worker/sql/work/reserve-disclosure-window.sql', import.meta.url),
      'utf8',
    );
    const saveRequestSql = await readFile(
      new URL('../../crates/worker/sql/work/save-request.sql', import.meta.url),
      'utf8',
    );
    const saveHeadSql = await readFile(
      new URL('../../crates/worker/sql/work/save-head.sql', import.meta.url),
      'utf8',
    );
    const bindSql = await readFile(
      new URL('../../crates/worker/sql/work/bind-disclosure.sql', import.meta.url),
      'utf8',
    );
    const auditSql = await readFile(
      new URL('../../crates/worker/sql/work/audit.sql', import.meta.url),
      'utf8',
    );
    const grantSql = await readFile(
      new URL('../../crates/worker/sql/work/save-grant.sql', import.meta.url),
      'utf8',
    );
    const runSql = await readFile(
      new URL('../../crates/worker/sql/work/save-run.sql', import.meta.url),
      'utf8',
    );
    const guardSql = await readFile(
      new URL('../../crates/worker/sql/work/guard.sql', import.meta.url),
      'utf8',
    );
    async function taskFor(o: Owner, r: ReturnType<typeof request>) {
      await DB.prepare('INSERT INTO work_task_repository VALUES(?,?,1,?,?,?,?,?)')
        .bind(
          r.task_repository,
          o.account,
          r.disclosure_digest,
          r.recipient,
          r.workload,
          r.code_repository,
          r.base_commit,
        )
        .run();
    }

    const savePreparationSql = await readFile(
      new URL('../../crates/worker/sql/work/save-preparation.sql', import.meta.url),
      'utf8',
    );
    const reservePreparationSql = await readFile(
      new URL('../../crates/worker/sql/work/reserve-preparation-window.sql', import.meta.url),
      'utf8',
    );
    const transitionPreparationSql = await readFile(
      new URL('../../crates/worker/sql/work/transition-preparation.sql', import.meta.url),
      'utf8',
    );
    const preparationMapping = (o: Owner, digest: string) => ({
      digest,
      task_repository: `task:${o.account}:${digest.slice(0, 8)}`,
      task_namespace: 'qualification-code',
      snapshot_namespace: 'qualification-context',
    });
    const syntheticEvidence = (id: string) => ({
      for_operation: id,
      task_repo_id: `remote-code:${id}`,
      snapshot_repo_id: `remote-snapshot:${id}`,
      payload_receipt: '1'.repeat(64),
      credential_receipt: '2'.repeat(64),
    });

    await t.test(
      'pre-I/O preparation reserves one stable destination across concurrent isolates and lost replies',
      async () => {
        const o = await owner('preparation-race'),
          d = await disclosure(o, 'preparation-race');
        const values = { action: 'reserve-preparation', ...preparationMapping(o, d.digest) };
        const results = await Promise.all([call(o, values, 200, a), call(o, values, 200, b)]);
        assert.equal(results[0].id, results[1].id);
        assert.equal(results[0].body, results[1].body);
        const p = JSON.parse(results[0].body).data;
        assert.equal(digestPreparation(p.plan), p.digest);
        assert.equal(
          p.plan.binding.reserved_bytes,
          input.code.object_bytes + Buffer.byteLength(input.contexts[0]!.files[0]!.content),
        );
        assert.equal(p.plan.binding.disclosure, d.digest);
        assert.equal(p.plan.binding.policy_projection, projection);
        assert.deepEqual(p.plan.binding.source_ids, ['code', 'personal']);
        assert.notEqual(p.plan.task_name, p.plan.snapshot_name);
        assert.equal(await count('work_preparation', 'WHERE owner_id=?', [o.account]), 1);
        assert.equal(
          await DB.prepare('SELECT attempts FROM work_preparation_window WHERE owner_id=?')
            .bind(o.account)
            .first('attempts'),
          1,
        );
        assert.equal(
          await count('work_audit', "WHERE owner_id=? AND action='preparation.reserve'", [
            o.account,
          ]),
          1,
        );
        assert.deepEqual(await call(o, values, 200, b), results[0]);
        await call(o, { ...values, snapshot_namespace: 'substituted-namespace' }, 409);
        const launches = await Promise.all([
          call(o, { action: 'dispatch-preparation', id: results[0].id }, 200, a),
          call(o, { action: 'dispatch-preparation', id: results[0].id }, 200, b),
        ]);
        assert.equal(launches.filter((v) => v.started).length, 1);
        assert.equal(launches[0].preparation.id, launches[1].preparation.id);
        assert.equal((await call(o, values)).state, 'dispatched');
        assert.equal(
          (await call(o, { action: 'dispatch-preparation', id: results[0].id }, 200, b)).started,
          false,
        );
        assert.equal(
          await count('work_audit', "WHERE owner_id=? AND action='preparation.dispatch'", [
            o.account,
          ]),
          1,
        );
        assert.equal(
          await count(
            'work_grant',
            'WHERE request_digest IN(SELECT digest FROM work_request WHERE owner_id=?)',
            [o.account],
          ),
          0,
        );
      },
    );

    await t.test(
      'pre-I/O reservation repeats all selected source and SSO guards and rolls back its hourly window',
      async () => {
        const o = await owner('preparation-source-loss'),
          d = await disclosure(o, 'preparation-source-loss');
        const mapping = preparationMapping(o, d.digest);
        const planned = await call(o, {
          action: 'preparation-body',
          id: 'precommit-loss',
          ...mapping,
        });
        const auditBefore = await count('work_audit', 'WHERE owner_id=?', [o.account]);
        await DB.prepare(
          "UPDATE work_source_access SET active=0,access_revision=2 WHERE owner_id=? AND source_id='personal'",
        )
          .bind(o.account)
          .run();
        await assert.rejects(
          DB.batch([
            DB.prepare(reservePreparationSql).bind(o.account),
            DB.prepare(savePreparationSql).bind(planned.body, o.hash),
          ]),
          /work_source_guard_failed/,
        );
        await call(o, { action: 'reserve-preparation', ...mapping }, 409, b);
        assert.equal(await count('work_preparation', 'WHERE owner_id=?', [o.account]), 0);
        assert.equal(await count('work_preparation_window', 'WHERE owner_id=?', [o.account]), 0);
        assert.equal(await count('work_audit', 'WHERE owner_id=?', [o.account]), auditBefore);
        const fresh = await owner('preparation-session-loss'),
          fd = await disclosure(fresh, 'preparation-session-loss');
        const plan = await call(fresh, {
          action: 'preparation-body',
          id: 'session-loss',
          ...preparationMapping(fresh, fd.digest),
        });
        await DB.prepare('UPDATE sso_session SET revoked=1 WHERE account_id=?')
          .bind(fresh.account)
          .run();
        await assert.rejects(
          DB.batch([
            DB.prepare(reservePreparationSql).bind(fresh.account),
            DB.prepare(savePreparationSql).bind(plan.body, fresh.hash),
            DB.prepare(guardSql).bind('session-preparation-guard'),
          ]),
          /work_guard_passed/,
        );
        assert.equal(
          await count('work_preparation_window', 'WHERE owner_id=?', [fresh.account]),
          0,
        );
        await call(
          fresh,
          { action: 'reserve-preparation', ...preparationMapping(fresh, fd.digest) },
          409,
        );
      },
    );

    await t.test(
      'unknown allocations count toward bytes and retained capacity; safety cleanup survives exhausted or missing policy',
      async () => {
        const o = await owner('preparation-budget'),
          first = await disclosure(o, 'preparation-budget-a'),
          second = await disclosure(o, 'preparation-budget-b');
        const defaults = (await DB.prepare(
          'SELECT * FROM work_preparation_policy WHERE id=1',
        ).first()) as Record<string, number> | null;
        assert.ok(defaults);
        try {
          const bytes =
            JSON.parse(first.body).data.data.code.object_bytes +
            JSON.parse(first.body).data.data.selected_bytes;
          await DB.prepare('UPDATE work_preparation_policy SET bytes_per_owner=? WHERE id=1')
            .bind(bytes)
            .run();
          const p = await call(o, {
            action: 'reserve-preparation',
            ...preparationMapping(o, first.digest),
          });
          await call(o, { action: 'dispatch-preparation', id: p.id });
          await call(
            o,
            { action: 'reserve-preparation', ...preparationMapping(o, second.digest) },
            409,
            b,
          );
          assert.equal(
            await DB.prepare('SELECT attempts FROM work_preparation_window WHERE owner_id=?')
              .bind(o.account)
              .first('attempts'),
            1,
          );
          await DB.prepare('DELETE FROM work_preparation_policy WHERE id=1').run();
          assert.equal(
            (await call(o, { action: 'cleanup-preparation', id: p.id })).state,
            'cleanup_pending',
          );
          assert.equal(
            (await call(o, { action: 'get-preparation', id: p.id })).state,
            'cleanup_pending',
          );
          await call(
            o,
            {
              action: 'verify-preparation',
              id: p.id,
              preparation_evidence: syntheticEvidence(p.id),
            },
            409,
          );
          const cleaned = await call(o, {
            action: 'cleaned-preparation',
            id: p.id,
            receipt: '3'.repeat(64),
          });
          assert.equal(cleaned.state, 'cleaned');
          assert.deepEqual(
            await call(
              o,
              { action: 'cleaned-preparation', id: p.id, receipt: '3'.repeat(64) },
              200,
              b,
            ),
            cleaned,
          );
          await call(o, { action: 'cleaned-preparation', id: p.id, receipt: '4'.repeat(64) }, 409);
          await call(
            o,
            { action: 'reserve-preparation', ...preparationMapping(o, second.digest) },
            409,
          );
          await DB.prepare('INSERT INTO work_preparation_policy VALUES(?,?,?,?,?,?)')
            .bind(...Object.values(defaults))
            .run();
          await DB.prepare(
            'UPDATE work_preparation_policy SET retained_per_owner=1 WHERE id=1',
          ).run();
          await call(
            o,
            { action: 'reserve-preparation', ...preparationMapping(o, second.digest) },
            409,
          );
          assert.equal(await count('work_preparation', 'WHERE owner_id=?', [o.account]), 1); // retained cleaned tombstone still charged
          await assert.rejects(
            DB.prepare('DELETE FROM work_preparation WHERE operation_id=?').bind(p.id).run(),
            /retained preparation intent/,
          );
        } finally {
          await DB.prepare('DELETE FROM work_preparation_policy WHERE id=1').run();
          await DB.prepare('INSERT INTO work_preparation_policy VALUES(?,?,?,?,?,?)')
            .bind(...Object.values(defaults))
            .run();
        }
      },
    );

    await t.test(
      'preparation global byte/row and per-hour ceilings fail without partial reservations',
      async () => {
        const o = await owner('preparation-ceilings'),
          first = await disclosure(o, 'preparation-ceilings-a'),
          second = await disclosure(o, 'preparation-ceilings-b');
        const defaults = (await DB.prepare(
          'SELECT * FROM work_preparation_policy WHERE id=1',
        ).first()) as Record<string, number>;
        const fields = Object.keys(defaults).filter((k) => k !== 'id');
        const reset = () =>
          DB.prepare(
            `UPDATE work_preparation_policy SET ${fields.map((k) => `${k}=?`).join(',')} WHERE id=1`,
          )
            .bind(...fields.map((k) => defaults[k]))
            .run();
        const bytes =
          JSON.parse(first.body).data.data.code.object_bytes +
          JSON.parse(first.body).data.data.selected_bytes;
        try {
          const liabilities = Number(
            await DB.prepare(
              "SELECT coalesce(sum(reserved_bytes),0) AS n FROM work_preparation WHERE state!='cleaned'",
            ).first('n'),
          );
          for (const [field, value] of [
            ['retained_total', await count('work_preparation')],
            ['bytes_total', liabilities + bytes - 1],
          ] as const) {
            await DB.prepare(`UPDATE work_preparation_policy SET ${field}=? WHERE id=1`)
              .bind(value)
              .run();
            await call(
              o,
              { action: 'reserve-preparation', ...preparationMapping(o, first.digest) },
              409,
            );
            assert.equal(
              await count('work_preparation_window', 'WHERE owner_id=?', [o.account]),
              0,
            );
            assert.equal(await count('work_preparation', 'WHERE owner_id=?', [o.account]), 0);
            await reset();
          }
          await DB.prepare(
            'UPDATE work_preparation_policy SET creations_per_hour=1 WHERE id=1',
          ).run();
          await call(o, { action: 'reserve-preparation', ...preparationMapping(o, first.digest) });
          await call(
            o,
            { action: 'reserve-preparation', ...preparationMapping(o, second.digest) },
            409,
          );
          assert.equal(
            await DB.prepare('SELECT attempts FROM work_preparation_window WHERE owner_id=?')
              .bind(o.account)
              .first('attempts'),
            1,
          );
          assert.equal(
            await count('work_audit', "WHERE owner_id=? AND entity_type='preparation'", [
              o.account,
            ]),
            1,
          );
          assert.equal(await count('work_transition_guard'), 0);
        } finally {
          await reset();
        }
      },
    );

    await t.test(
      'verified preparation accepts only exact immutable evidence and never creates workload authority',
      async () => {
        const o = await owner('preparation-verified'),
          d = await disclosure(o, 'preparation-verified');
        const p = await call(o, {
          action: 'reserve-preparation',
          ...preparationMapping(o, d.digest),
        });
        await call(
          o,
          { action: 'verify-preparation', id: p.id, preparation_evidence: syntheticEvidence(p.id) },
          409,
        ); // not dispatched
        await call(o, { action: 'dispatch-preparation', id: p.id });
        const other = await disclosure(o, 'preparation-other');
        await call(
          o,
          {
            action: 'reserve-preparation',
            ...preparationMapping(o, other.digest),
            task_repository: preparationMapping(o, d.digest).task_repository,
          },
          409,
        );
        const q = await call(o, {
          action: 'reserve-preparation',
          ...preparationMapping(o, other.digest),
        });
        await call(
          o,
          { action: 'verify-preparation', id: p.id, preparation_evidence: syntheticEvidence(q.id) },
          409,
        );
        const verified = await call(o, {
          action: 'verify-preparation',
          id: p.id,
          preparation_evidence: syntheticEvidence(p.id),
        });
        assert.equal(verified.state, 'verified');
        assert.deepEqual(
          await call(
            o,
            {
              action: 'verify-preparation',
              id: p.id,
              preparation_evidence: syntheticEvidence(p.id),
            },
            200,
            b,
          ),
          verified,
        );
        await call(
          o,
          {
            action: 'verify-preparation',
            id: p.id,
            preparation_evidence: {
              ...syntheticEvidence(p.id),
              credential_receipt: '5'.repeat(64),
            },
          },
          409,
        );
        assert.equal(await count('work_request', 'WHERE owner_id=?', [o.account]), 0);
        assert.equal(
          await count('work_audit', "WHERE owner_id=? AND action='preparation.verify'", [
            o.account,
          ]),
          1,
        );
        const cancelled = await call(o, { action: 'cleanup-preparation', id: q.id });
        assert.equal(cancelled.state, 'cleaned'); // no dispatch, no external cleanup receipt needed
        assert.equal((await call(o, { action: 'dispatch-preparation', id: q.id })).started, false);
      },
    );

    await t.test(
      'source loss between preparation readback and primary verification refuses success but retains cleanup identity',
      async () => {
        const o = await owner('preparation-readback-race'),
          d = await call(o, { action: 'disclosure', disclosure: multi, expires_at: expiry });
        const p = await call(o, {
          action: 'reserve-preparation',
          ...preparationMapping(o, d.digest),
        });
        await call(o, { action: 'dispatch-preparation', id: p.id });
        await DB.prepare(
          "UPDATE work_source_access SET active=0,access_revision=2 WHERE owner_id=? AND source_id='project'",
        )
          .bind(o.account)
          .run();
        await call(
          o,
          { action: 'verify-preparation', id: p.id, preparation_evidence: syntheticEvidence(p.id) },
          409,
          b,
        );
        assert.equal((await call(o, { action: 'get-preparation', id: p.id })).state, 'dispatched');
        assert.equal((await call(o, { action: 'dispatch-preparation', id: p.id })).started, false);
        await DB.prepare('UPDATE account_security SET active=0,epoch=1 WHERE account_id=?')
          .bind(o.account)
          .run();
        assert.equal(
          (await call(o, { action: 'cleanup-preparation', id: p.id })).state,
          'cleanup_pending',
        );
        assert.equal(
          (await call(o, { action: 'cleaned-preparation', id: p.id, receipt: '3'.repeat(64) }))
            .state,
          'cleaned',
        );
      },
    );

    await t.test(
      'preparation dispatch is atomically fenced after source or policy changes',
      async () => {
        const o = await owner('preparation-dispatch-race'),
          d = await disclosure(o, 'preparation-dispatch-race');
        const p = await call(o, {
          action: 'reserve-preparation',
          ...preparationMapping(o, d.digest),
        });
        await DB.prepare(
          "UPDATE work_source_access SET active=0,access_revision=2 WHERE owner_id=? AND source_id='personal'",
        )
          .bind(o.account)
          .run();
        await assert.rejects(
          DB.batch([
            DB.prepare(transitionPreparationSql).bind(p.id, 1, p.body, 'dispatched', null, null),
          ]),
          /work_source_guard_failed/,
        );
        await call(o, { action: 'dispatch-preparation', id: p.id }, 409, b);
        assert.equal((await call(o, { action: 'get-preparation', id: p.id })).state, 'reserved');
        assert.equal(
          await count('work_audit', "WHERE owner_id=? AND action='preparation.dispatch'", [
            o.account,
          ]),
          0,
        );
        assert.equal((await call(o, { action: 'cleanup-preparation', id: p.id })).state, 'cleaned');
        const po = await owner('preparation-policy-race'),
          pd = await disclosure(po, 'preparation-policy-race');
        const pp = await call(po, {
          action: 'reserve-preparation',
          ...preparationMapping(po, pd.digest),
        });
        await DB.prepare(
          'UPDATE runtime_policy_active SET generation=generation+1 WHERE id=1',
        ).run();
        try {
          await call(po, { action: 'dispatch-preparation', id: pp.id }, 409);
        } finally {
          await DB.prepare(
            'UPDATE runtime_policy_active SET generation=generation-1 WHERE id=1',
          ).run();
        }
        assert.equal((await call(po, { action: 'get-preparation', id: pp.id })).state, 'reserved');
      },
    );

    await t.test(
      'preparation audit failure rolls back reservation and dispatch so neither can authorize external work',
      async () => {
        const o = await owner('preparation-audit'),
          d = await disclosure(o, 'preparation-audit');
        const mapping = preparationMapping(o, d.digest);
        await DB.prepare(
          "CREATE TRIGGER fail_preparation_audit BEFORE INSERT ON work_audit WHEN NEW.entity_type='preparation' BEGIN SELECT RAISE(ABORT,'injected private failure'); END",
        ).run();
        try {
          await call(o, { action: 'reserve-preparation', ...mapping }, 500);
        } finally {
          await DB.prepare('DROP TRIGGER fail_preparation_audit').run();
        }
        assert.equal(await count('work_preparation', 'WHERE owner_id=?', [o.account]), 0);
        assert.equal(await count('work_preparation_window', 'WHERE owner_id=?', [o.account]), 0);
        const p = await call(o, { action: 'reserve-preparation', ...mapping });
        await DB.prepare(
          "CREATE TRIGGER fail_preparation_dispatch_audit BEFORE INSERT ON work_audit WHEN NEW.action='preparation.dispatch' BEGIN SELECT RAISE(ABORT,'injected private failure'); END",
        ).run();
        try {
          await call(o, { action: 'dispatch-preparation', id: p.id }, 500);
        } finally {
          await DB.prepare('DROP TRIGGER fail_preparation_dispatch_audit').run();
        }
        assert.equal((await call(o, { action: 'get-preparation', id: p.id })).state, 'reserved');
        assert.equal(await count('work_transition_guard'), 0);
      },
    );

    await t.test(
      '0005 preserves all earlier records, adds no allocation and retains referenced disclosures',
      async () => {
        const o = await owner('preparation-migration');
        const md = await disclosure(o, 'preparation-migration');
        const planned = await call(o, {
          action: 'preparation-body',
          id: 'migration-preparation',
          ...preparationMapping(o, md.digest),
        });
        const sql = new DatabaseSync(':memory:'),
          directory = new URL('../../crates/worker/work-migrations/', import.meta.url);
        try {
          sql.exec('PRAGMA foreign_keys=ON');
          await applySqliteBaseline(sql);
          for (const name of (await readdir(directory))
            .filter((n) => n.endsWith('.sql') && Number(n.slice(0, 4)) < 5)
            .sort())
            sql.exec(await readFile(new URL(name, directory), 'utf8'));
          for (const table of [
            'runtime_policy_version',
            'runtime_policy_active',
            'account_security',
            'credential',
            'sso_session',
            'sso_context',
            'work_source_version',
            'work_source_head',
            'work_source_access',
            'work_disclosure',
            'work_request',
            'work_request_head',
            'work_request_disclosure',
            'work_audit',
          ]) {
            const filters: Record<string, [string, unknown[]]> = {
              account_security: ['WHERE account_id IN(?,?)', [original.account, o.account]],
              credential: ['WHERE account_id IN(?,?)', [original.account, o.account]],
              sso_session: ['WHERE account_id IN(?,?)', [original.account, o.account]],
              sso_context: [
                'WHERE sso_id IN(?,?)',
                [`sso:${original.account}`, `sso:${o.account}`],
              ],
              work_source_access: ['WHERE owner_id IN(?,?)', [original.account, o.account]],
              work_disclosure: ['WHERE digest IN(?,?)', [d.digest, md.digest]],
              work_request: ['WHERE digest=?', [saved.digest]],
              work_request_head: ['WHERE digest=?', [saved.digest]],
              work_request_disclosure: ['WHERE request_digest=?', [saved.digest]],
              work_audit: ['WHERE owner_id IN(?,?)', [original.account, o.account]],
            };
            const [where, params] = filters[table] ?? ['', []];
            const { results } = await DB.prepare(`SELECT * FROM ${table} ${where}`)
              .bind(...params)
              .all();
            for (const row of results) {
              const keys = Object.keys(row);
              sql
                .prepare(
                  `INSERT INTO ${table}(${keys.join(',')}) VALUES(${keys.map(() => '?').join(',')})`,
                )
                .run(...(keys.map((k) => row[k]) as any[]));
            }
          }
          const tables = (
            sql
              .prepare(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
              )
              .all() as { name: string }[]
          ).map((r) => r.name);
          const before = tables.map((name) => sql.prepare(`SELECT * FROM ${name}`).all());
          sql.exec(await readFile(new URL('0005_work_preparation_intents.sql', directory), 'utf8'));
          assert.deepEqual(
            tables.map((name) => sql.prepare(`SELECT * FROM ${name}`).all()),
            before,
          );
          assert.deepEqual(sql.prepare('PRAGMA foreign_key_check').all(), []);
          assert.equal(sql.prepare('SELECT count(*) AS n FROM work_preparation').get()!.n, 0);
          sql.prepare(savePreparationSql).run(planned.body, o.hash);
          // Advance this isolated SQLite clock past grace without mutating
          // immutable evidence. A pending allocation protects unbound metadata.
          sql.function('unixepoch', () => expiry + 86401);
          assert.throws(
            () => sql.prepare('DELETE FROM work_disclosure WHERE digest=?').run(md.digest),
            /referenced preparation disclosure/,
          );
        } finally {
          sql.close();
        }
        const row = (await DB.prepare(
          'SELECT disclosure_digest FROM work_preparation LIMIT 1',
        ).first()) as { disclosure_digest: string } | null;
        assert.ok(row);
        await assert.rejects(
          DB.prepare('DELETE FROM work_disclosure WHERE digest=?')
            .bind(row.disclosure_digest)
            .run(),
        );
      },
    );

    await t.test(
      'independent digest, exact UTF-8 bytes and owner review contain metadata only',
      async () => {
        assert.equal(d.digest, digestManifest(manifest));
        assert.equal(manifest.format_version, 2);
        assert.deepEqual(manifest.registered_sources, [
          { source_id: 'code', source_revision: 1, access_revision: 1, role: 'code' },
          { source_id: 'personal', source_revision: 1, access_revision: 1, role: 'personal' },
        ]);
        assert.equal(manifest.code.commits, 2);
        assert.equal(
          manifest.code.history_digest,
          createHash('sha256')
            .update(input.code.commits.join('\n') + '\n')
            .digest('hex'),
        );
        const content = '結論から書く。\n',
          file = manifest.contexts[0].files[0];
        assert.equal(file.bytes, Buffer.byteLength(content));
        assert.equal(file.sha256, createHash('sha256').update(content).digest('hex'));
        assert.equal(d.body.includes(content), false);
        assert.equal(Object.hasOwn(file, 'content'), false);
        assert.equal(
          await count('work_request_disclosure', 'WHERE request_digest=?', [saved.digest]),
          1,
        );
        const http = await b.fetch(`https://work.test/work/disclosures/${d.digest}`, {
          headers: { Cookie: `__Host-op-sso=${original.cookie}` },
        });
        assert.equal(http.status, 200);
        assert.equal(http.headers.get('Cache-Control'), 'no-store');
        assert.deepEqual(((await http.json()) as any).record.manifest, manifest);
        assert.equal(
          (
            await b.fetch(`https://work.test/work/disclosures/${d.digest}`, {
              headers: { Cookie: `__Host-op-sso=${foreign.cookie}` },
            })
          ).status,
          404,
        );
        await assert.rejects(
          DB.prepare('UPDATE work_disclosure SET selected_bytes=0 WHERE digest=?')
            .bind(d.digest)
            .run(),
        );
        await assert.rejects(
          DB.prepare('DELETE FROM work_disclosure WHERE digest=?').bind(d.digest).run(),
        );
        await assert.rejects(
          DB.prepare('DELETE FROM work_request_disclosure WHERE request_digest=?')
            .bind(saved.digest)
            .run(),
        );
      },
    );

    await t.test(
      'every source in a two-context disclosure is bound; loss and restored access invalidate the old digest',
      async () => {
        const o = await owner('multi-source-owner');
        const md = await call(o, { action: 'disclosure', disclosure: multi, expires_at: expiry });
        const m = JSON.parse(md.body).data.data;
        assert.equal(md.digest, digestManifest(m));
        assert.deepEqual(
          m.registered_sources.map((s: any) => s.source_id),
          ['code', 'personal', 'project'],
        );
        const mr = request('multi-source', md.digest);
        await DB.prepare(
          "UPDATE work_source_access SET active=0,access_revision=2 WHERE owner_id=? AND source_id='project'",
        )
          .bind(o.account)
          .run();
        await call(o, { action: 'resolved-request', request: mr }, 409);
        await call(
          o,
          {
            action: 'disclosure',
            disclosure: { ...multi, snapshot: { ...multi.snapshot, repository: 'revoked-multi' } },
            expires_at: expiry,
          },
          409,
        );
        assert.equal(await count('work_request', 'WHERE owner_id=?', [o.account]), 0);
        await DB.prepare(
          "UPDATE work_source_access SET active=1,access_revision=3 WHERE owner_id=? AND source_id='project'",
        )
          .bind(o.account)
          .run();
        await call(o, { action: 'resolved-request', request: mr }, 409);
        const fresh = await call(
          o,
          { action: 'disclosure', disclosure: multi, expires_at: expiry },
          200,
          b,
        );
        assert.notEqual(fresh.digest, md.digest);
        assert.equal(JSON.parse(fresh.body).data.data.registered_sources[2].access_revision, 3);
        await call(o, {
          action: 'resolved-request',
          request: request('multi-source', fresh.digest),
        });
      },
    );

    await t.test(
      'native binding refuses Git file and complete-history claims outside the registered receipt',
      async () => {
        for (const mutate of [
          (i: any) => (i.contexts[0].files[0].content = 'Changed text\n'),
          (i: any) => (i.contexts[0].files[0].path = 'not-registered.md'),
          (i: any) => (i.code.object_bytes += 1),
          (i: any) => (i.code.commits = [i.code.commit]),
        ]) {
          const changed = structuredClone(input);
          mutate(changed);
          await call(
            original,
            { action: 'disclosure', disclosure: changed, expires_at: expiry },
            409,
          );
        }
      },
    );

    await t.test(
      'revocation after native resolution rolls back a disclosure and its reservation at the SQL boundary',
      async () => {
        const o = await owner('resolved-source-race');
        const prepared = await call(o, {
          action: 'disclosure-body',
          disclosure: multi,
          expires_at: expiry,
        });
        await DB.prepare(
          "UPDATE work_source_access SET active=0,access_revision=2 WHERE owner_id=? AND source_id='personal'",
        )
          .bind(o.account)
          .run();
        await assert.rejects(
          DB.batch([
            DB.prepare(reserveSql).bind(o.account),
            DB.prepare(saveDisclosureSql).bind(prepared.body, projection, o.hash),
          ]),
          /work_source_guard_failed/,
        );
        assert.equal(await count('work_disclosure', 'WHERE owner_id=?', [o.account]), 0);
        assert.equal(await count('work_disclosure_window', 'WHERE owner_id=?', [o.account]), 0);
        assert.equal(await count('work_audit', 'WHERE owner_id=?', [o.account]), 0);
      },
    );

    await t.test(
      'revocation after request preparation rolls back request, head, binding and pending audit together',
      async () => {
        const o = await owner('request-source-race');
        const md = await call(o, { action: 'disclosure', disclosure: multi, expires_at: expiry });
        const req = await call(o, {
          action: 'request-body',
          request: request('race-create', md.digest),
        });
        const digest = JSON.parse(req.body).data.digest;
        await DB.prepare(
          "UPDATE work_source_access SET active=0,access_revision=2 WHERE owner_id=? AND source_id='project'",
        )
          .bind(o.account)
          .run();
        const audits = await count('work_audit', 'WHERE owner_id=?', [o.account]);
        await assert.rejects(
          DB.batch([
            DB.prepare(saveRequestSql).bind(req.body, projection, o.hash),
            DB.prepare(saveHeadSql).bind(digest),
            DB.prepare(bindSql).bind(digest, md.digest, o.account, o.hash),
            DB.prepare(auditSql).bind(
              'source-race-audit',
              o.account,
              'request',
              digest,
              'request.save',
              o.account,
              1,
              null,
              null,
              null,
            ),
          ]),
          /work_source_guard_failed/,
        );
        for (const table of ['work_request', 'work_request_head', 'work_request_disclosure'])
          assert.equal(await count(table, 'WHERE owner_id=?', [o.account]), 0);
        assert.equal(await count('work_audit', 'WHERE owner_id=?', [o.account]), audits);
        await call(
          o,
          { action: 'resolved-request', request: request('race-create', md.digest) },
          409,
          b,
        );
      },
    );

    await t.test(
      'source, recipient, workload, deadline and unknown upload fields cannot substitute review',
      async () => {
        for (const patch of [
          { base_commit: 'a'.repeat(40) },
          { recipient: 'other' },
          { workload: 'other' },
          { deadline: expiry + 1 },
          { task_repository: 'snapshot' },
        ])
          await call(
            original,
            {
              action: 'resolved-request',
              request: { ...request(`mismatch:${Object.keys(patch)[0]}`), ...patch },
            },
            409,
          );
        await call(foreign, { action: 'resolved-request', request: request('foreign') }, 409);
        await call(
          original,
          { action: 'disclosure', disclosure: { ...input, uploaded_owner: original.account } },
          400,
        );
        assert.equal(await count('work_request', 'WHERE owner_id=?', [original.account]), 1);
        // A legacy weak fixture row cannot become qualified through an immutable retry.
        const legacy = await call(original, { action: 'request', request: request('legacy') });
        await call(original, { action: 'resolved-request', request: request('legacy') }, 409);
        assert.equal(
          await count('work_request_disclosure', 'WHERE request_digest=?', [legacy.digest]),
          0,
        );
        const auditCount = await count('work_audit');
        assert.equal(
          (await call(original, { action: 'resolved-request', request: r }, 200, b)).digest,
          saved.digest,
        );
        assert.equal(await count('work_audit'), auditCount);
      },
    );

    await t.test(
      'source head replacement rejects the previous registered version even when Git bytes are unchanged',
      async () => {
        const o = await owner('source-head-owner');
        const facts = JSON.parse(
          (await DB.prepare(
            "SELECT body FROM work_source_version WHERE source_id='personal' AND source_revision=1",
          ).first('body')) as string,
        ).data.data;
        const source = { ...facts, source_id: 'head-context', repo_name: 'head-context' };
        await registerSource(source);
        await DB.prepare("INSERT INTO work_source_access VALUES(?,'head-context',0,1,1)")
          .bind(o.account)
          .run();
        const gi = {
          ...input,
          contexts: [{ ...input.contexts[0]!, repository: 'head-context' }],
          snapshot: { ...input.snapshot, repository: 'head-snapshot' },
        };
        const prepared = await call(o, {
          action: 'disclosure-body',
          disclosure: gi,
          expires_at: expiry,
        });
        const next = await call(o, {
          action: 'source-body',
          source: { ...source, source_revision: 2 },
        });
        await DB.batch([
          DB.prepare('INSERT INTO work_source_version VALUES(?,?,?)').bind(
            'head-context',
            2,
            next.body,
          ),
          DB.prepare(
            "UPDATE work_source_head SET source_revision=2 WHERE source_id='head-context'",
          ),
        ]);
        await assert.rejects(
          DB.prepare(saveDisclosureSql).bind(prepared.body, projection, o.hash).run(),
          /work_source_guard_failed/,
        );
        const fresh = await call(o, { action: 'disclosure', disclosure: gi, expires_at: expiry });
        assert.notEqual(fresh.digest, prepared.digest);
        assert.equal(JSON.parse(fresh.body).data.data.registered_sources[1].source_revision, 2);
      },
    );

    await t.test(
      'SQL source guard rejects forged file/history facts independently of the native constructor',
      async () => {
        const o = await owner('sql-registered-receipts');
        const prepared = await call(o, {
          action: 'disclosure-body',
          disclosure: multi,
          expires_at: expiry,
        });
        for (const mutate of [
          (m: any) => (m.code.history_digest = '0'.repeat(64)),
          (m: any) => (m.contexts[1].files[0].sha256 = '0'.repeat(64)),
          (m: any) => (m.registered_sources[2].source_id = 'personal'),
          (m: any) => (m.registered_sources[1].access_revision = 2),
        ]) {
          const record = JSON.parse(prepared.body);
          mutate(record.data.data);
          record.data.digest = digestManifest(record.data.data);
          await assert.rejects(
            DB.prepare(saveDisclosureSql).bind(JSON.stringify(record), projection, o.hash).run(),
            /work_source_guard_failed/,
          );
        }
        assert.equal(await count('work_disclosure', 'WHERE owner_id=?', [o.account]), 0);
      },
    );

    await t.test(
      'grant/run admission repeats source freshness after their native preparation; retained grants stay revocable',
      async () => {
        const o = await owner('source-issuance-owner');
        const md = await call(o, { action: 'disclosure', disclosure: multi, expires_at: expiry });
        const r = request('source-issuance', md.digest);
        const w = await call(o, { action: 'resolved-request', request: r });
        await taskFor(o, r);
        const preparedGrant = await call(o, {
          action: 'grant-body',
          id: 'stale-source-grant',
          digest: w.digest,
        });
        await call(o, { action: 'grant', id: 'retained-source-grant', digest: w.digest });
        const preparedRun = await call(o, {
          action: 'run-body',
          grant: 'retained-source-grant',
          run: 'stale-source-run',
        });
        await DB.prepare(
          "UPDATE work_source_access SET active=0,access_revision=2 WHERE owner_id=? AND source_id='project'",
        )
          .bind(o.account)
          .run();
        await call(o, { action: 'grant', id: 'new-source-grant', digest: w.digest }, 409);
        await call(
          o,
          { action: 'run', grant: 'retained-source-grant', run: 'new-source-run' },
          409,
        );
        await assert.rejects(
          DB.batch([
            DB.prepare(grantSql).bind(preparedGrant.body, o.hash, md.digest),
            DB.prepare(guardSql).bind('stale-grant-guard'),
          ]),
          /work_guard_passed/,
        );
        await assert.rejects(
          DB.batch([
            DB.prepare(runSql).bind(preparedRun.body, preparedRun.actor_expires_at, md.digest),
            DB.prepare(guardSql).bind('stale-run-guard'),
          ]),
          /work_guard_passed/,
        );
        assert.equal(await count('work_grant', "WHERE grant_id='stale-source-grant'"), 0);
        assert.equal(await count('work_run', 'WHERE request_digest=?', [w.digest]), 0);
        await call(o, { action: 'revoke-grant', id: 'retained-source-grant' });
        assert.equal(
          await DB.prepare(
            "SELECT revoked FROM work_grant WHERE grant_id='retained-source-grant'",
          ).first('revoked'),
          1,
        );
        assert.equal(await count('work_transition_guard'), 0);
      },
    );

    await t.test(
      'retained v1 disclosure stays readable but cannot create or renew request/grant/run authority',
      async () => {
        const o = await owner('legacy-source-owner');
        const legacy = await call(o, {
          action: 'legacy-disclosure-body',
          disclosure: input,
          expires_at: expiry,
        });
        const m = JSON.parse(legacy.body).data.data;
        assert.equal(legacy.digest, digestManifest(m));
        const r = request('legacy-source', legacy.digest);
        const w = await call(o, { action: 'request', request: r });
        // Simulate records retained from before 0050; only this local fixture
        // bypasses new-admission triggers, restoring them in finally.
        const triggers = ['work_disclosure_registered_sources', 'work_request_disclosure_sources'];
        const definitions: string[] = [];
        for (const name of triggers)
          definitions.push(
            (await DB.prepare('SELECT sql FROM sqlite_master WHERE name=?')
              .bind(name)
              .first('sql')) as string,
          );
        for (const name of triggers) await DB.prepare(`DROP TRIGGER ${name}`).run();
        try {
          await DB.prepare('INSERT INTO work_disclosure VALUES(?,?,?,?,?,?,?,?)')
            .bind(
              legacy.digest,
              o.account,
              0,
              m.policy_revision,
              projection,
              expiry,
              m.selected_bytes,
              legacy.body,
            )
            .run();
          await DB.prepare('INSERT INTO work_request_disclosure VALUES(?,?,?)')
            .bind(w.digest, legacy.digest, o.account)
            .run();
        } finally {
          for (const sql of definitions) await DB.prepare(sql).run();
        }
        const read = await b.fetch(`https://work.test/work/disclosures/${legacy.digest}`, {
          headers: { Cookie: `__Host-op-sso=${o.cookie}` },
        });
        assert.equal(read.status, 200);
        assert.deepEqual(((await read.json()) as any).record.manifest, m);
        await call(o, { action: 'resolved-request', request: r }, 409);
        await call(
          o,
          { action: 'resolved-request', request: request('new-legacy-source', legacy.digest) },
          409,
        );
        await taskFor(o, r);
        await call(o, { action: 'grant', id: 'forbidden-legacy-grant', digest: w.digest }, 409);
        const grant = await call(o, {
          action: 'grant-body',
          id: 'historic-legacy-grant',
          digest: w.digest,
        });
        const g = JSON.parse(grant.body).data;
        await DB.prepare(
          'INSERT INTO work_grant(grant_id,request_digest,task_revision,expires_at,body) VALUES(?,?,?,?,?)',
        )
          .bind(g.id, g.request, g.task_revision, g.expires_at, grant.body)
          .run();
        await call(o, { action: 'run', grant: g.id, run: 'forbidden-legacy-run' }, 409);
        await call(o, { action: 'revoke-grant', id: g.id });
        assert.equal(await count('work_run', 'WHERE request_digest=?', [w.digest]), 0);
      },
    );

    await t.test(
      'binding SQL repeats code/recipient and current policy/epoch rather than trusting parsed input',
      async () => {
        const bad = { ...request('sql-mismatch'), recipient: 'other' };
        const { digest } = await call(original, { action: 'request', request: bad });
        await assert.rejects(
          DB.prepare('INSERT INTO work_request_disclosure VALUES(?,?,?)')
            .bind(digest, d.digest, original.account)
            .run(),
        );
        const stale = await owner('epoch-owner'),
          sd = await disclosure(stale, 'epoch-snapshot');
        await DB.prepare('UPDATE account_security SET epoch=epoch+1 WHERE account_id=?')
          .bind(stale.account)
          .run();
        await DB.prepare('UPDATE sso_session SET epoch=epoch+1 WHERE account_id=?')
          .bind(stale.account)
          .run();
        await call(
          stale,
          { action: 'resolved-request', request: request('epoch-stale', sd.digest) },
          409,
        );
        assert.equal(await count('work_request', 'WHERE request_id=?', ['epoch-stale']), 0);
      },
    );

    await t.test(
      '0004 preserves existing v1/v2 metadata and associations without certifying legacy selection authority',
      async () => {
        const sql = new DatabaseSync(':memory:');
        const directory = new URL('../../crates/worker/work-migrations/', import.meta.url);
        try {
          sql.exec('PRAGMA foreign_keys=ON');
          await applySqliteBaseline(sql);
          for (const name of (await readdir(directory))
            .filter((n) => n.endsWith('.sql') && Number(n.slice(0, 4)) < 4)
            .sort())
            sql.exec(await readFile(new URL(name, directory), 'utf8'));
          async function copy(table: string, where = '', parameters: unknown[] = []) {
            const { results } = await DB.prepare(`SELECT * FROM ${table} ${where}`)
              .bind(...parameters)
              .all();
            for (const row of results) {
              const keys = Object.keys(row);
              sql
                .prepare(
                  `INSERT INTO ${table}(${keys.join(',')}) VALUES(${keys.map(() => '?').join(',')})`,
                )
                .run(...(keys.map((k) => row[k]) as any[]));
            }
          }
          await copy('runtime_policy_version');
          await copy('runtime_policy_active');
          await copy('account_security', 'WHERE account_id=?', [original.account]);
          await copy('credential', 'WHERE account_id=?', [original.account]);
          await copy('sso_session', 'WHERE account_id=?', [original.account]);
          await copy('sso_context', 'WHERE sso_id=?', [`sso:${original.account}`]);
          await copy('work_source_version');
          await copy('work_source_head');
          await copy('work_source_access', 'WHERE owner_id=?', [original.account]);
          await copy('work_disclosure', 'WHERE digest=?', [d.digest]);
          await copy('work_request', 'WHERE digest=?', [saved.digest]);
          await copy('work_request_head', 'WHERE digest=?', [saved.digest]);
          await copy('work_request_disclosure', 'WHERE request_digest=?', [saved.digest]);
          const legacy = await call(original, {
            action: 'legacy-disclosure-body',
            disclosure: { ...input, snapshot: { ...input.snapshot, repository: 'preserved-v1' } },
            expires_at: expiry,
          });
          const m = JSON.parse(legacy.body).data.data;
          sql
            .prepare('INSERT INTO work_disclosure VALUES(?,?,?,?,?,?,?,?)')
            .run(
              legacy.digest,
              original.account,
              0,
              m.policy_revision,
              projection,
              expiry,
              m.selected_bytes,
              legacy.body,
            );
          const lr = await call(original, {
            action: 'request-body',
            request: request('preserved-v1-request', legacy.digest),
          });
          const raw = JSON.parse(lr.body).data;
          sql
            .prepare('INSERT INTO work_request VALUES(?,?,?,?,?,?,?,?,?)')
            .run(
              raw.digest,
              raw.input.request_id,
              original.account,
              1,
              0,
              raw.policy_revision,
              projection,
              raw.input.deadline,
              lr.body,
            );
          sql
            .prepare('INSERT INTO work_request_head VALUES(?,?,?,?)')
            .run(original.account, raw.input.request_id, 1, raw.digest);
          sql
            .prepare('INSERT INTO work_request_disclosure VALUES(?,?,?)')
            .run(raw.digest, legacy.digest, original.account);
          const tables = (
            sql
              .prepare(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
              )
              .all() as { name: string }[]
          ).map((r) => r.name);
          const before = tables.map((name) => sql.prepare(`SELECT * FROM ${name}`).all());
          sql.exec(
            await readFile(new URL('0004_work_registered_disclosures.sql', directory), 'utf8'),
          );
          assert.deepEqual(
            tables.map((name) => sql.prepare(`SELECT * FROM ${name}`).all()),
            before,
          );
          assert.deepEqual(sql.prepare('PRAGMA foreign_key_check').all(), []);
          assert.equal(
            sql
              .prepare('SELECT count(*) AS n FROM work_disclosure_source_current WHERE digest=?')
              .get(d.digest)!.n,
            1,
          );
          assert.equal(
            sql
              .prepare('SELECT count(*) AS n FROM work_disclosure_source_current WHERE digest=?')
              .get(legacy.digest)!.n,
            0,
          );
          assert.throws(
            () =>
              sql.prepare('INSERT INTO work_disclosure VALUES(?,?,?,?,?,?,?,?)').run(
                '0'.repeat(64),
                original.account,
                0,
                m.policy_revision,
                projection,
                expiry,
                m.selected_bytes,
                JSON.stringify({
                  ...JSON.parse(legacy.body),
                  data: { data: m, digest: '0'.repeat(64) },
                }),
              ),
            /work_source_guard_failed/,
          );
          assert.throws(
            () =>
              sql
                .prepare('INSERT INTO work_request_disclosure VALUES(?,?,?)')
                .run(raw.digest, legacy.digest, original.account),
            /work_source_guard_failed/,
          );
        } finally {
          sql.close();
        }
      },
    );

    await t.test(
      'two isolates reserve one remaining snapshot atomically; exact retries do not charge',
      async () => {
        const o = await owner('snapshot-race');
        await DB.prepare(
          'UPDATE work_resource_policy SET disclosures_per_owner=1 WHERE id=1',
        ).run();
        try {
          const replies = await Promise.all(
            [a, b].map((target, i) =>
              target.fetch('https://work.test/fixture', {
                method: 'POST',
                body: JSON.stringify({
                  session: o.hash,
                  action: 'disclosure',
                  disclosure: {
                    ...input,
                    snapshot: { ...input.snapshot, repository: `race:${i}` },
                  },
                  expires_at: expiry,
                }),
              }),
            ),
          );
          assert.deepEqual(replies.map((x) => x.status).sort(), [200, 409]);
          const winner = (await replies.find((x) => x.status === 200)!.json()) as any;
          const name = JSON.parse(winner.body).data.data.snapshot.repository;
          await disclosure(o, name, 200, b);
          assert.equal(await count('work_disclosure', 'WHERE owner_id=?', [o.account]), 1);
          assert.equal(await count('work_audit', 'WHERE owner_id=?', [o.account]), 1);
          assert.equal(
            await DB.prepare('SELECT attempts FROM work_disclosure_window WHERE owner_id=?')
              .bind(o.account)
              .first('attempts'),
            1,
          );
          assert.equal(await count('work_transition_guard'), 0);
        } finally {
          await resetPolicy();
        }
      },
    );

    await t.test(
      'byte/global/hour/audit budgets fail before allocation and roll back reservations',
      async () => {
        const o = await owner('snapshot-limits');
        const constraints = [
          ['disclosure_bytes_per_owner', 1],
          ['disclosure_bytes_total', 1],
          ['disclosures_total', 1],
          ['new_audits_total', 1],
        ] as const;
        for (const [field, value] of constraints) {
          await DB.prepare(`UPDATE work_resource_policy SET ${field}=? WHERE id=1`)
            .bind(value)
            .run();
          await disclosure(o, `limit:${field}`, 409);
          assert.equal(await count('work_disclosure_window', 'WHERE owner_id=?', [o.account]), 0);
          await resetPolicy();
        }
        await DB.prepare(
          'UPDATE work_resource_policy SET disclosure_reviews_per_hour=1 WHERE id=1',
        ).run();
        try {
          await disclosure(o, 'hour-first');
          await disclosure(o, 'hour-second', 409);
          assert.equal(
            await DB.prepare('SELECT attempts FROM work_disclosure_window WHERE owner_id=?')
              .bind(o.account)
              .first('attempts'),
            1,
          );
        } finally {
          await resetPolicy();
        }
      },
    );

    await t.test('audit failure rolls back snapshot, reservation and guards', async () => {
      const o = await owner('snapshot-audit');
      await DB.prepare(
        "CREATE TRIGGER fail_snapshot_audit BEFORE INSERT ON work_audit BEGIN SELECT RAISE(ABORT,'injected private error'); END",
      ).run();
      try {
        await disclosure(o, 'audit-fail', 500);
        assert.equal(await count('work_disclosure', 'WHERE owner_id=?', [o.account]), 0);
        assert.equal(await count('work_disclosure_window', 'WHERE owner_id=?', [o.account]), 0);
        assert.equal(await count('work_transition_guard'), 0);
      } finally {
        await DB.prepare('DROP TRIGGER fail_snapshot_audit').run();
      }
    });

    await t.test(
      'creation ceilings and missing policy preserve revocation and outcome recording',
      async () => {
        await DB.batch([
          DB.prepare('INSERT INTO work_task_repository VALUES(?,?,1,?,?,?,?,?)').bind(
            r.task_repository,
            original.account,
            d.digest,
            r.recipient,
            r.workload,
            r.code_repository,
            r.base_commit,
          ),
          DB.prepare('INSERT INTO work_code_target VALUES(?,?,?,?,1,1)').bind(
            r.adoption_repository,
            r.adoption_ref,
            original.account,
            r.expected_head,
          ),
        ]);
        const grant = 'budget-grant',
          run = 'budget-run',
          approval = 'budget-approval',
          operation = 'budget-operation';
        await call(original, { action: 'grant', id: grant, digest: saved.digest });
        await call(original, { action: 'run', grant, run });
        const candidate = await call(original, {
          action: 'candidate',
          grant,
          run,
          candidate: { commit: 'd'.repeat(40), tree: 'e'.repeat(40), evidence: '6'.repeat(64) },
        });
        await call(original, { action: 'approve', id: approval, digest: candidate.digest });
        await call(original, { action: 'prepare', id: operation, approval });
        await call(original, { action: 'dispatch', id: operation });
        const perOwner: [string, Record<string, unknown>][] = [
          ['requests_per_owner', { action: 'resolved-request', request: request('owner-limit') }],
          ['grants_per_owner', { action: 'grant', id: 'owner-limit-grant', digest: saved.digest }],
          ['runs_per_owner', { action: 'run', grant, run: 'owner-limit-run' }],
          [
            'candidates_per_owner',
            {
              action: 'candidate',
              grant,
              run,
              candidate: { commit: 'f'.repeat(40), tree: 'e'.repeat(40), evidence: '6'.repeat(64) },
            },
          ],
          [
            'approvals_per_owner',
            { action: 'approve', id: 'owner-limit-approval', digest: candidate.digest },
          ],
          [
            'new_audits_per_owner',
            { action: 'resolved-request', request: request('owner-audit-limit') },
          ],
          [
            'objects_total',
            { action: 'resolved-request', request: request('global-object-limit') },
          ],
        ];
        for (const [field, action] of perOwner) {
          await DB.prepare(`UPDATE work_resource_policy SET ${field}=1 WHERE id=1`).run();
          try {
            await call(original, action, 409);
          } finally {
            await resetPolicy();
          }
        }
        await DB.prepare(
          'UPDATE work_resource_policy SET requests_per_owner=1,grants_per_owner=1,runs_per_owner=1,candidates_per_owner=1,approvals_per_owner=1,objects_total=1,new_audits_per_owner=1,new_audits_total=1 WHERE id=1',
        ).run();
        try {
          await call(
            original,
            { action: 'resolved-request', request: request('over-budget') },
            409,
          );
          await call(original, { action: 'grant', id: 'extra-grant', digest: saved.digest }, 409);
          await call(original, { action: 'run', grant, run: 'extra-run' }, 409);
          await call(
            original,
            {
              action: 'candidate',
              grant,
              run,
              candidate: { commit: 'f'.repeat(40), tree: 'e'.repeat(40), evidence: '6'.repeat(64) },
            },
            409,
          );
          await call(
            original,
            { action: 'approve', id: 'extra-approval', digest: candidate.digest },
            409,
          );
          await call(original, { action: 'outcome', id: operation, outcome: 'unknown' });
          await DB.prepare('DELETE FROM work_resource_policy').run();
          await disclosure(original, 'missing-policy', 409);
          await call(original, { action: 'revoke-grant', id: grant });
          await call(original, {
            action: 'outcome',
            id: operation,
            outcome: 'applied',
            receipt: 'receipt:budget-safe',
          });
          assert.equal(
            await DB.prepare('SELECT revoked FROM work_grant WHERE grant_id=?')
              .bind(grant)
              .first('revoked'),
            1,
          );
          assert.equal(
            await DB.prepare('SELECT state FROM work_code_operation WHERE operation_id=?')
              .bind(operation)
              .first('state'),
            'applied',
          );
        } finally {
          const fields = Object.keys(policy);
          await DB.prepare(
            `INSERT INTO work_resource_policy(${fields.join(',')}) VALUES(${fields.map(() => '?').join(',')}) ON CONFLICT(id) DO NOTHING`,
          )
            .bind(...fields.map((k) => policy[k]))
            .run();
          await resetPolicy();
        }
      },
    );

    await t.test(
      '0002 preserves previous OP and work records without certifying legacy disclosure facts',
      async () => {
        const sql = new DatabaseSync(':memory:'),
          directory = new URL('../../crates/worker/work-migrations/', import.meta.url);
        try {
          sql.exec('PRAGMA foreign_keys=ON');
          await applySqliteBaseline(sql);
          for (const name of (await readdir(directory))
            .filter((n) => n.endsWith('.sql') && Number(n.slice(0, 4)) < 2)
            .sort())
            sql.exec(await readFile(new URL(name, directory), 'utf8'));
          const tables = [
            'account_security',
            'credential',
            'sso_session',
            'sso_context',
            'runtime_policy_version',
            'runtime_policy_active',
            'work_request',
            'work_request_head',
          ];
          for (const table of tables) {
            const { results } = await DB.prepare(`SELECT * FROM ${table}`).all();
            for (const row of results) {
              const keys = Object.keys(row);
              sql
                .prepare(
                  `INSERT INTO ${table}(${keys.join(',')}) VALUES(${keys.map(() => '?').join(',')})`,
                )
                .run(...keys.map((k) => row[k] as string | number | null));
            }
          }
          const rows = tables.map((table) => sql.prepare(`SELECT * FROM ${table}`).all());
          const schema = sql
            .prepare(
              "SELECT name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY name",
            )
            .all();
          sql.exec('BEGIN IMMEDIATE');
          sql.exec(await readFile(new URL('0002_work_disclosure_budget.sql', directory), 'utf8'));
          sql.exec('COMMIT');
          tables.forEach((table, i) =>
            assert.deepEqual(sql.prepare(`SELECT * FROM ${table}`).all(), rows[i]),
          );
          for (const item of schema)
            assert.equal(
              sql.prepare('SELECT sql FROM sqlite_master WHERE name=?').get(item.name as string)!
                .sql,
              item.sql,
            );
          assert.equal(
            sql.prepare('SELECT count(*) AS n FROM work_request_disclosure').get()!.n,
            0,
          );
          assert.equal(sql.prepare('PRAGMA integrity_check').get()!.integrity_check, 'ok');
          assert.deepEqual(sql.prepare('PRAGMA foreign_key_check').all(), []);
        } finally {
          sql.close();
        }
      },
    );

    await t.test(
      'bounded orphan metadata collection retains referenced snapshots and audit evidence',
      async () => {
        const o = await owner('snapshot-retention');
        const currentPolicy = await DB.prepare(
          'SELECT projection_revision FROM runtime_policy_active WHERE id=1',
        ).first('projection_revision');
        const expired = clock() - 86410;
        await DB.prepare(
          'UPDATE work_resource_policy SET disclosures_per_owner=128 WHERE id=1',
        ).run();
        const aged = await call(o, {
          action: 'disclosure-body',
          disclosure: { ...input, snapshot: { ...input.snapshot, repository: 'aged-reference' } },
          issued_at: expired - 600,
          expires_at: expired,
        });
        const agedManifest = JSON.parse(aged.body).data.data;
        await DB.prepare('INSERT INTO work_disclosure VALUES(?,?,?,?,?,?,?,?)')
          .bind(
            aged.digest,
            o.account,
            0,
            agedManifest.policy_revision,
            currentPolicy,
            expired,
            agedManifest.selected_bytes,
            aged.body,
          )
          .run();
        const agedRequest = await call(o, {
          action: 'request-body',
          request: { ...request('aged-request', aged.digest), deadline: expired - 60 },
          issued_at: expired - 600,
        });
        const ar = JSON.parse(agedRequest.body).data;
        await DB.prepare('INSERT INTO work_request VALUES(?,?,?,?,?,?,?,?,?)')
          .bind(
            ar.digest,
            ar.input.request_id,
            o.account,
            1,
            0,
            ar.policy_revision,
            currentPolicy,
            ar.input.deadline,
            agedRequest.body,
          )
          .run();
        // Replay a formerly live association after simulated time elapsed. Only
        // this isolated fixture temporarily bypasses the new-admission trigger.
        const bindingTrigger = (await DB.prepare(
          "SELECT sql FROM sqlite_master WHERE name='work_request_disclosure_binding'",
        ).first('sql')) as string;
        await DB.prepare('DROP TRIGGER work_request_disclosure_binding').run();
        try {
          await DB.prepare('INSERT INTO work_request_disclosure VALUES(?,?,?)')
            .bind(ar.digest, aged.digest, o.account)
            .run();
        } finally {
          await DB.prepare(bindingTrigger).run();
        }
        for (let i = 0; i < 101; i++) {
          const old = await call(o, {
            action: 'disclosure-body',
            disclosure: { ...input, snapshot: { ...input.snapshot, repository: `expired:${i}` } },
            issued_at: expired - 600,
            expires_at: expired,
          });
          const meta = JSON.parse(old.body).data.data;
          await DB.prepare('INSERT INTO work_disclosure VALUES(?,?,?,?,?,?,?,?)')
            .bind(
              old.digest,
              o.account,
              0,
              meta.policy_revision,
              currentPolicy,
              expired,
              meta.selected_bytes,
              old.body,
            )
            .run();
        }
        const audits = await count('work_audit');
        const collected = await call(o, { action: 'collect-disclosures' });
        assert.equal(collected.collected, 100);
        assert.equal(await count('work_disclosure', 'WHERE owner_id=?', [o.account]), 2);
        assert.equal((await call(o, { action: 'collect-disclosures' }, 200, b)).collected, 1);
        assert.equal((await call(o, { action: 'collect-disclosures' })).collected, 0);
        assert.equal(await count('work_disclosure', 'WHERE digest=?', [d.digest]), 1);
        assert.equal(
          await count('work_request_disclosure', 'WHERE request_digest=?', [saved.digest]),
          1,
        );
        assert.equal(await count('work_audit'), audits);
        assert.equal(await count('work_disclosure', 'WHERE digest=?', [aged.digest]), 1);
        await assert.rejects(
          DB.prepare('DELETE FROM work_disclosure WHERE digest=?').bind(aged.digest).run(),
        );
        // Git payload is a separate operator-owned artifact, never erased by D1 GC.
        assert.equal(input.contexts[0]!.files[0]!.content, '結論から書く。\n');
      },
    );
    await t.test(
      'a changed policy projection at the same generation cannot relabel an already prepared disclosure',
      async () => {
        const o = await owner('projection-source-owner');
        const prepared = await call(o, {
          action: 'disclosure-body',
          disclosure: input,
          expires_at: expiry,
        });
        const substituted = '4'.repeat(64);
        assert.notEqual(substituted, projection);
        // Fault injection only; the real policy activator advances generation.
        await DB.prepare(
          'INSERT INTO runtime_policy_version SELECT ?,policy_revision,projection_json,created_at FROM runtime_policy_version WHERE projection_revision=?',
        )
          .bind(substituted, projection)
          .run();
        await DB.prepare('UPDATE runtime_policy_active SET projection_revision=? WHERE id=1')
          .bind(substituted)
          .run();
        try {
          await assert.rejects(
            DB.batch([
              DB.prepare(reserveSql).bind(o.account),
              DB.prepare(saveDisclosureSql).bind(prepared.body, substituted, o.hash),
            ]),
            /work_source_guard_failed/,
          );
          const fresh = await call(o, {
            action: 'disclosure-body',
            disclosure: input,
            expires_at: expiry,
          });
          assert.notEqual(fresh.digest, prepared.digest);
          assert.equal(JSON.parse(fresh.body).data.data.policy_projection, substituted);
          for (const table of ['work_disclosure', 'work_disclosure_window', 'work_audit'])
            assert.equal(await count(table, 'WHERE owner_id=?', [o.account]), 0);
        } finally {
          await DB.prepare('UPDATE runtime_policy_active SET projection_revision=? WHERE id=1')
            .bind(projection)
            .run();
        }
      },
    );
  } finally {
    await harness.close();
    await rm(parent, { recursive: true, force: true });
  }
});
