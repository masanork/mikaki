import { applyWorkMigrations } from './support/work-migrations.ts';
/** Actual Rust owner HTTP boundary on workerd/D1; seeded OP sessions, no login/actor/Git claims. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { createTestHarness } from 'wrangler';
import { activateWorkerPolicy } from '../../scripts/worker-policy-store.ts';

test('OP owner work transport uses live SSO, bounded projections and guarded revocation', async (t) => {
  const root = new URL('../..', import.meta.url).pathname;
  const config = {
    name: 'work-owner-a',
    main: `${root}/local/generated/work-store-main/worker.mjs`,
    compatibility_date: '2026-10-03',
    vars: { LOCAL_WORK_QUALIFICATION: 'true', WORK_OWNER_API_ENABLED: 'true' },
    d1_databases: [
      {
        binding: 'DB',
        database_name: 'work-owner',
        database_id: '00000000-0000-0000-0000-000000000048',
        migrations_dir: `${root}/crates/worker/migrations`,
      },
    ],
  };
  const harness = createTestHarness({
    root,
    workers: [
      { config },
      { config: { ...config, name: 'work-owner-b' } },
      {
        config: {
          ...config,
          name: 'work-owner-disabled',
          vars: { LOCAL_WORK_QUALIFICATION: 'true' },
        },
      },
    ],
  });
  try {
    await harness.listen();
    const a = harness.getWorker('work-owner-a');
    const b = harness.getWorker('work-owner-b');
    const disabled = harness.getWorker('work-owner-disabled');
    await a.applyD1Migrations('DB');
    const { DB } = await a.getEnv();
    await applyWorkMigrations(DB);
    await activateWorkerPolicy(
      DB,
      JSON.parse(
        await readFile(new URL('../generated/worker-policy.json', import.meta.url), 'utf8'),
      ),
      { actor: 'work-owner-test', reason: 'local qualification' },
    );
    const clock = () => Math.floor(Date.now() / 1000);
    async function owner(account: string) {
      const cookie = `synthetic-cookie:${account}`;
      const hash = createHash('sha256').update(cookie).digest('base64url');
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
      ]);
      return { account, cookie, hash };
    }
    type Owner = Awaited<ReturnType<typeof owner>>;
    async function fixture(o: Owner, input: Record<string, unknown>, status = 200): Promise<any> {
      const response = await a.fetch('https://work.test/fixture', {
        method: 'POST',
        body: JSON.stringify({ session: o.hash, ...input }),
      });
      const body = await response.json();
      assert.equal(response.status, status, JSON.stringify(body));
      return body;
    }
    async function http(
      path: string,
      o?: Owner,
      options: { method?: string; headers?: Record<string, string>; body?: string } = {},
      target = a,
    ) {
      const response = await target.fetch(`https://work.test${path}`, {
        ...options,
        headers: { ...(o ? { Cookie: `__Host-op-sso=${o.cookie}` } : {}), ...options.headers },
      });
      return {
        status: response.status,
        body: (await response.json()) as any,
        headers: response.headers,
      };
    }
    const revoke = (id: string, o: Owner, target = a) =>
      http(
        `/work/grants/${id}/revoke`,
        o,
        {
          method: 'POST',
          headers: { Origin: 'https://work.test', 'Content-Type': 'application/json' },
          body: '{"format_version":1}',
        },
        target,
      );
    async function request(o: Owner, label: string) {
      const input = {
        profile: 'mikaki-managed-work-v1',
        request_id: label,
        revision: 1,
        goal: 'Owner-reviewed sample goal',
        acceptance: 'Review the exact diff',
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
          input.task_repository,
          o.account,
          input.disclosure_digest,
          input.recipient,
          input.workload,
          input.code_repository,
          input.base_commit,
        ),
        DB.prepare('INSERT INTO work_code_target VALUES(?,?,?,?,1,1)').bind(
          input.adoption_repository,
          input.adoption_ref,
          o.account,
          input.expected_head,
        ),
      ]);
      const { digest } = await fixture(o, { action: 'request', request: input });
      return { input, digest };
    }
    async function base(o: Owner, label: string) {
      const f = await request(o, label);
      const grant = `grant:${label}`,
        run = `run:${label}`,
        approval = `approval:${label}`,
        operation = `operation:${label}`;
      await fixture(o, { action: 'grant', id: grant, digest: f.digest });
      await fixture(o, { action: 'run', grant, run });
      const candidate = { commit: 'd'.repeat(40), tree: 'e'.repeat(40), evidence: '6'.repeat(64) };
      const saved = await fixture(o, { action: 'candidate', grant, run, candidate });
      await fixture(o, { action: 'approve', id: approval, digest: saved.digest });
      await fixture(o, { action: 'prepare', id: operation, approval });
      return { ...f, grant, run, operation, candidate };
    }
    const first = await owner('owner-http-a'),
      foreign = await owner('owner-http-b');
    const f = await base(first, 'owner-http');

    await t.test(
      'closed routes and feature gates precede origin, session and body checks',
      async () => {
        const attempts = () =>
          DB.prepare('SELECT coalesce(sum(attempts),0) AS n FROM auth_request_window').first('n');
        const before = await attempts();
        const headers = { Origin: 'https://foreign.test', 'Content-Type': 'text/plain' };
        const closed: [string, string][] = [
          ['POST', '/work/preparations'],
          ...['GET', 'POST', 'DELETE', 'PUT'].flatMap((method) =>
            ['copy', 'copy-consent'].map((action): [string, string] => [
              method,
              `/work/preparations/bad%2Fid/${action}`,
            ]),
          ),
          ['GET', '/work/grants/id/revoke'],
          ['POST', '/work/grants/id/revoke/extra'],
          ['PUT', '/work/session'],
        ];
        for (const [method, path] of closed) {
          const r = await http(path, undefined, {
            method,
            headers,
            ...(method === 'POST' ? { body: 'x'.repeat(17000) } : {}),
          });
          assert.equal(r.status, 404, `${method} ${path}`);
          assert.deepEqual(r.body, { error: 'not_found' });
        }
        assert.equal(await attempts(), before, 'Closed routes consume no owner ingress');
        for (const path of [
          '/work/requests/' + 'x'.repeat(513),
          '/work/requests?' + 'q'.repeat(257),
        ]) {
          assert.equal((await http(path, undefined, { headers })).status, 400, path);
          assert.equal((await http(path, undefined, { headers }, disabled)).status, 404, path);
        }
        assert.equal(await attempts(), before, 'Length guards precede owner ingress');
      },
    );

    await t.test(
      'origin and request shape precede ingress while mutation JSON follows authentication',
      async () => {
        const attempts = () =>
          DB.prepare('SELECT coalesce(sum(attempts),0) AS n FROM auth_request_window').first('n');
        const before = await attempts();
        for (const path of [
          '/work/grants/bad%2Fid',
          '/work/requests?owner=foreign',
          '/work/requests/',
        ]) {
          const foreign = await http(path, undefined, {
            headers: { Origin: 'https://foreign.test' },
          });
          assert.equal(foreign.status, 403, path);
          assert.deepEqual(foreign.body, { error: 'invalid_origin' });
          assert.equal((await http(path)).status, 400, path);
        }
        for (const path of ['/work/session?after=valid', `/work/requests/${f.digest}?after=valid`])
          assert.equal((await http(path)).status, 400, path);
        const revokePath = `/work/grants/${f.grant}/revoke`;
        assert.equal(
          (await http(revokePath, undefined, { method: 'POST', body: '{' })).status,
          403,
        );
        assert.equal(
          await attempts(),
          before,
          'Origin and shape failures consume no owner ingress',
        );
        const unauthenticated = await http(revokePath, undefined, {
          method: 'POST',
          headers: { Origin: 'https://work.test', 'Content-Type': 'text/plain' },
          body: 'x'.repeat(257),
        });
        assert.equal(unauthenticated.status, 401);
        assert.deepEqual(unauthenticated.body, { error: 'authentication_required' });
        assert.equal((await http(`/work/grants/${f.grant}`, first)).body.record.revoked, false);
      },
    );

    await t.test(
      'disabled transport returns 404; cookies, not headers/bearer claims, authenticate owners',
      async () => {
        assert.equal((await http('/work/requests', first, {}, disabled)).status, 404);
        assert.equal((await http('/work/preparations/any', first, {}, disabled)).status, 404);
        const authenticationHeaders: Record<string, string>[] = [
          {},
          {
            Authorization: 'Bearer owner-http-a',
            'X-Mikaki-Account': first.account,
            'X-Mikaki-Session-Hash': first.hash,
          },
          { Cookie: `__Host-op-sso=${first.hash}` },
          { Cookie: `__Host-op-sso=${first.cookie}; __Host-op-sso=${first.cookie}` },
          { Cookie: `__Host-op-sso=${'x'.repeat(513)}` },
        ];
        for (const headers of authenticationHeaders) {
          assert.equal((await http('/work/requests', undefined, { headers })).status, 401);
        }
        const read = await http(`/work/requests/${f.digest}`, first);
        assert.equal(read.status, 200);
        assert.deepEqual(read.body.record.request, f.input);
        assert.equal(read.body.record.is_current, true);
        assert.equal(read.headers.get('Cache-Control'), 'no-store');
        assert.equal(read.headers.get('X-Content-Type-Options'), 'nosniff');
        assert.equal(read.headers.get('Access-Control-Allow-Origin'), null);
        assert.equal(JSON.stringify(read.body).includes(first.hash), false);
        assert.equal(JSON.stringify(read.body).includes(first.cookie), false);
        assert.equal((await http('/work/requests?owner=owner-http-a', first)).status, 400);
        assert.equal(
          (await http(`/work/grants/${encodeURIComponent(f.grant)}`, first)).status,
          200,
        );
        for (const id of ['bad%2Fid', 'bad%253Aid', 'bad%FFid', 'bad%', 'bad+id']) {
          assert.equal((await http(`/work/grants/${id}`, first)).status, 400);
        }
      },
    );

    await t.test(
      'a discarded revocation reply is recovered by the same owner read without another audit',
      async () => {
        const o = await owner('lost-reply-owner'),
          r = await base(o, 'lost-reply-http');
        // Simulate client delivery loss by discarding the completed HTTP response.
        await a.fetch(`https://work.test/work/grants/${encodeURIComponent(r.grant)}/revoke`, {
          method: 'POST',
          headers: {
            Cookie: `__Host-op-sso=${o.cookie}`,
            Origin: 'https://work.test',
            'Content-Type': 'application/json',
          },
          body: '{"format_version":1}',
        });
        assert.equal((await http(`/work/grants/${r.grant}`, o, {}, b)).body.record.revoked, true);
        assert.equal((await revoke(r.grant, o, b)).body.record.revision, 2);
        assert.equal(
          await DB.prepare(
            "SELECT count(*) AS n FROM work_audit WHERE entity_id=? AND action='authority.revoke'",
          )
            .bind(r.grant)
            .first('n'),
          1,
        );
      },
    );

    await t.test(
      'every read and revocation is owner-scoped with the same missing/foreign response',
      async () => {
        const own = await request(foreign, 'foreign-http');
        const list = await http('/work/requests', foreign);
        assert.deepEqual(
          list.body.requests.map((x: any) => x.digest),
          [own.digest],
        );
        for (const path of [
          `/work/requests/${f.digest}`,
          `/work/grants/${f.grant}`,
          `/work/runs/${f.run}`,
          `/work/operations/${f.operation}`,
        ]) {
          const denied = await http(path, foreign);
          assert.equal(denied.status, 404);
          assert.deepEqual(denied.body, { error: 'not_found' });
        }
        assert.deepEqual((await http('/work/grants/nonexistent', foreign)).body, {
          error: 'not_found',
        });
        assert.equal((await revoke(f.grant, foreign)).status, 404);
        assert.equal((await http(`/work/grants/${f.grant}`, first)).body.record.revoked, false);
      },
    );

    await t.test(
      'expired/revoked sessions, inactive credential/account and changed epoch stop access',
      async () => {
        const updates = [
          'UPDATE sso_session SET expires_at=unixepoch() WHERE account_id=?',
          'UPDATE sso_session SET revoked=1 WHERE account_id=?',
          'UPDATE credential SET active=0 WHERE account_id=?',
          'UPDATE account_security SET active=0 WHERE account_id=?',
          'UPDATE account_security SET epoch=epoch+1 WHERE account_id=?',
        ];
        for (const [index, sql] of updates.entries()) {
          const o = await owner(`dead-session:${index}`),
            r = await request(o, `dead-request:${index}`);
          await DB.prepare(sql).bind(o.account).run();
          assert.equal((await http(`/work/requests/${r.digest}`, o)).status, 401);
          // Direct named-store reads must repeat authentication even if an adapter
          // had successfully checked the session before this state change.
          await fixture(o, { action: 'owner-request-read', digest: r.digest }, 409);
          assert.deepEqual((await fixture(o, { action: 'owner-requests-read' })).requests, []);
        }
      },
    );

    await t.test(
      'unknown outcome and grant/run states survive cross-isolate reads and concurrent revoke retries',
      async () => {
        await fixture(first, { action: 'dispatch', id: f.operation });
        await fixture(first, { action: 'outcome', id: f.operation, outcome: 'unknown' });
        const replies = await Promise.all(
          [a, b, a, b].map((target) => revoke(f.grant, first, target)),
        );
        for (const r of replies) {
          assert.equal(r.status, 200);
          assert.equal(r.body.record.revoked, true);
          assert.equal(r.body.record.revision, 2);
        }
        const run = await http(`/work/runs/${f.run}`, first, {}, b);
        assert.equal(run.body.record.revoked, false);
        assert.equal(Object.hasOwn(run.body.record, 'execution'), false);
        const op = await http(`/work/operations/${f.operation}`, first, {}, b);
        assert.equal(op.body.record.id, f.operation);
        assert.equal(op.body.record.state, 'outcome_unknown');
        assert.equal(op.body.record.receipt, null);
        assert.equal(
          await DB.prepare(
            "SELECT count(*) AS n FROM work_audit WHERE entity_id=? AND action='authority.revoke'",
          )
            .bind(f.grant)
            .first('n'),
          1,
        );
        await fixture(
          first,
          { action: 'candidate', grant: f.grant, run: f.run, candidate: f.candidate },
          409,
        );
        const input = { ...f.input, revision: 2, goal: 'A different reviewed goal' };
        const edited = await fixture(first, { action: 'request', request: input });
        assert.equal(
          (await http(`/work/requests/${f.digest}`, first)).body.record.is_current,
          false,
        );
        assert.equal(
          (await http(`/work/requests/${edited.digest}`, first)).body.record.is_current,
          true,
        );
      },
    );

    await t.test(
      'mutations require same-origin closed bounded JSON and expose no issuance or effect action',
      async () => {
        const originHeaders: Record<string, string>[] = [
          {},
          { Origin: 'null' },
          { Origin: 'https://evil.test' },
          { Origin: 'https://work.test', 'Sec-Fetch-Site': 'cross-site' },
        ];
        for (const headers of originHeaders) {
          assert.equal(
            (
              await http(`/work/grants/${f.grant}/revoke`, first, {
                method: 'POST',
                headers,
                body: '{"format_version":1}',
              })
            ).status,
            403,
          );
        }
        assert.equal(
          (await http('/work/requests', first, { headers: { 'Sec-Fetch-Site': 'cross-site' } }))
            .status,
          403,
        );
        assert.equal(
          (await http('/work/requests', first, { headers: { Origin: 'https://evil.test' } }))
            .status,
          403,
        );
        const headers = { Origin: 'https://work.test', 'Content-Type': 'application/json' };
        for (const body of [
          '{}',
          '{"format_version":2}',
          '{"format_version":1,"owner":"owner-http-b"}',
          '{"format_version":1,"revoked":false}',
          '{"format_version":1,"format_version":1}',
          '{',
        ]) {
          assert.equal(
            (await http(`/work/grants/${f.grant}/revoke`, first, { method: 'POST', headers, body }))
              .status,
            400,
          );
        }
        assert.equal(
          (
            await http(`/work/grants/${f.grant}/revoke`, first, {
              method: 'POST',
              headers,
              body: 'x'.repeat(257),
            })
          ).status,
          413,
        );
        assert.equal(
          (
            await http(`/work/grants/${f.grant}/revoke`, first, {
              method: 'POST',
              headers: { Origin: 'https://work.test', 'Content-Type': 'text/plain' },
              body: '{"format_version":1}',
            })
          ).status,
          415,
        );
        for (const path of [
          '/work/requests',
          '/work/token',
          '/work/grants',
          '/work/dispatch',
          `/work/operations/${f.operation}`,
        ]) {
          assert.equal(
            (await http(path, first, { method: 'POST', headers, body: '{"format_version":1}' }))
              .status,
            404,
          );
        }
        assert.equal((await http(`/work/grants/${f.grant}/revoke`, first)).status, 404);
        for (const query of [
          'after=',
          'after=x&after=y',
          'limit=1000',
          'after=bad%2Fid',
          'after=' + 'x'.repeat(257),
        ]) {
          assert.equal((await http(`/work/requests?${query}`, first)).status, 400);
        }
      },
    );

    await t.test(
      'keyset pages contain only current owner heads, at most 20 public summaries',
      async () => {
        const o = await owner('paged-owner');
        for (let index = 0; index < 21; index++)
          await request(o, `paged:${String(index).padStart(2, '0')}`);
        const page = await http('/work/requests', o);
        assert.equal(page.status, 200);
        assert.equal(page.body.requests.length, 20);
        assert.equal(page.body.next_after, 'paged:19');
        assert.deepEqual(Object.keys(page.body.requests[0]).sort(), [
          'digest',
          'expires_at',
          'request_id',
          'revision',
        ]);
        const next = await http(`/work/requests?after=${page.body.next_after}`, o, {}, b);
        assert.deepEqual(
          next.body.requests.map((x: any) => x.request_id),
          ['paged:20'],
        );
        assert.equal(next.body.next_after, null);
        assert.equal(
          new Set([...page.body.requests, ...next.body.requests].map((x: any) => x.digest)).size,
          21,
        );
      },
    );

    await t.test(
      'audit/storage failure denies revocation without leaking errors or partial state',
      async () => {
        const o = await owner('audit-owner'),
          r = await base(o, 'audit-http');
        await DB.prepare(
          "CREATE TRIGGER fail_owner_work_audit BEFORE INSERT ON work_audit BEGIN SELECT RAISE(ABORT,'private database diagnostic'); END",
        ).run();
        const failed = await revoke(r.grant, o);
        assert.equal(failed.status, 503);
        assert.deepEqual(failed.body, { error: 'work_unavailable' });
        assert.equal((await http(`/work/grants/${r.grant}`, o)).body.record.revoked, false);
        await DB.prepare('DROP TRIGGER fail_owner_work_audit').run();
        assert.equal((await revoke(r.grant, o, b)).body.record.revoked, true);
      },
    );

    await t.test(
      'existing ingress budgets bound reads and deny writes before authority changes',
      async () => {
        const o = await owner('limited-owner'),
          r = await base(o, 'limited-http');
        await DB.prepare('DELETE FROM auth_request_window').run();
        await DB.prepare(
          'UPDATE auth_resource_policy SET source_per_minute=1,deployment_per_minute=2 WHERE id=1',
        ).run();
        assert.equal((await http('/work/requests', o)).status, 200);
        const denied = await revoke(r.grant, o);
        assert.equal(denied.status, 429);
        assert.equal(denied.headers.get('Retry-After'), '60');
        assert.equal(
          await DB.prepare('SELECT revoked FROM work_grant WHERE grant_id=?')
            .bind(r.grant)
            .first('revoked'),
          0,
        );
        await DB.prepare('DELETE FROM auth_resource_policy').run();
        assert.deepEqual((await http('/work/requests', o)).body, { error: 'work_unavailable' });
      },
    );
  } finally {
    await harness.close();
  }
});
