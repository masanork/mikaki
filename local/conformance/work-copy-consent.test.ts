/** Actual product owner API/private plan, enrolled checkpoint and explicit 0013.
 * Git sources and OP sessions are local synthetic fixtures; no remote effects. */
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createSourceFixture } from './support/work-source-fixture.ts';
import { seedPreparationReview } from './support/work-preparation-review-fixture.ts';

async function setup() {
  const f = await createSourceFixture(undefined, true, 'product', true);
  const s = await seedPreparationReview(f);
  const path = '/work/preparations/' + s.reserved.id + '/copy-consent';
  const request = async (method = 'GET', body?: unknown, o = f.first, target = f.worker) => {
    const r = await f.http(
      path,
      o,
      {
        method,
        headers: { Origin: 'https://work.test', 'Content-Type': 'application/json' },
        ...(body === undefined
          ? {}
          : { body: typeof body === 'string' ? body : JSON.stringify(body) }),
      },
      target,
    );
    return { status: r.status, body: (await r.json()) as any, headers: r.headers };
  };
  const preview = await request();
  assert.equal(preview.status, 200, JSON.stringify(preview.body));
  const intent = { format_version: 1, review_digest: preview.body.record.review_digest };
  const fixture = async (input: Record<string, unknown>) => {
    const r = await f.fixture.fetch('https://work.test/fixture', {
      method: 'POST',
      body: JSON.stringify({ session: f.first.hash, ...input }),
    });
    return { status: r.status, body: (await r.json()) as any };
  };
  return { f, s, path, request, preview, intent, fixture };
}

test('copy consent binds an exact owner review and gates private productive copying', async (t) => {
  const c = await setup();
  const { f, s, request, fixture, intent, preview } = c;
  try {
    await t.test('inspection has no consent, dispatch or workload authority', async () => {
      assert.equal(preview.body.record.can_approve, true);
      assert.equal(preview.body.record.subject.preparation_digest, s.reserved.digest);
      assert.equal(preview.body.record.subject.operator, 'Cloudflare Artifacts');
      assert.equal(
        await f.DB.prepare('SELECT count(*) FROM work_copy_consent').first('count(*)'),
        0,
      );
      assert.equal(
        (await fixture({ action: 'dispatch-preparation', id: s.reserved.id })).status,
        409,
      );
      assert.equal(
        await f.DB.prepare('SELECT state FROM work_preparation WHERE operation_id=?')
          .bind(s.reserved.id)
          .first('state'),
        'reserved',
      );
    });
    await t.test('method, gate, owner, origin and closed JSON boundaries', async () => {
      assert.equal((await request('GET', undefined, f.foreign)).status, 404);
      assert.equal((await request('POST', intent, f.foreign)).status, 404);
      assert.equal((await request('GET', undefined, f.first, f.disabled)).status, 404);
      assert.equal((await f.worker.fetch('https://work.test' + c.path)).status, 401);
      for (const method of ['PUT', 'PATCH', 'OPTIONS'])
        assert.equal((await request(method, intent)).status, 404);
      for (const headers of [
        { Origin: 'https://evil.test' },
        { Origin: 'https://work.test', 'Sec-Fetch-Site': 'cross-site' },
      ] as Record<string, string>[])
        assert.equal(
          (await f.http(c.path, f.first, { method: 'POST', body: JSON.stringify(intent), headers }))
            .status,
          403,
        );
      assert.equal(
        (
          await f.worker.fetch('https://work.test' + c.path, {
            method: 'POST',
            headers: {
              Cookie: '__Host-op-sso=' + f.first.cookie,
              'Content-Type': 'application/json',
            },
            body: JSON.stringify(intent),
          })
        ).status,
        403,
      );
      assert.equal((await request('POST', { ...intent, actor: f.first.account })).status, 400);
      assert.equal(
        (await request('POST', { ...intent, review_digest: 'f'.repeat(64) })).status,
        409,
      );
      assert.equal(
        (
          await request(
            'POST',
            '{"format_version":1,"format_version":1,"review_digest":"' +
              intent.review_digest +
              '"}',
          )
        ).status,
        400,
      );
      assert.equal((await request('POST', ' '.repeat(257))).status, 413);
      assert.equal((await f.http(c.path + '?owner=x')).status, 400);
    });
    await t.test('exact retry adds one consent and one audit, never a grant or token', async () => {
      for (let i = 0; i < 2; i++) {
        const r = await request('POST', intent);
        assert.equal(r.status, 200, JSON.stringify(r.body));
        assert.equal(r.body.record.status, 'approved');
        assert.equal(r.body.record.current, true);
        assert.equal(r.headers.get('Cache-Control'), 'no-store');
        assert.equal(JSON.stringify(r.body).includes(f.first.hash), false);
      }
      assert.equal(await f.DB.prepare('SELECT count(*) AS n FROM work_copy_consent').first('n'), 1);
      assert.equal(
        await f.DB.prepare(
          "SELECT count(*) AS n FROM work_audit WHERE action='copy.approve'",
        ).first('n'),
        1,
      );
      for (const table of ['work_grant', 'work_run', 'work_credential_attempt'])
        assert.equal(await f.DB.prepare('SELECT count(*) AS n FROM ' + table).first('n'), 0);
    });
    await t.test(
      'Native dispatch and product repo-create plan consume current consent',
      async () => {
        await s.call({ action: 'dispatch-preparation', id: s.reserved.id });
        await s.call({ action: 'activate-credential-key' });
        const a = await s.call({
          action: 'reserve-credential',
          credential: { preparation_id: s.reserved.id, role: 'task', purpose: 'initial' },
        });
        const env = await f.fixture.getEnv();
        const plan = async () => {
          const r = await env.OP_EFFECT_STORE.fetch(
            new Request('https://private.invalid/effect', {
              method: 'POST',
              body: JSON.stringify({ action: 'initial-plan', attempt_id: a.id }),
            }),
          );
          return { status: r.status, body: (await r.json()) as any };
        };
        const allowed = await plan();
        assert.equal(allowed.status, 200, JSON.stringify(allowed.body));
        assert.equal(allowed.body.effect, 'repo.create');
        assert.equal((await request('DELETE', intent)).status, 200);
        assert.equal((await plan()).status, 409);
        assert.equal((await request('POST', intent)).status, 409);
        assert.equal((await request('DELETE', intent)).body.record.status, 'withdrawn');
        assert.equal(
          await f.DB.prepare(
            "SELECT count(*) AS n FROM work_audit WHERE action='copy.withdraw'",
          ).first('n'),
          1,
        );
        // Safety transition and fixed journal identity survive withdrawal.
        await s.call({ action: 'cleanup-preparation', id: s.reserved.id });
        assert.equal(
          await f.DB.prepare('SELECT state FROM work_preparation WHERE operation_id=?')
            .bind(s.reserved.id)
            .first('state'),
          'cleanup_pending',
        );
        assert.equal(
          await f.DB.prepare('SELECT count(*) AS n FROM work_credential_attempt').first('n'),
          1,
        );
      },
    );
  } finally {
    await f.close();
  }
});

for (const change of ['source', 'session', 'checkpoint', 'withdraw'] as const)
  test('copy approval refuses changed ' + change + ' without productive dispatch', async () => {
    const { f, s, request, intent, fixture } = await setup();
    try {
      if (change === 'withdraw') {
        assert.equal((await request('POST', intent)).status, 200);
        assert.equal((await request('DELETE', intent)).status, 200);
      } else if (change === 'source')
        await f.DB.prepare(
          "UPDATE work_source_access SET active=0,access_revision=access_revision+1 WHERE owner_id=? AND source_id='personal'",
        )
          .bind(f.first.account)
          .run();
      else if (change === 'session') await f.revokeSession();
      else await f.checkpoint({ action: 'freeze' });
      assert.equal((await request('POST', intent)).status, change === 'session' ? 401 : 409);
      assert.equal(
        (await fixture({ action: 'dispatch-preparation', id: s.reserved.id })).status,
        409,
      );
      assert.equal(
        await f.DB.prepare('SELECT state FROM work_preparation WHERE operation_id=?')
          .bind(s.reserved.id)
          .first('state'),
        'reserved',
      );
      assert.equal(await f.DB.prepare('SELECT count(*) AS n FROM work_grant').first('n'), 0);
    } finally {
      await f.close();
    }
  });

test('retained consent cannot be inserted or rewritten outside a Native checkpoint frame', async () => {
  const { f, s, request, intent } = await setup();
  try {
    await assert.rejects(
      f.DB.prepare(
        'INSERT INTO work_copy_consent(preparation_id,review_digest,preparation_digest,owner_id,session_hash,artifacts_account,expires_at,active,revision) VALUES(?,?,?,?,?,?,?,1,1)',
      )
        .bind(
          s.reserved.id,
          intent.review_digest,
          s.reserved.digest,
          f.first.account,
          f.first.hash,
          'a'.repeat(32),
          Math.floor(Date.now() / 1000) + 600,
        )
        .run(),
    );
    assert.equal((await request('POST', intent)).status, 200);
    await assert.rejects(f.DB.prepare('UPDATE work_copy_consent SET active=0,revision=2').run());
    await assert.rejects(f.DB.prepare('DELETE FROM work_copy_consent').run());
    assert.equal((await request()).body.record.current, true);
  } finally {
    await f.close();
  }
});

test('consent and withdrawal roll back with their audit and leave the same review retryable', async () => {
  const { f, request, intent } = await setup();
  try {
    await f.DB.prepare(
      "CREATE TRIGGER copy_approval_audit_fault BEFORE INSERT ON work_audit WHEN NEW.action='copy.approve' BEGIN SELECT RAISE(ABORT,'copy audit fault'); END",
    ).run();
    assert.equal((await request('POST', intent)).status, 503);
    assert.equal(await f.DB.prepare('SELECT count(*) AS n FROM work_copy_consent').first('n'), 0);
    await f.DB.prepare('DROP TRIGGER copy_approval_audit_fault').run();
    assert.equal((await request('POST', intent)).status, 200);
    await f.DB.prepare(
      "CREATE TRIGGER copy_withdrawal_audit_fault BEFORE INSERT ON work_audit WHEN NEW.action='copy.withdraw' BEGIN SELECT RAISE(ABORT,'copy audit fault'); END",
    ).run();
    assert.equal((await request('DELETE', intent)).status, 503);
    assert.equal((await request()).body.record.current, true);
    await f.DB.prepare('DROP TRIGGER copy_withdrawal_audit_fault').run();
    assert.equal((await request('DELETE', intent)).status, 200);
  } finally {
    await f.close();
  }
});

test('a changed destination account cannot inherit consent and still permits owner withdrawal', async () => {
  const { f, request, intent } = await setup();
  try {
    assert.equal((await request('POST', intent)).status, 200);
    const r = await request('GET', undefined, f.first, f.otherAccount!);
    assert.equal(r.status, 200);
    assert.equal(r.body.record.status, 'approved');
    assert.equal(r.body.record.current, false);
    assert.equal(r.body.record.subject.artifacts_account, 'a'.repeat(32));
    assert.equal((await request('POST', intent, f.first, f.otherAccount!)).status, 409);
    assert.equal((await request('DELETE', intent, f.first, f.otherAccount!)).status, 200);
    assert.equal((await request()).body.record.current, false);
  } finally {
    await f.close();
  }
});

test('copy authority cannot outlive the approving SSO or reach external admission with a longer deadline', async () => {
  const f = await createSourceFixture(undefined, true, 'product', true, 120);
  try {
    const s = await seedPreparationReview(f);
    const path = '/work/preparations/' + s.reserved.id + '/copy-consent';
    const r = await f.http(path);
    assert.equal(r.status, 200);
    const { record } = (await r.json()) as any;
    assert.equal(record.can_approve, false);
    assert.equal(
      (
        await f.http(path, f.first, {
          method: 'POST',
          body: JSON.stringify({ format_version: 1, review_digest: record.review_digest }),
        })
      ).status,
      409,
    );
    assert.equal(await f.DB.prepare('SELECT count(*) AS n FROM work_copy_consent').first('n'), 0);
    // Captured primary SQL cannot bypass the Native deadline check at commit.
    await assert.rejects(
      f.DB.prepare(
        'INSERT INTO work_copy_consent(preparation_id,review_digest,preparation_digest,owner_id,session_hash,artifacts_account,expires_at,active,revision) SELECT operation_id,?,digest,owner_id,?,?,expires_at,1,1 FROM work_preparation WHERE operation_id=?',
      )
        .bind(record.review_digest, f.first.hash, 'a'.repeat(32), s.reserved.id)
        .run(),
    );
    assert.equal(
      await f.DB.prepare('SELECT state FROM work_preparation WHERE operation_id=?')
        .bind(s.reserved.id)
        .first('state'),
      'reserved',
    );
  } finally {
    await f.close();
  }
});
