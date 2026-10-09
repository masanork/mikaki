/** Actual product Rust/Wasm, primary D1, enrolled checkpoint and real local Git.
 * No provider mutation or workload identity/assurance is supplied by this lane. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { createSourceFixture } from './support/work-source-fixture.ts';
import { preparationComposePort } from '../../crates/worker/ui/work-compose-view.ts';
import { sourceHttpPort } from '../../crates/worker/ui/work-source-view.ts';

async function setup(sessionSeconds = 3600) {
  const f = await createSourceFixture(undefined, true, 'product', true, sessionSeconds, true);
  await f.register('code', f.first, {
    role: 'code',
    label: 'Synthetic code',
    files: [],
    ...f.codeSource,
  });
  const input = {
    format_version: 1,
    code: { source_id: 'code', source_revision: 1, access_revision: 1 },
    contexts: [f.input()],
    expires_at: Math.floor(Date.now() / 1000) + 600,
  };
  const request = (
    value: unknown = input,
    target = f.worker,
    owner = f.first,
    headers?: HeadersInit,
  ) =>
    f.http(
      '/work/preparations',
      owner,
      { method: 'POST', body: typeof value === 'string' ? value : JSON.stringify(value), headers },
      target,
    );
  const count = (table: string) => {
    assert.ok(
      [
        'work_disclosure',
        'work_preparation',
        'work_copy_consent',
        'work_credential_attempt',
        'work_request',
        'work_task_repository',
        'work_grant',
        'work_run',
        'source_reader_calls',
      ].includes(table),
    );
    return f.DB.prepare('SELECT count(*) AS n FROM ' + table).first('n');
  };
  return { ...f, input, request, count };
}
test('owner composition reserves Native metadata from pinned selections without copy or delegation authority', async (t) => {
  const f = await setup();
  let ack: any;
  try {
    await t.test(
      'closed transport refuses caller authority and stale selection before private I/O',
      async () => {
        assert.equal((await f.request(f.input, f.disabled)).status, 404);
        assert.equal(
          (
            await f.worker.fetch('https://work.test/work/preparations', {
              method: 'POST',
              headers: { Origin: 'https://work.test', 'Content-Type': 'application/json' },
              body: JSON.stringify(f.input),
            })
          ).status,
          401,
        );
        assert.equal((await f.request(f.input, f.worker, f.foreign)).status, 404);
        assert.equal((await f.request(f.input, f.unenrolled!)).status, 409);
        assert.equal(
          (await f.request(f.input, f.worker, f.first, { Origin: 'https://evil.test' })).status,
          403,
        );
        assert.equal(
          (await f.request(f.input, f.worker, f.first, { 'Sec-Fetch-Site': 'cross-site' })).status,
          403,
        );
        assert.equal(
          (await f.request(f.input, f.worker, f.first, { 'Content-Type': 'text/plain' })).status,
          415,
        );
        assert.equal(
          (
            await f.http('/work/preparations?owner=other', f.first, {
              method: 'POST',
              body: JSON.stringify(f.input),
            })
          ).status,
          400,
        );
        for (const key of [
          'actor',
          'owner_id',
          'recipient',
          'workload',
          'namespace',
          'task_repository',
          'snapshot',
          'disclosure',
          'receipt',
          'token',
        ])
          assert.equal((await f.request({ ...f.input, [key]: 'caller-input' })).status, 400, key);
        for (const change of [
          { source_revision: 2 },
          { access_revision: 2 },
          { source_id: 'missing' },
        ]) {
          const r = await f.request({ ...f.input, code: { ...f.input.code, ...change } });
          assert.equal(r.status, change.source_id ? 404 : 409, JSON.stringify(change));
        }
        assert.equal(
          (await f.request({ ...f.input, code: { ...f.input.code, source_id: 'personal' } }))
            .status,
          400,
        );
        assert.equal(
          (await f.request({ ...f.input, contexts: [f.input.contexts[0], f.input.contexts[0]] }))
            .status,
          400,
        );
        assert.equal((await f.request('{"format_version":1,"format_version":1}')).status, 400);
        assert.equal((await f.request(' '.repeat(16385))).status, 413);
        assert.equal(await f.count('source_reader_calls'), 0);
        assert.equal(await f.count('work_disclosure'), 0);
        assert.equal(await f.count('work_preparation'), 0);
      },
    );
    await t.test(
      'the planned parentless snapshot matches ordinary Git and retains metadata only',
      async () => {
        const r = await f.request();
        assert.equal(r.status, 200, await r.clone().text());
        ack = ((await r.json()) as any).record;
        assert.equal(r.headers.get('Cache-Control'), 'no-store');
        assert.equal(
          ack.request_digest,
          createHash('sha256')
            .update('mikaki.work-owner-compose-input.v1\0' + JSON.stringify(f.input))
            .digest('hex'),
        );
        const stored = await f.DB.prepare('SELECT body FROM work_disclosure WHERE digest=?')
          .bind(ack.disclosure_digest)
          .first('body');
        const d = JSON.parse(String(stored)).data.data;
        assert.equal(d.snapshot.commit, f.disclosure.snapshot.commit);
        assert.equal(d.snapshot.tree, f.disclosure.snapshot.tree);
        assert.equal(d.code.history_digest, f.codeSource.code.history_digest);
        assert.equal(d.code.commits, 2);
        assert.equal(d.recipient, 'synthetic-client');
        assert.equal(d.workload, 'synthetic-workload');
        assert.deepEqual(
          d.contexts[0].files.map((v: any) => v.snapshot_path),
          ['context/00/preferences/writing.md'],
        );
        assert.doesNotMatch(
          String(stored),
          /結論から|SYNTHETIC_UNSELECTED|SYNTHETIC_HISTORICAL_ONLY|content/,
        );
        const p = (await f.DB.prepare('SELECT * FROM work_preparation WHERE operation_id=?')
          .bind(ack.preparation_id)
          .first()) as any;
        assert.equal(p.state, 'reserved');
        assert.equal(p.revision, 1);
        assert.equal(p.task_namespace, 'mikaki-dev');
        assert.equal(p.snapshot_namespace, 'mikaki-dev');
        assert.match(p.task_repository, /^task-[a-f0-9]{64}$/);
        assert.notEqual(p.task_name, p.snapshot_name);
        for (const table of [
          'work_copy_consent',
          'work_credential_attempt',
          'work_task_repository',
          'work_request',
          'work_grant',
          'work_run',
        ])
          assert.equal(await f.count(table), 0, table);
      },
    );
    await t.test(
      'exact retries and competing isolates retain one preparation and reservation charge',
      async () => {
        const retries = await Promise.all([f.request(), f.request(f.input, f.b)]);
        for (const r of retries) {
          assert.equal(r.status, 200);
          assert.deepEqual(((await r.json()) as any).record, ack);
        }
        assert.equal(await f.count('work_disclosure'), 1);
        assert.equal(await f.count('work_preparation'), 1);
        for (const action of ['disclosure.reserve', 'preparation.reserve'])
          assert.equal(
            await f.DB.prepare('SELECT count(*) AS n FROM work_audit WHERE action=?')
              .bind(action)
              .first('n'),
            1,
          );
        assert.equal(
          await f.DB.prepare('SELECT sum(attempts) AS n FROM work_preparation_window').first('n'),
          1,
        );
      },
    );
    await t.test(
      'the source client correlates bounded acknowledgements and approval remains a separate owner action',
      async () => {
        const transport: typeof fetch = async (path, init) => {
          const r = await f.http(String(path), f.first, {
            method: init?.method,
            headers: init?.headers,
            ...(init?.body === undefined ? {} : { body: String(init.body) }),
          });
          return Response.json(await r.json(), {
            status: r.status,
            headers: Object.fromEntries(r.headers),
          });
        };
        const sources = await sourceHttpPort(transport).list();
        const code = sources.sources.find((s) => s.role === 'code')!;
        const context = sources.sources.find((s) => s.role === 'personal')!;
        assert.deepEqual(
          await preparationComposePort(transport).prepare(
            code,
            [{ source: context, paths: ['preferences/writing.md'] }],
            f.input.expires_at,
          ),
          ack,
        );
        const path = '/work/preparations/' + ack.preparation_id + '/copy-consent';
        const review = (await (await f.http(path)).json()) as any;
        assert.equal(review.record.status, 'unconfirmed');
        assert.equal(review.record.current, false);
        assert.equal(review.record.can_approve, true);
        const r = await f.http(path, f.first, {
          method: 'POST',
          body: JSON.stringify({ format_version: 1, review_digest: review.record.review_digest }),
        });
        assert.equal(r.status, 200);
        assert.equal(((await r.json()) as any).record.status, 'approved');
        assert.equal(await f.count('work_copy_consent'), 1);
        for (const table of [
          'work_credential_attempt',
          'work_task_repository',
          'work_request',
          'work_grant',
          'work_run',
        ])
          assert.equal(await f.count(table), 0, table);
        assert.equal(
          await f.DB.prepare('SELECT state FROM work_preparation').first('state'),
          'reserved',
        );
      },
    );
  } finally {
    await f.close();
  }
});
for (const [fault, status] of [
  ['access-replace', 409],
  ['head-revoke', 404],
  ['checkpoint-pending', 409],
  ['wrong-tree', 503],
  ['corrupt-blob', 503],
  ['reply-content', 404],
] as const)
  test(
    'composition refuses ' + fault + ' during source I/O without retained copy authority',
    async () => {
      const f = await setup();
      try {
        await f.fault('personal', fault);
        const r = await f.request();
        assert.equal(r.status, status, await r.clone().text());
        assert.equal(await f.count('work_disclosure'), 0);
        assert.equal(await f.count('work_preparation'), 0);
        assert.equal(await f.count('work_copy_consent'), 0);
      } finally {
        await f.close();
      }
    },
  );
test('preparation audit abort retains only safe disclosure metadata and the same selection is retryable', async () => {
  const f = await setup();
  try {
    await f.DB.exec(
      "CREATE TRIGGER compose_audit_abort BEFORE INSERT ON work_audit WHEN NEW.action='preparation.reserve' BEGIN SELECT RAISE(ABORT,'synthetic compose audit abort'); END;",
    );
    assert.equal((await f.request()).status, 503);
    assert.equal(await f.count('work_disclosure'), 1);
    assert.equal(await f.count('work_preparation'), 0);
    assert.equal(await f.count('work_copy_consent'), 0);
    assert.equal(
      await f.DB.prepare(
        'SELECT coalesce(sum(attempts),0) AS n FROM work_preparation_window',
      ).first('n'),
      0,
    );
    await f.DB.exec('DROP TRIGGER compose_audit_abort');
    const r = await f.request();
    assert.equal(r.status, 200, await r.clone().text());
    assert.equal(await f.count('work_disclosure'), 1);
    assert.equal(await f.count('work_preparation'), 1);
    assert.equal(
      await f.DB.prepare(
        "SELECT count(*) AS n FROM work_audit WHERE action='disclosure.reserve'",
      ).first('n'),
      1,
    );
    assert.equal(
      await f.DB.prepare(
        "SELECT count(*) AS n FROM work_audit WHERE action='preparation.reserve'",
      ).first('n'),
      1,
    );
  } finally {
    await f.close();
  }
});
test('composition deadline stays inside the current SSO and code-only preparation selects an empty snapshot', async () => {
  const f = await setup(120);
  try {
    assert.equal((await f.request()).status, 400);
    assert.equal(await f.count('source_reader_calls'), 0);
    assert.equal(await f.count('work_disclosure'), 0);
    const r = await f.request({
      ...f.input,
      contexts: [],
      expires_at: Math.floor(Date.now() / 1000) + 90,
    });
    assert.equal(r.status, 200, await r.clone().text());
    const ack = ((await r.json()) as any).record;
    const stored = await f.DB.prepare('SELECT body FROM work_disclosure WHERE digest=?')
      .bind(ack.disclosure_digest)
      .first('body');
    const d = JSON.parse(String(stored)).data.data;
    assert.deepEqual(d.contexts, []);
    assert.equal(d.snapshot.tree, '4b825dc642cb6eb9a060e54bf8d69288fbee4904');
    assert.equal(d.selected_bytes, 0);
    assert.equal(await f.count('source_reader_calls'), 0);
    assert.equal(await f.count('work_copy_consent'), 0);
  } finally {
    await f.close();
  }
});
test('composition client rejects substituted, over-bound and aborted acknowledgements without inheriting authority', async () => {
  const f = await setup();
  try {
    const list = await sourceHttpPort(async (p) => {
      const r = await f.http(String(p));
      return Response.json(await r.json(), { status: r.status });
    }).list();
    const code = list.sources.find((s) => s.role === 'code')!,
      context = list.sources.find((s) => s.role === 'personal')!;
    for (const fault of ['digest', 'extra', 'oversize', 'expiry']) {
      const port = preparationComposePort(async (_p, init) => {
        const r = await f.request(String(init!.body));
        const b = (await r.json()) as any;
        assert.equal(r.status, 200);
        if (fault === 'oversize') return new Response(' '.repeat(4097));
        if (fault === 'digest') b.record.request_digest = 'f'.repeat(64);
        if (fault === 'extra') b.record.token = 'SYNTHETIC_NO_AUTHORITY';
        if (fault === 'expiry') b.record.expires_at++;
        return Response.json(b);
      });
      await assert.rejects(
        port.prepare(
          code,
          [{ source: context, paths: ['preferences/writing.md'] }],
          f.input.expires_at,
        ),
      );
    }
    const controller = new AbortController();
    controller.abort();
    const port = preparationComposePort(async () => {
      throw new Error('aborted request reached transport');
    });
    await assert.rejects(
      port.prepare(code, [], f.input.expires_at, controller.signal),
      /unavailable/,
    );
    assert.equal(await f.count('work_preparation'), 1);
    assert.equal(await f.count('work_copy_consent'), 0);
  } finally {
    await f.close();
  }
});
