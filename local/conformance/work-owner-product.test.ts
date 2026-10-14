/** Actual production OP shim/facade and private checkpoint. Only the separate
 * qualification Worker seeds synthetic SSO/preparations and real local Git. */
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { gzipSync } from 'node:zlib';
import { createSourceFixture } from './support/work-source-fixture.ts';
import { seedPreparationReview } from './support/work-preparation-review-fixture.ts';

test('production owner routes preserve live authority and expose no fixture or productive action', async (t) => {
  const f = await createSourceFixture(undefined, true, 'product');
  try {
    const s = await seedPreparationReview(f);
    const paths = [
      '/work/session',
      '/work/requests',
      '/work/preparations',
      '/work/preparations/' + s.reserved.id,
      '/work/disclosures/' + s.disclosure.digest,
      '/work/sources',
      '/work/source-review',
      '/work/source-review.js',
      '/work/source-review.css',
      '/work/task-demo.js',
      '/work/task-demo.css',
      '/work/preparation-review',
      '/work/preparation-review.js',
      '/work/preparation-review.css',
    ];
    const guardedPaths = [
      ...paths,
      '/work/requests/missing',
      '/work/grants/missing',
      '/work/runs/missing',
      '/work/operations/missing',
    ];
    await t.test(
      'authenticated product entry serves projections and private review bundles',
      async () => {
        for (const path of paths) {
          const r = await f.http(path);
          assert.equal(r.status, 200, path);
          assert.equal(r.headers.get('Cache-Control'), 'no-store');
          assert.equal(r.headers.get('Vary'), 'Cookie, Origin');
          if (path.endsWith('.js')) {
            const bytes = Buffer.from(await r.arrayBuffer());
            assert.ok(bytes.length <= 196608, path + ' raw budget');
            assert.ok(gzipSync(bytes).length <= 65536, path + ' gzip estimate budget');
            t.diagnostic(`${path}: ${bytes.length} raw / ${gzipSync(bytes).length} gzip estimate`);
          } else if (path.endsWith('.css'))
            assert.ok((await r.arrayBuffer()).byteLength <= 48128, path + ' CSS budget');
        }
        const r = await f.http('/work/session');
        const session = (await r.json()) as Record<string, unknown>;
        assert.equal(session.account_id, f.first.account);
        assert.equal(JSON.stringify(session).includes(f.first.hash), false);
        assert.equal(JSON.stringify(session).includes(f.first.cookie), false);
      },
    );
    await t.test(
      'same-origin, live SSO, owner and feature gates apply at the public entry',
      async () => {
        for (const path of ['/work/session', '/work/sources', '/work/preparation-review.js']) {
          assert.equal((await f.worker.fetch('https://work.test' + path)).status, 401);
          assert.equal(
            (await f.http(path, f.first, { headers: { Origin: 'https://foreign.test' } })).status,
            403,
          );
          assert.equal(
            (await f.http(path, f.first, { headers: { 'Sec-Fetch-Site': 'cross-site' } })).status,
            403,
          );
        }
        assert.equal((await f.http('/work/preparations/' + s.reserved.id, f.foreign)).status, 404);
        assert.equal(
          (await f.http('/work/disclosures/' + s.disclosure.digest, f.foreign)).status,
          404,
        );
        for (const path of ['/work/source-review', '/work/preparation-review.js'])
          assert.equal((await f.http(path, f.first, {}, f.disabled)).status, 404);
        for (const host of ['app.mikaki.org', 'mikaki-native.tossa.app'])
          for (const path of paths)
            assert.equal(
              (
                await f.worker.fetch(`https://${host}${path}`, {
                  headers: { Cookie: '__Host-op-sso=' + f.first.cookie },
                })
              ).status,
              404,
            );
      },
    );
    await t.test(
      'work ingress is counted once and unknown methods/actions remain closed',
      async () => {
        const attempts = () =>
          f.DB.prepare('SELECT coalesce(sum(attempts),0) AS n FROM auth_request_window').first(
            'n',
          ) as Promise<number | null>;
        const before = (await attempts())!;
        assert.equal((await f.http('/work/session')).status, 200);
        assert.equal(
          (await attempts())! - before,
          2,
          'One deployment and one source budget increment',
        );
        const counted = await attempts();
        for (const path of [
          '/fixture',
          '/checkpoint-fixture',
          '/authority-fixture',
          '/effect',
          '/git-effect',
          '/mint-effect',
          '/work/disclosures',
          '/work/preparations',
          '/work/requests',
          '/work/grants',
          '/work/runs',
          '/work/copy',
          '/work/launch',
        ])
          assert.equal(
            (await f.http(path, f.first, { method: 'POST', body: '{}' })).status,
            404,
            path,
          );
        for (const method of ['HEAD', 'OPTIONS', 'DELETE', 'PUT'])
          assert.equal((await f.http('/work/session', f.first, { method })).status, 404);
        assert.equal(await attempts(), counted, 'Closed routes do not consume owner ingress');
        for (const q of ['owner=foreign', 'limit=100', 'after=x&after=y'])
          assert.equal((await f.http('/work/preparations?' + q)).status, 400);
        for (const table of ['work_request', 'work_grant', 'work_run', 'work_task_repository'])
          assert.equal(await f.DB.prepare(`SELECT count(*) AS n FROM ${table}`).first('n'), 0);
      },
    );
    await t.test(
      'a qualification Env flag cannot bypass a missing product checkpoint binding',
      async () => {
        const unenrolled = f.unenrolled;
        assert.ok(unenrolled);
        for (const path of guardedPaths)
          assert.equal((await f.http(path, f.first, {}, unenrolled)).status, 409, path);
        assert.equal(
          (
            await f.http(
              '/work/sources/read',
              f.first,
              { method: 'POST', body: JSON.stringify(f.input()) },
              unenrolled,
            )
          ).status,
          409,
        );
        assert.equal(
          await f.DB.prepare('SELECT count(*) AS n FROM source_reader_calls').first('n'),
          0,
        );
      },
    );
    await t.test(
      'selected Git text is rechecked after checkpoint intent appears inside source RPC',
      async () => {
        const read = () =>
          f.http('/work/sources/read', f.first, {
            method: 'POST',
            body: JSON.stringify(f.input()),
          });
        const valid = await read();
        assert.equal(valid.status, 200);
        const body = (await valid.json()) as { record: { files: { content: string }[] } };
        assert.equal(body.record.files[0]!.content, f.contents['preferences/writing.md']);
        await f.fault('personal', 'checkpoint-pending');
        const refused = await read();
        assert.equal(refused.status, 409);
        assert.equal(
          (await refused.text()).includes(f.contents['preferences/writing.md'].trim()),
          false,
        );
        for (const path of guardedPaths) assert.equal((await f.http(path)).status, 409, path);
        const calls = await f.DB.prepare('SELECT count(*) AS n FROM source_reader_calls').first(
          'n',
        );
        assert.equal((await read()).status, 409);
        assert.equal(
          await f.DB.prepare('SELECT count(*) AS n FROM source_reader_calls').first('n'),
          calls,
        );
      },
    );
  } finally {
    await f.close();
  }
});

test('product compilation refuses unenrolled work schema despite the qualification Env flag', async () => {
  const f = await createSourceFixture(undefined, true, 'product-unenrolled');
  try {
    assert.equal(
      await f.DB.prepare('SELECT count(*) AS n FROM work_authority_checkpoint').first('n'),
      0,
    );
    // The test-only compilation's pre-enrollment exemption is real; serving
    // the same data through the production entry must never acquire it.
    assert.equal((await f.http('/work/sources', f.first, {}, f.fixture)).status, 200);
    for (const path of [
      '/work/session',
      '/work/sources',
      '/work/requests',
      '/work/preparations',
      '/work/source-review',
      '/work/source-review.js',
      '/work/source-review.css',
      '/work/task-demo.js',
      '/work/task-demo.css',
      '/work/preparation-review',
      '/work/preparation-review.js',
      '/work/preparation-review.css',
    ])
      assert.equal((await f.http(path)).status, 409, path);
    assert.equal(
      (
        await f.http('/work/sources/read', f.first, {
          method: 'POST',
          body: JSON.stringify(f.input()),
        })
      ).status,
      409,
    );
    assert.equal(await f.DB.prepare('SELECT count(*) AS n FROM source_reader_calls').first('n'), 0);
    assert.equal((await f.http('/fixture', f.first, { method: 'POST', body: '{}' })).status, 404);
  } finally {
    await f.close();
  }
});

for (const mode of ['freeze', 'floor', 'mismatch'] as const)
  test(`production review refuses ${mode} checkpoint authority before source RPC`, async () => {
    const f = await createSourceFixture(undefined, true, 'product');
    try {
      const s = await seedPreparationReview(f);
      assert.equal((await f.http('/work/preparations/' + s.reserved.id)).status, 200);
      if (mode === 'mismatch') {
        const expected = await f.DB.prepare(
          'SELECT authority,epoch,sequence,tip FROM work_authority_checkpoint WHERE id=1',
        ).first();
        const begin = await f.checkpoint({
          action: 'begin',
          release: 1,
          expected,
          operation: 'simulate-db-restore',
        });
        assert.equal(begin.status, 200);
        const permit = (await begin.json()) as { next: unknown };
        // Advance only the independent floor, leaving Native D1 behind.
        assert.equal(
          (await f.checkpoint({ action: 'commit', release: 1, permit, observed: permit.next }))
            .status,
          200,
        );
      } else
        assert.equal(
          (
            await f.checkpoint(
              mode === 'freeze' ? { action: 'freeze' } : { action: 'raise-floor', floor: 2 },
            )
          ).status,
          200,
        );
      for (const path of [
        '/work/session',
        '/work/requests',
        '/work/requests/missing',
        '/work/grants/missing',
        '/work/runs/missing',
        '/work/operations/missing',
        '/work/preparations',
        '/work/preparations/' + s.reserved.id,
        '/work/disclosures/' + s.disclosure.digest,
        '/work/sources',
        '/work/source-review',
        '/work/source-review.js',
        '/work/source-review.css',
        '/work/task-demo.js',
        '/work/task-demo.css',
        '/work/preparation-review',
        '/work/preparation-review.js',
        '/work/preparation-review.css',
      ])
        assert.equal((await f.http(path)).status, 409, path);
      assert.equal(
        (
          await f.http('/work/sources/read', f.first, {
            method: 'POST',
            body: JSON.stringify(f.input()),
          })
        ).status,
        409,
      );
      assert.equal(
        await f.DB.prepare('SELECT count(*) AS n FROM source_reader_calls').first('n'),
        0,
      );
      assert.equal(await f.DB.prepare('SELECT count(*) AS n FROM work_grant').first('n'), 0);
    } finally {
      await f.close();
    }
  });
