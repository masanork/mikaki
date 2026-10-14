import { applySqliteBaseline } from './support/work-migrations.ts';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFile, readdir } from 'node:fs/promises';
import { DatabaseSync } from 'node:sqlite';
import { gzipSync } from 'node:zlib';
import { createSourceFixture } from './support/work-source-fixture.ts';

test('owner source access and real Git bytes through native OP/D1/private RPC', async (t) => {
  const f = await createSourceFixture();
  const read = (body: unknown, target = f.worker) =>
    f.http('/work/sources/read', f.first, { method: 'POST', body: JSON.stringify(body) }, target);
  const calls = async () =>
    Number(await f.DB.prepare('SELECT count(*) AS n FROM source_reader_calls').first('n'));
  try {
    await t.test(
      'review page, assets and display lease require live owner and opt-in source transport',
      async () => {
        for (const path of [
          '/work/source-review',
          '/work/source-review.js',
          '/work/source-review.css',
          '/work/task-demo.js',
          '/work/task-demo.css',
        ]) {
          assert.equal((await f.http(path, f.first, {}, f.disabled)).status, 404);
          const response = await f.http(path);
          assert.equal(response.status, 200);
          assert.equal(response.headers.get('Cache-Control'), 'no-store');
          assert.equal(response.headers.get('Vary'), 'Cookie, Origin');
          const bytes = Buffer.from(await response.arrayBuffer());
          if (path.endsWith('.js')) {
            assert.ok(bytes.length <= 196608, 'Source review JavaScript exceeds 192 KiB');
            assert.ok(
              gzipSync(bytes).length <= 65536,
              'Source review gzip estimate exceeds 64 KiB',
            );
            assert.match(response.headers.get('Content-Type')!, /^text\/javascript/);
          } else if (path.endsWith('.css')) {
            assert.ok(bytes.length <= 48128, 'Source review CSS exceeds the product CSS budget');
            assert.match(response.headers.get('Content-Type')!, /^text\/css/);
          }
          assert.equal(
            (await f.http(path, f.first, { headers: { Origin: 'https://foreign.test' } })).status,
            403,
          );
          assert.equal((await f.worker.fetch(`https://work.test${path}`)).status, 401);
        }
        const lease = await f.http('/work/session');
        const identity = (await lease.json()) as {
          account_id: string;
          credential_id: string;
          session_tag: string;
        };
        assert.equal(identity.account_id, f.first.account);
        assert.match(identity.session_tag, /^[A-Za-z0-9_-]{43}$/);
        assert.equal(lease.headers.get('Cache-Control'), 'no-store');
        assert.equal(JSON.stringify(identity).includes(f.first.hash), false);
        assert.equal((await f.worker.fetch('https://work.test/work/session')).status, 401);
        assert.equal((await f.http('/work/session?after=personal')).status, 400);
        assert.equal((await f.http('/work/source-review?lang=other')).status, 400);
        assert.equal(
          (await f.http('/work/source-review', f.first, { method: 'POST', body: '{}' })).status,
          404,
        );
        assert.equal(await f.DB.prepare('SELECT count(*) AS n FROM work_grant').first('n'), 0);
      },
    );
    await t.test('disabled and public/private-reader HTTP never expose a capability', async () => {
      assert.equal((await f.http('/work/sources', f.first, {}, f.disabled)).status, 404);
      assert.equal(
        (
          await f.harness
            .getWorker('source-reader')
            .fetch('https://private.test/', { method: 'POST', body: JSON.stringify(f.input()) })
        ).status,
        404,
      );
      assert.equal((await f.worker.fetch('https://work.test/work/source-review')).status, 401);
      assert.equal((await f.worker.fetch('https://work.test/work/source-review.js')).status, 401);
    });
    await t.test(
      'lists only owned pinned receipts and reads exactly selected rehashed UTF-8 blobs',
      async () => {
        const page = await f.http('/work/sources');
        assert.equal(page.status, 200);
        const { record } = (await page.json()) as any;
        assert.equal(record.sources[0].commit, f.source.commit);
        assert.equal(JSON.stringify(record).includes('repo_name'), false);
        assert.equal(JSON.stringify(record).includes('結論から'), false);
        assert.deepEqual(
          ((await (await f.http('/work/sources', f.foreign)).json()) as any).record.sources,
          [],
        );
        const response = await read(f.input(), f.b);
        assert.equal(response.status, 200);
        assert.equal(response.headers.get('Cache-Control'), 'no-store');
        assert.equal(response.headers.get('Access-Control-Allow-Origin'), null);
        const result = (await response.json()) as any;
        assert.equal(result.record.files.length, 1);
        assert.equal(result.record.files[0].content, '結論から書く。\n');
        assert.equal(JSON.stringify(result).includes('SYNTHETIC_UNSELECTED'), false);
        const wire = (await f.DB.prepare('SELECT request FROM source_reader_calls LIMIT 1').first(
          'request',
        )) as string;
        assert.equal(wire.includes(f.first.hash), false);
        assert.equal(wire.includes(f.first.account), false);
        assert.equal(await f.DB.prepare('SELECT count(*) AS n FROM work_grant').first('n'), 0);
        assert.equal(await f.DB.prepare('SELECT count(*) AS n FROM work_disclosure').first('n'), 0);
        assert.equal(
          (
            await f.http('/work/sources/read', f.foreign, {
              method: 'POST',
              body: JSON.stringify(f.input()),
            })
          ).status,
          404,
        );
      },
    );
    await t.test(
      'stale revisions, unknown/duplicate fields, arbitrary repo/blob and unsupported paths stop before RPC',
      async () => {
        const before = await calls();
        for (const patch of [{ source_revision: 2 }, { access_revision: 2 }])
          assert.equal((await read({ ...f.input(), ...patch })).status, 409);
        for (const patch of [
          { repo_name: 'other' },
          { blob: 'a'.repeat(40) },
          { owner: f.foreign.account },
          { paths: ['../wallet'] },
          { paths: ['preferences/writing.md', 'preferences/writing.md'] },
          { format_version: 2 },
        ])
          assert.ok([400, 404].includes((await read({ ...f.input(), ...patch })).status));
        assert.equal(
          (
            await f.http('/work/sources/read', f.first, {
              method: 'POST',
              body: '{"format_version":1,"format_version":1}',
            })
          ).status,
          400,
        );
        assert.equal(
          (await f.http('/work/sources/read', f.first, { method: 'POST', body: 'x'.repeat(16385) }))
            .status,
          413,
        );
        assert.equal(
          (
            await f.http('/work/sources/read', f.first, {
              method: 'POST',
              headers: { Origin: 'https://evil.test' },
              body: JSON.stringify(f.input()),
            })
          ).status,
          403,
        );
        assert.equal(
          (await f.http('/work/sources', f.first, { headers: { 'Sec-Fetch-Site': 'cross-site' } }))
            .status,
          403,
        );
        assert.equal(await calls(), before);
      },
    );
    await t.test(
      'Git API tree/blob mismatch and substituted native reply never release plaintext',
      async () => {
        for (const mode of [
          'wrong-tree',
          'missing-blob',
          'corrupt-blob',
          'missing-file',
          'wrong-file',
          'reply-id',
          'reply-content',
          'reply-unknown',
          'large-reply',
          'stall',
        ]) {
          await f.fault('personal', mode);
          const response = await read(f.input());
          assert.ok([400, 404, 503].includes(response.status), mode);
          const body = await response.text();
          assert.equal(body.includes('結論から'), false);
          assert.equal(body.includes('private database'), false);
        }
        await f.DB.prepare('DELETE FROM source_reader_fault').run();
      },
    );
    await t.test(
      'access/head/session/epoch changes during RPC are checked again before plaintext leaves OP',
      async () => {
        for (const mode of ['access-revoke', 'access-replace', 'head-revoke', 'epoch', 'session']) {
          const o = await f.owner(`race-owner:${mode}`);
          await f.register(`race:${mode}`, o);
          await f.fault(`race:${mode}`, mode, o.account);
          const response = await f.http('/work/sources/read', o, {
            method: 'POST',
            body: JSON.stringify(f.input(`race:${mode}`)),
          });
          assert.ok([404, 409].includes(response.status), mode);
          assert.equal((await response.text()).includes('結論から'), false);
        }
      },
    );
    await t.test(
      'keyset listing is bounded and source changes/audit failures are monotonic and atomic',
      async () => {
        const o = await f.owner('source-pages');
        for (let i = 0; i < 11; i++) await f.register(`page:${String(i).padStart(2, '0')}`, o);
        const first = (await (await f.http('/work/sources', o)).json()) as any;
        assert.equal(first.record.sources.length, 10);
        assert.equal(first.record.next_after, 'page:09');
        const next = (await (
          await f.http('/work/sources?after=page:09', o, {}, f.b)
        ).json()) as any;
        assert.equal(next.record.sources.length, 1);
        assert.equal((await f.http('/work/sources?limit=1000', o)).status, 400);
        await assert.rejects(
          f.DB.prepare("UPDATE work_source_version SET body='{}' WHERE source_id='personal'").run(),
        );
        await assert.rejects(
          f.DB.prepare(
            "UPDATE work_source_access SET access_revision=1 WHERE source_id='personal'",
          ).run(),
        );
        await assert.rejects(
          f.DB.prepare("DELETE FROM work_source_head WHERE source_id='personal'").run(),
        );
        await f.DB.prepare(
          "CREATE TRIGGER fail_source_audit BEFORE INSERT ON work_source_audit BEGIN SELECT RAISE(ABORT,'injected private diagnostic'); END",
        ).run();
        try {
          await assert.rejects(
            f.DB.prepare(
              "UPDATE work_source_access SET access_revision=2,active=0 WHERE source_id='personal'",
            ).run(),
          );
        } finally {
          await f.DB.prepare('DROP TRIGGER fail_source_audit').run();
        }
        assert.equal(
          await f.DB.prepare(
            "SELECT active FROM work_source_access WHERE source_id='personal'",
          ).first('active'),
          1,
        );
      },
    );
    await t.test(
      '0005 preserves previous OP/work schema and rows without inventing source access',
      async () => {
        const sql = new DatabaseSync(':memory:'),
          directory = new URL('../../crates/worker/work-migrations/', import.meta.url);
        try {
          sql.exec('PRAGMA foreign_keys=ON');
          await applySqliteBaseline(sql);
          for (const name of (await readdir(directory))
            .filter((n) => n.endsWith('.sql') && Number(n.slice(0, 4)) < 5)
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
            const { results } = await f.DB.prepare(`SELECT * FROM ${table}`).all();
            for (const row of results) {
              const keys = Object.keys(row);
              sql
                .prepare(
                  `INSERT INTO ${table}(${keys.join(',')}) VALUES(${keys.map(() => '?').join(',')})`,
                )
                .run(...keys.map((k) => row[k] as string | number | null));
            }
          }
          const before = tables.map((table) => sql.prepare(`SELECT * FROM ${table}`).all());
          const schema = sql
            .prepare(
              "SELECT name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY name",
            )
            .all();
          sql.exec('BEGIN IMMEDIATE');
          sql.exec(await readFile(new URL('0005_work_sources.sql', directory), 'utf8'));
          sql.exec('COMMIT');
          tables.forEach((table, i) =>
            assert.deepEqual(sql.prepare(`SELECT * FROM ${table}`).all(), before[i]),
          );
          for (const row of schema)
            assert.equal(
              sql.prepare('SELECT sql FROM sqlite_master WHERE name=?').get(row.name as string)!
                .sql,
              row.sql,
            );
          assert.equal(sql.prepare('SELECT count(*) AS n FROM work_source_access').get()!.n, 0);
          assert.equal(sql.prepare('PRAGMA integrity_check').get()!.integrity_check, 'ok');
          assert.deepEqual(sql.prepare('PRAGMA foreign_key_check').all(), []);
        } finally {
          sql.close();
        }
      },
    );
    await t.test(
      'a retired source cannot reactivate the same revision or satisfy a stale read',
      async () => {
        await f.register('head-transition', f.first);
        await f.DB.prepare(
          "UPDATE work_source_head SET active=0 WHERE source_id='head-transition'",
        ).run();
        await assert.rejects(
          f.DB.prepare(
            "UPDATE work_source_head SET active=1 WHERE source_id='head-transition'",
          ).run(),
        );
        const receipt = JSON.parse(
          (await f.DB.prepare(
            "SELECT body FROM work_source_version WHERE source_id='head-transition'",
          ).first('body')) as string,
        );
        receipt.data.data.source_revision = 2;
        await f.DB.prepare('INSERT INTO work_source_version VALUES(?,?,?)')
          .bind('head-transition', 2, JSON.stringify(receipt))
          .run();
        await f.DB.prepare(
          "UPDATE work_source_head SET active=1,source_revision=2 WHERE source_id='head-transition'",
        ).run();
        assert.equal((await read(f.input('head-transition'))).status, 409);
      },
    );
    await t.test(
      'current policy changes during RPC invalidate its earlier permission snapshot',
      async () => {
        await f.fault('personal', 'policy');
        const response = await read(f.input());
        assert.equal(response.status, 409);
        assert.equal((await response.text()).includes('結論から'), false);
      },
    );
  } finally {
    await f.close();
  }
});
