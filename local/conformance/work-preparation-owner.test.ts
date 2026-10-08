import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { gzipSync } from 'node:zlib';
import { createSourceFixture } from './support/work-source-fixture.ts';
import { seedPreparationReview } from './support/work-preparation-review-fixture.ts';
import { preparationFixture } from './support/work-preparation-fixture.ts';

test('preparation review is private, paged, historical and independent of grant issuance', async (t) => {
  const f = await createSourceFixture(undefined, true);
  try {
    const s = await seedPreparationReview(f);
    const json = async (path: string, o = f.first, target = f.worker) => {
      const r = await f.http(path, o, {}, target);
      return { status: r.status, body: (await r.json()) as any, headers: r.headers };
    };
    await t.test('owner, feature gates, methods, origin and closed query boundaries', async () => {
      for (const path of [
        '/work/preparation-review',
        '/work/preparation-review.js',
        '/work/preparation-review.css',
      ]) {
        const r = await f.http(path);
        assert.equal(r.status, 200);
        assert.equal(r.headers.get('Cache-Control'), 'no-store');
        if (path.endsWith('.js')) {
          const bytes = Buffer.from(await r.arrayBuffer());
          assert.ok(bytes.length <= 196608, 'Preparation JavaScript exceeds 192 KiB');
          assert.ok(gzipSync(bytes).length <= 65536, 'Preparation gzip estimate exceeds 64 KiB');
          t.diagnostic(
            `Preparation UI: ${bytes.length} raw / ${gzipSync(bytes).length} gzip estimate`,
          );
        } else if (path.endsWith('.css'))
          assert.ok(
            (await r.arrayBuffer()).byteLength <= 48128,
            'Preparation CSS exceeds product budget',
          );
        assert.equal((await f.http(path, f.first, {}, f.disabled)).status, 404);
        assert.equal((await f.worker.fetch('https://work.test' + path)).status, 401);
        assert.equal((await f.http(path, f.first, { method: 'POST', body: '{}' })).status, 404);
        assert.equal(
          (await f.http(path, f.first, { headers: { Origin: 'https://evil.test' } })).status,
          403,
        );
        assert.equal((await f.http(path + '?after=x')).status, 400);
      }
      for (const q of ['after=', 'after=x&after=y', 'owner=foreign', 'limit=100', 'after=bad%2fid'])
        assert.equal((await json('/work/preparations?' + q)).status, 400);
      assert.equal((await f.http('/work/preparation-review?lang=ja&lang=en')).status, 400);
      assert.equal((await f.http('/work/preparation-review?lang=xx')).status, 400);
      assert.equal((await json('/work/preparations', f.foreign)).body.preparations.length, 0);
      assert.equal((await json('/work/preparations/' + s.reserved.id, f.foreign)).status, 404);
    });
    await t.test(
      'bounded keyset projections never disclose body, bearer material or foreign rows',
      async () => {
        await f.DB.prepare(
          'UPDATE work_preparation_policy SET retained_per_owner=32,creations_per_hour=32 WHERE id=1',
        ).run();
        for (let i = 0; i < 21; i++) {
          const d = await s.call({
            action: 'disclosure',
            disclosure: f.disclosure,
            expires_at: Math.floor(Date.now() / 1000) + 700 + i,
          });
          await s.reserve('paged-task-' + i, d.digest);
        }
        const page = await json('/work/preparations');
        assert.equal(page.body.preparations.length, 20);
        const next = await json('/work/preparations?after=' + page.body.next_after);
        assert.equal(next.body.preparations.length, 2);
        assert.equal(next.body.next_after, null);
        const all = [...page.body.preparations, ...next.body.preparations];
        assert.equal(new Set(all.map((p) => p.id)).size, 22);
        assert.equal(JSON.stringify(all).includes(f.first.hash), false);
        assert.equal(
          all.some((p) => Object.hasOwn(p, 'body') || Object.hasOwn(p, 'evidence')),
          false,
        );
        assert.equal(
          (await json('/work/preparations/' + s.reserved.id, f.first, f.b)).body.record.preparation
            .state,
          'reserved',
        );
      },
    );
    await t.test(
      'verified history remains visible while current authority is false after source revocation',
      async () => {
        await s.verify(s.reserved.id);
        const p = (await json('/work/preparations/' + s.reserved.id)).body.record.preparation;
        assert.equal(p.state, 'verified');
        assert.equal(p.materialized, false);
        assert.equal(p.current_authority, false);
        await s.call({ action: 'materialize-preparation', id: s.reserved.id });
        assert.equal(
          (await json('/work/preparations/' + s.reserved.id)).body.record.preparation
            .current_authority,
          true,
        );
        await f.DB.prepare(
          "UPDATE work_source_access SET active=0,access_revision=access_revision+1 WHERE owner_id=? AND source_id='personal'",
        )
          .bind(f.first.account)
          .run();
        const history = (await json('/work/preparations/' + s.reserved.id)).body.record.preparation;
        assert.equal(history.state, 'verified');
        assert.equal(history.materialized, true);
        assert.equal(history.current_authority, false);
        assert.equal(await f.DB.prepare('SELECT count(*) AS n FROM work_grant').first('n'), 0);
        await f.DB.prepare('UPDATE sso_session SET revoked=1 WHERE account_id=?')
          .bind(f.first.account)
          .run();
        assert.equal((await json('/work/preparations')).status, 401);
      },
    );
  } finally {
    await f.close();
  }
});

test('preparation listing, detail, manifest and private shell refuse frozen checkpoint authority', async () => {
  const source = await createSourceFixture();
  const directory = await mkdtemp(join(tmpdir(), 'mikaki-preparation-owner-'));
  const f = await preparationFixture(
    directory,
    { WORK_SOURCE_API_ENABLED: 'true', WORK_PREPARATION_REVIEW_ENABLED: 'true' },
    true,
  );
  try {
    const p = await f.initialize(source.disclosure);
    const paths = [
      '/work/preparations',
      '/work/preparations/' + p.id,
      '/work/disclosures/pending',
      '/work/preparation-review',
      '/work/preparation-review.js',
      '/work/preparation-review.css',
    ];
    // Obtain the exact digest from the authenticated Native projection.
    const detail = await f.ownerRead('/work/preparations/' + p.id);
    paths[2] = '/work/disclosures/' + (detail.body.record as any).preparation.disclosure_digest;
    for (const path of paths)
      assert.equal(
        (await f.request(path, { headers: { Cookie: '__Host-op-sso=synthetic-delivery-session' } }))
          .status,
        200,
      );
    const frozen = await f.request('/checkpoint-fixture', {
      method: 'POST',
      body: JSON.stringify({ action: 'freeze' }),
    });
    assert.equal(frozen.status, 200);
    for (const path of paths)
      assert.equal(
        (await f.request(path, { headers: { Cookie: '__Host-op-sso=synthetic-delivery-session' } }))
          .status,
        409,
      );
  } finally {
    await f.close();
    await source.close();
    await rm(directory, { recursive: true, force: true });
  }
});
