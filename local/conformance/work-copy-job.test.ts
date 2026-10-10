/** Actual product Rust/Wasm/D1, Workflows engine and loopback Git. Provider
 * identities and local SSO are synthetic; no real Artifacts operation occurs. */
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { copyJobFixture as fixture } from './support/work-copy-job-fixture.ts';
import { copyHttpPort } from '../../crates/worker/ui/work-copy-view.ts';
test('one owner start drives both real Git copies and six closures without a grant', async () => {
  const f = await fixture();
  try {
    assert.equal((await f.start()).status, 409);
    assert.equal((await f.remote()).counts.create ?? 0, 0);
    assert.equal((await f.approve()).status, 200);
    assert.equal((await f.copy()).body.record.can_start, true);
    const r = await f.start();
    assert.equal(r.status, 200);
    const end = await f.settled();
    assert.equal(end.job.state, 'verified');
    assert.equal(end.job.next_step, 19);
    const remote = await f.remote();
    assert.equal(remote.counts.create, 2);
    assert.equal(remote.counts.mint, 4);
    assert.equal(remote.repos.length, 2);
    assert.ok(remote.repos.every((r: any) => r.tokens.every((t: any) => t.state !== 'active')));
    assert.equal(
      await f.DB.prepare(
        "SELECT count(*) AS n FROM work_credential_attempt WHERE state='closed' AND confirmation='refused' AND envelope IS NULL",
      ).first('n'),
      6,
    );
    for (const table of ['work_request', 'work_prepared_task', 'work_grant', 'work_run'])
      assert.equal(await f.DB.prepare('SELECT count(*) AS n FROM ' + table).first('n'), 0);
    assert.equal(
      await f.DB.prepare("SELECT count(*) AS n FROM work_audit WHERE action='copy.queue'").first(
        'n',
      ),
      1,
    );
    const before = JSON.stringify((await f.remote()).counts);
    const repeated = await f.copyPrivate({ action: 'advance', preparation_id: f.p.id, step: 0 });
    assert.equal(repeated.status, 200);
    assert.equal(JSON.stringify((await f.remote()).counts), before);
    const port = copyHttpPort(async (path) => {
      const r = await f.product(String(path));
      return Response.json(r.body, { status: r.status });
    });
    assert.equal((await port.read(f.p.id, new AbortController().signal)).job?.state, 'verified');
    assert.doesNotMatch(JSON.stringify(end), /SECRET|plaintext|token_id|envelope/);
  } finally {
    await f.close();
  }
});

test('queued outbox retries retain one identity, reject browser assertions, and stop without effects', async () => {
  const f = await fixture({ LOCAL_COPY_TRIGGER_DISABLED: 'true' });
  try {
    const path = `/work/preparations/${f.p.id}/copy`;
    const body = { format_version: 1, review_digest: f.digest };
    assert.equal((await f.approve()).status, 200);
    assert.equal((await f.product(path, 'POST', { ...body, account: 'b'.repeat(32) })).status, 400);
    assert.equal(
      (await f.product(path, 'POST', { ...body, review_digest: '0'.repeat(64) })).status,
      409,
    );
    assert.equal((await f.product(path + '?retry=1', 'POST', body)).status, 400);
    for (const headers of [
      { Origin: 'https://evil.test' },
      { Origin: 'null' },
      { 'Sec-Fetch-Site': 'cross-site' },
    ]) {
      const r = await f.productFetch(path, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...headers },
        body: JSON.stringify(body),
      });
      assert.equal(r.status, 403);
      await r.text();
    }
    const unauthenticated = await f.productFetch(path, { headers: { Cookie: '' } });
    assert.equal(unauthenticated.status, 401);
    await unauthenticated.text();
    assert.equal(await f.DB.prepare('SELECT count(*) AS n FROM work_copy_job').first('n'), 0);
    assert.equal((await f.start()).status, 200);
    assert.equal((await f.start()).status, 200);
    const queued = (await f.copy()).body.record;
    assert.equal(queued.job.state, 'queued');
    assert.equal(queued.job.next_step, 0);
    assert.equal(queued.can_start, false);
    assert.equal(
      await f.DB.prepare("SELECT count(*) AS n FROM work_audit WHERE action='copy.queue'").first(
        'n',
      ),
      1,
    );
    const pending = await f.copyPrivate({ action: 'pending' });
    assert.deepEqual(await pending.json(), { preparations: [{ preparation_id: f.p.id }] });
    assert.equal((await f.advance(1)).status, 409);
    assert.equal((await f.stop()).body.record.job.state, 'blocked');
    assert.equal((await f.advance(0)).body.state, 'blocked');
    assert.equal((await f.start()).body.record.job.state, 'blocked');
    assert.equal((await f.remote()).counts.create ?? 0, 0);
    assert.equal(
      await f.DB.prepare('SELECT count(*) AS n FROM work_credential_attempt').first('n'),
      0,
    );
    await assert.rejects(f.DB.prepare('DELETE FROM work_copy_job').run());
    await assert.rejects(
      f.DB.prepare("UPDATE work_copy_job SET state='queued',revision=revision+1").run(),
    );
  } finally {
    await f.close();
  }
});

test('a lost accepted push blocks the same job and closes known credentials without resending Git', async () => {
  const f = await fixture();
  try {
    f.http.setMode('push-lost');
    assert.equal((await f.approve()).status, 200);
    assert.equal((await f.start()).status, 200);
    const end = await f.settled();
    assert.equal(end.job.state, 'blocked');
    assert.equal(end.job.next_step, 3);
    assert.equal(end.cleanup_pending, false);
    assert.equal(f.http.counts.pushes, 1);
    const before = (await f.remote()).counts;
    assert.equal(before.create, 2);
    assert.equal(before.mint, 1);
    assert.ok(
      (await f.remote()).repos.every((r: any) => r.tokens.every((t: any) => t.state !== 'active')),
    );
    f.http.setMode('normal');
    assert.equal((await f.advance(3)).body.state, 'blocked');
    assert.equal((await f.stop()).status, 200);
    assert.equal((await f.stop()).status, 200);
    assert.equal((await f.copy()).body.record.job.state, 'blocked');
    assert.deepEqual((await f.remote()).counts, before);
    assert.equal(f.http.counts.pushes, 1);
    assert.equal(await f.DB.prepare('SELECT count(*) AS n FROM work_grant').first('n'), 0);
    assert.notEqual(
      await f.DB.prepare('SELECT state FROM work_preparation').first('state'),
      'verified',
    );
  } finally {
    await f.close();
  }
});

test('queue audit failure rolls back admission and leaves no Workflow/provider effects', async () => {
  const f = await fixture();
  try {
    assert.equal((await f.approve()).status, 200);
    await f.DB.exec(
      "CREATE TRIGGER copy_queue_abort BEFORE INSERT ON work_audit WHEN NEW.action='copy.queue' BEGIN SELECT RAISE(ABORT,'synthetic copy queue abort'); END;",
    );
    assert.equal((await f.start()).status, 503);
    assert.equal(await f.DB.prepare('SELECT count(*) AS n FROM work_copy_job').first('n'), 0);
    assert.equal((await f.remote()).counts.create ?? 0, 0);
    // A failed covered batch freezes admission; it cannot be retried by resetting
    // the checkpoint or substituting a new Workflow identity.
    await f.DB.exec('DROP TRIGGER copy_queue_abort');
    assert.equal((await f.start()).status, 409);
    assert.equal(await f.DB.prepare('SELECT count(*) AS n FROM work_copy_job').first('n'), 0);
  } finally {
    await f.close();
  }
});

test('withdrawn consent blocks a queued job before dispatch and releases no authority', async () => {
  const f = await fixture({ LOCAL_COPY_TRIGGER_DISABLED: 'true' });
  try {
    assert.equal((await f.approve()).status, 200);
    assert.equal((await f.start()).status, 200);
    assert.equal(
      (
        await f.product(`/work/preparations/${f.p.id}/copy-consent`, 'DELETE', {
          format_version: 1,
          review_digest: f.digest,
        })
      ).status,
      200,
    );
    assert.equal((await f.advance(0)).status, 409);
    assert.equal((await f.start()).status, 409);
    assert.equal((await f.stop()).status, 200);
    assert.equal((await f.copy()).body.record.job.state, 'blocked');
    assert.equal((await f.remote()).counts.create ?? 0, 0);
    assert.equal(await f.DB.prepare('SELECT count(*) AS n FROM work_grant').first('n'), 0);
  } finally {
    await f.close();
  }
});

test('cancel a custodied mint before Git using known-ID safety only', async () => {
  const f = await fixture({ LOCAL_COPY_TRIGGER_DISABLED: 'true' });
  try {
    assert.equal((await f.approve()).status, 200);
    assert.equal((await f.start()).status, 200);
    for (let step = 0; step <= 2; step++)
      assert.equal((await f.advance(step)).body.state, 'running');
    assert.equal((await f.remote()).counts.mint, 1);
    assert.equal(
      await f.DB.prepare(
        "SELECT count(*) AS n FROM work_credential_attempt WHERE state='captured'",
      ).first('n'),
      1,
    );
    const stopped = await f.stop();
    assert.equal(stopped.status, 200);
    assert.equal(stopped.body.record.job.state, 'blocked');
    assert.equal(stopped.body.record.cleanup_pending, false);
    assert.equal(f.http.counts.pushes, 0);
    assert.equal(f.http.counts.fetches, 0);
    assert.equal(
      await f.DB.prepare(
        "SELECT count(*) AS n FROM work_credential_attempt WHERE state='closed' AND envelope IS NULL",
      ).first('n'),
      3,
    );
    assert.ok(
      (await f.remote()).repos.every((r: any) => r.tokens.every((t: any) => t.state !== 'active')),
    );
    const before = (await f.remote()).counts;
    assert.equal((await f.advance(3)).body.state, 'blocked');
    assert.equal((await f.stop()).status, 200);
    assert.deepEqual((await f.remote()).counts, before);
  } finally {
    await f.close();
  }
});

test('two starts and concurrent same-step admission cannot create or mint twice', async () => {
  const f = await fixture({ LOCAL_COPY_TRIGGER_DISABLED: 'true' });
  try {
    assert.equal((await f.approve()).status, 200);
    const starts = await Promise.all([f.start(), f.start()]);
    assert.ok(starts.some((r) => r.status === 200));
    assert.equal(await f.DB.prepare('SELECT count(*) AS n FROM work_copy_job').first('n'), 1);
    const results = await Promise.all([f.advance(0), f.advance(0)]);
    assert.ok(results.every((r) => [200, 409].includes(r.status)));
    assert.ok(((await f.remote()).counts.create ?? 0) <= 1);
    assert.equal((await f.remote()).counts.mint ?? 0, 0);
    assert.equal(await f.DB.prepare('SELECT count(*) AS n FROM work_grant').first('n'), 0);
  } finally {
    await f.close();
  }
});
