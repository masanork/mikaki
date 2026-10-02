import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { createTestHarness } from 'wrangler';
import { issueBootstrapInvite } from '../../scripts/enrollment-store.ts';

test('bootstrap invitation is hashed, single-open, expiring, and permanently closed', async () => {
  const harness = createTestHarness({
    root: new URL('../..', import.meta.url).pathname,
    workers: [
      { configPath: new URL('../../crates/worker/wrangler.jsonc', import.meta.url).pathname },
    ],
  });
  try {
    await harness.listen();
    const worker = harness.getWorker('mikaki-op-worker');
    await worker.applyD1Migrations('DB');
    const { DB } = await worker.getEnv();
    const first = await issueBootstrapInvite(DB, 'operator', 'first enrollment');
    assert.equal(first.invitation.length, 43);
    const firstHash = createHash('sha256').update(first.invitation).digest('base64url');
    assert.equal(
      (await DB.prepare('SELECT invite_hash FROM enrollment_invite').first()).invite_hash,
      firstHash,
    );
    await assert.rejects(issueBootstrapInvite(DB, 'operator', 'parallel issue'));
    const now = Math.floor(Date.now() / 1000);
    await DB.prepare('UPDATE enrollment_invite SET issued_at=?,expires_at=? WHERE invite_hash=?')
      .bind(now - 1000, now - 1, firstHash)
      .run();
    const second = await issueBootstrapInvite(DB, 'operator', 'expired replacement');
    assert.notEqual(second.invitation, first.invitation);
    assert.equal(
      (
        await DB.prepare('SELECT revoked FROM enrollment_invite WHERE invite_hash=?')
          .bind(firstHash)
          .first()
      ).revoked,
      1,
    );
    await DB.prepare('UPDATE bootstrap_state SET closed=1 WHERE id=1').run();
    await assert.rejects(issueBootstrapInvite(DB, 'operator', 'closed bootstrap'));
    assert.equal((await DB.prepare('SELECT COUNT(*) AS n FROM enrollment_invite').first()).n, 2);
    assert.equal(
      (await DB.prepare('SELECT COUNT(*) AS n FROM enrollment_invite_audit').first()).n,
      2,
    );
  } finally {
    await harness.close();
  }
});

test('invitation entry accepts supported locales and binds the registration continuation', async () => {
  const issuer = 'https://mikaki.test';
  const harness = createTestHarness({
    root: new URL('../..', import.meta.url).pathname,
    workers: [
      {
        configPath: new URL('../../crates/worker/wrangler.jsonc', import.meta.url).pathname,
        vars: { MIKAKI_ISSUER: issuer },
      },
    ],
  });
  try {
    await harness.listen();
    const worker = harness.getWorker('mikaki-op-worker');
    await worker.applyD1Migrations('DB');
    const { DB } = await worker.getEnv();
    for (const lang of ['ja', 'en']) {
      const response = await worker.fetch(`${issuer}/enroll?lang=${lang}`, {
        redirect: 'manual',
        headers: { 'Accept-Language': lang === 'ja' ? 'en' : 'ja' },
      });
      assert.equal(response.status, 302);
      const destination = new URL(response.headers.get('location')!);
      assert.equal(destination.searchParams.get('lang'), lang);
      const tx = destination.searchParams.get('tx')!;
      const row = await DB.prepare('SELECT authorization_url FROM login_transaction WHERE tx_id=?')
        .bind(tx)
        .first();
      assert.equal(row.authorization_url, `${issuer}/enroll/complete?lang=${lang}`);
      const screen = await worker.fetch(destination.href, {
        headers: { cookie: response.headers.get('set-cookie')!.split(';')[0] },
      });
      assert.equal(screen.status, 200);
      assert.match(await screen.text(), new RegExp(`<html lang="${lang}">`));
    }
    for (const path of [
      '/enroll?lang=xx',
      '/enroll?lang=en&lang=ja',
      '/enroll?next=https://evil.test/',
    ])
      assert.equal((await worker.fetch(`${issuer}${path}`, { redirect: 'manual' })).status, 400);
    assert.equal(
      (await worker.fetch('https://evil.test/enroll?lang=en', { redirect: 'manual' })).status,
      400,
    );
    assert.equal((await DB.prepare('SELECT count(*) AS n FROM login_transaction').first()).n, 2);
  } finally {
    await harness.close();
  }
});
