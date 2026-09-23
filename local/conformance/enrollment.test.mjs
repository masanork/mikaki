import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { createTestHarness } from 'wrangler';
import { issueBootstrapInvite } from '../../scripts/enrollment-store.mjs';

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
