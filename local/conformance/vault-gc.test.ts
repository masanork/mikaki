import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createTestHarness } from 'wrangler';

test('candidate GC converges beyond 256 daily updates and survives retries without deleting heads', async () => {
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
    const { DB, VAULT_BLOBS } = await worker.getEnv();
    await DB.prepare("INSERT INTO account_security VALUES('gc-owner',1,1)").run();
    const due = Math.floor(Date.now() / 1000) + 2 * 86400;
    const statements = [];
    statements.push(
      DB.prepare(
        "INSERT INTO vault_owner_key_head VALUES('gc-owner','vault','https://mikaki.test',1,1,2,'PRF-HKDF-SHA256-AES256GCM-v2',?, ?,unixepoch())",
      ).bind('b'.repeat(43), 'c'.repeat(43)),
    );
    for (let i = 0; i < 700; i++) {
      const key = `vault-owner-record/old-${i.toString().padStart(4, '0')}`;
      await VAULT_BLOBS.put(key, 'ciphertext');
      statements.push(
        DB.prepare(
          "INSERT INTO vault_owner_record_head VALUES('gc-owner','vault','personal','record','note',?,1,2,?,?,?,0,1) ON CONFLICT(account_id,vault_id,collection_id,record_id) DO UPDATE SET revision=excluded.revision,object_key=excluded.object_key",
        ).bind(i + 1, key, 'd'.repeat(43), 'e'.repeat(82)),
      );
    }
    await DB.batch(statements);
    await DB.prepare(
      "INSERT INTO vault_gc_candidate VALUES('vault-owner-record/old-0699',1,'pending')",
    ).run();
    await VAULT_BLOBS.put('vault-owner-record/failed-upload', 'orphan');
    await DB.prepare(
      "INSERT INTO vault_gc_candidate VALUES('vault-owner-record/failed-upload',1,'pending')",
    ).run();
    await VAULT_BLOBS.put('vault-owner-record/interrupted', 'orphan');
    await DB.prepare(
      "INSERT INTO vault_gc_candidate VALUES('vault-owner-record/interrupted',1,'deleting')",
    ).run();
    await DB.prepare(
      "INSERT INTO vault_gc_candidate VALUES('vault-owner-record/recent',?,'pending')",
    )
      .bind(due + 60)
      .run();
    await VAULT_BLOBS.put('vault-owner-record/recent', 'recent');
    // An in-flight R2 deletion cannot be raced by installing that key as a head.
    await assert.rejects(
      DB.prepare(
        "UPDATE vault_owner_record_head SET object_key='vault-owner-record/interrupted'",
      ).run(),
      /vault_object_retired/,
    );
    for (let i = 0; i < 3; i++) {
      await worker.scheduled({ cron: '*/10 * * * *', scheduledTime: new Date(due * 1000) });
    }
    assert.equal(await VAULT_BLOBS.get('vault-owner-record/old-0000'), null);
    assert.equal(await VAULT_BLOBS.get('vault-owner-record/old-0697'), null);
    assert.equal(await VAULT_BLOBS.get('vault-owner-record/failed-upload'), null);
    assert.equal(await VAULT_BLOBS.get('vault-owner-record/interrupted'), null);
    assert.ok(await VAULT_BLOBS.get('vault-owner-record/recent'));
    assert.equal(await VAULT_BLOBS.get('vault-owner-record/old-0698'), null);
    assert.ok(await VAULT_BLOBS.get('vault-owner-record/old-0699'));
    assert.equal(
      await DB.prepare(
        'SELECT count(*) AS n FROM vault_gc_candidate WHERE eligible_at<=? AND NOT EXISTS(SELECT 1 FROM vault_owner_record_head h WHERE h.object_key=vault_gc_candidate.object_key AND h.deleted=0)',
      )
        .bind(due)
        .first('n'),
      0,
    );
    assert.equal((await VAULT_BLOBS.list({ limit: 1000 })).objects.length, 2);
  } finally {
    await harness.close();
  }
});
