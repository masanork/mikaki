import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { createTestHarness } from 'wrangler';
import { activateWorkerPolicy } from '../../scripts/worker-policy-store.ts';
const opaque = () => randomBytes(32).toString('base64url');

test('product ingress budgets are atomic across isolates and expired state converges in bounded batches', async () => {
  const config = JSON.parse(
    await readFile(new URL('../../crates/worker/wrangler.jsonc', import.meta.url), 'utf8'),
  );
  config.name = 'second-op';
  config.main = new URL('../../crates/worker/build/worker/shim.mjs', import.meta.url).pathname;
  config.d1_databases[0].migrations_dir = new URL(
    '../../crates/worker/migrations',
    import.meta.url,
  ).pathname;
  config.vars = { MIKAKI_ISSUER: 'https://auth.test' };
  const harness = createTestHarness({
    root: new URL('../..', import.meta.url).pathname,
    workers: [
      { config },
      {
        configPath: new URL('../../crates/worker/wrangler.jsonc', import.meta.url).pathname,
        vars: { MIKAKI_ISSUER: 'https://auth.test' },
      },
    ],
  });
  try {
    await harness.listen();
    const worker = harness.getWorker('mikaki-op-worker');
    await worker.applyD1Migrations('DB');
    const { DB } = await worker.getEnv();
    await activateWorkerPolicy(
      DB,
      JSON.parse(
        await readFile(new URL('../generated/worker-policy.json', import.meta.url), 'utf8'),
      ),
      { actor: 'resource-test', reason: 'ingress and retention' },
    );
    await DB.prepare(
      'UPDATE auth_resource_policy SET source_per_minute=3,deployment_per_minute=10',
    ).run();
    const second = harness.getWorker('second-op');
    const request = (source: string, target = worker) =>
      target.fetch('https://auth.test/token', {
        method: 'POST',
        headers: { 'CF-Connecting-IP': source },
        body: 'invalid',
      });
    const replies = await Promise.all(
      Array.from({ length: 6 }, (_, i) => request('192.0.2.1', i % 2 ? worker : second)),
    );
    assert.equal(replies.filter((r) => r.status === 429).length, 3);
    for (const r of replies.filter((r) => r.status === 429)) {
      assert.equal(r.headers.get('Retry-After'), '60');
      assert.equal(r.headers.get('Cache-Control'), 'no-store');
    }
    assert.notEqual((await request('192.0.2.2')).status, 429);
    // Fixed windows expire at the minute boundary; old reservations do not pin the next window.
    await DB.prepare('UPDATE auth_request_window SET window_start=window_start-60').run();
    assert.notEqual((await request('192.0.2.1')).status, 429);
    await DB.prepare(
      "INSERT INTO client(client_id,revision,active,sector_identifier) VALUES('rp',1,1,'rp.test')",
    ).run();
    const browser = opaque();
    const insert = (expires: number, browserHash = browser) =>
      DB.prepare(
        "INSERT INTO login_transaction(tx_id,browser_hash,authorization_url,client_id,challenge,expires_at) VALUES(?,?,'https://auth.test/authorize','rp',?,?)",
      ).bind(opaque(), browserHash, opaque(), expires);
    const now = Math.floor(Date.now() / 1000);
    await DB.batch(Array.from({ length: 5 }, () => insert(now + 300)));
    await assert.rejects(insert(now + 300).run(), /auth_capacity_exceeded/);
    await DB.prepare(
      'UPDATE login_transaction SET expires_at=? WHERE tx_id=(SELECT tx_id FROM login_transaction WHERE browser_hash=? LIMIT 1)',
    )
      .bind(now, browser)
      .run();
    await insert(now + 300, browser).run(); // expiry is exclusive at the boundary
    await DB.prepare('UPDATE login_transaction SET consumed=1 WHERE browser_hash=?')
      .bind(browser)
      .run();
    await insert(now + 300).run();
    for (let cycle = 0; cycle < 2; cycle++) {
      await DB.batch(Array.from({ length: 1200 }, () => insert(now - 86401, opaque())));
      for (let batch = 0; batch < 2; batch++) await worker.scheduled({ cron: '* * * * *' });
      assert.equal(
        await DB.prepare('SELECT count(*) AS n FROM login_transaction WHERE expires_at<?')
          .bind(now - 86400)
          .first('n'),
        0,
      );
    }
    assert.equal(
      await DB.prepare(
        'SELECT count(*) AS n FROM login_transaction WHERE expires_at>? AND consumed=0',
      )
        .bind(now)
        .first('n'),
      1,
    );
    // An expired token pins its code/session for 90 days. Pending delivery is
    // preserved until its own deadline plus retention, even when SSO has expired.
    await DB.batch([
      DB.prepare("INSERT INTO account_security VALUES('account',1,1)"),
      DB.prepare("INSERT INTO credential VALUES('credential','account',1)"),
      DB.prepare("INSERT INTO signing_key VALUES('op',1,1,'ES256','{}')"),
      DB.prepare("INSERT INTO app_connection VALUES('account','rp',1,1)"),
      DB.prepare(
        "INSERT INTO client_redirect_uri(client_id,redirect_uri) VALUES('rp','https://rp.test/cb')",
      ),
    ]);
    const old = now - 7776000 - 100;
    for (const [label, expiry] of [
      ['expired', old],
      ['retained', now - 60],
    ] as const) {
      const code = opaque();
      await DB.batch([
        DB.prepare("INSERT INTO sso_session VALUES(?,'account','credential',1,?,1)").bind(
          label,
          old,
        ),
        DB.prepare('INSERT INTO sso_context VALUES(?,?,?)').bind(label, opaque(), old - 60),
        DB.prepare("INSERT INTO client_session VALUES('rp',?,?,'account','sub',1,1)").bind(
          label,
          label,
        ),
        DB.prepare(
          "INSERT INTO authorization_code(code_hash,client_id,sid,client_revision,redirect_uri,pkce_challenge,expires_at,consumed_by,consumed_at) VALUES(?,'rp',?,1,'https://rp.test/cb',?,?,'issued-'||?,?)",
        ).bind(code, label, opaque(), old, label, old - 60),
        DB.prepare('INSERT INTO code_context(code_hash,nonce) VALUES(?,NULL)').bind(code),
        DB.prepare(
          "INSERT INTO token_issue(code_hash,operation_id,access_hash,access_expires_at,signing_kid,issued_at,revoked) VALUES(?,'issued-'||?,?,?,'op',?,1)",
        ).bind(code, label, opaque(), expiry, old - 60),
      ]);
    }
    const event = opaque();
    await DB.batch([
      DB.prepare("INSERT INTO sso_session VALUES('delivery','account','credential',1,?,1)").bind(
        old,
      ),
      DB.prepare("INSERT INTO sso_logout_event VALUES(?,'delivery',?,?)").bind(
        event,
        now - 120,
        now + 3600,
      ),
      DB.prepare(
        "INSERT INTO logout_delivery(event_id,client_id,sid,sub,logout_uri,next_at) VALUES(?,'rp','delivery','sub','https://rp.test/logout',?)",
      ).bind(event, now + 600),
    ]);
    await worker.scheduled({ cron: '* * * * *' });
    assert.equal(
      await DB.prepare("SELECT count(*) AS n FROM sso_session WHERE sso_id='expired'").first('n'),
      0,
    );
    assert.equal(
      await DB.prepare("SELECT count(*) AS n FROM sso_session WHERE sso_id='retained'").first('n'),
      1,
    );
    assert.equal(await DB.prepare('SELECT count(*) AS n FROM logout_delivery').first('n'), 1);
    assert.equal(
      await DB.prepare("SELECT count(*) AS n FROM sso_session WHERE sso_id='delivery'").first('n'),
      1,
    );
    // A partial D1 failure rolls the cleanup batch back and a later run converges.
    await DB.prepare(
      "CREATE TRIGGER fail_gc BEFORE DELETE ON token_issue BEGIN SELECT RAISE(ABORT,'injected cleanup failure'); END",
    ).run();
    await DB.prepare('UPDATE token_issue SET access_expires_at=?').bind(old).run();
    await worker.scheduled({ cron: '* * * * *' });
    assert.equal(await DB.prepare('SELECT count(*) AS n FROM token_issue').first('n'), 1);
    await DB.prepare('DROP TRIGGER fail_gc').run();
    await worker.scheduled({ cron: '* * * * *' });
    assert.equal(await DB.prepare('SELECT count(*) AS n FROM token_issue').first('n'), 0);
    assert.equal((await DB.prepare('PRAGMA foreign_key_check').all()).results.length, 0);
  } finally {
    await harness.close();
  }
});
