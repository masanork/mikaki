import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash, randomBytes } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';
import { createTestHarness } from 'wrangler';
import { OWNER_MIGRATIONS } from '../../scripts/production-owner-schema.ts';
import { setClientEmailPolicy } from '../../scripts/client-admin-store.ts';

test('email release requires matching account, client, connection and consent revisions', () => {
  const db = new DatabaseSync(':memory:');
  try {
    db.exec('PRAGMA foreign_keys=ON');
    for (const { name } of OWNER_MIGRATIONS)
      db.exec(readFileSync(`crates/worker/migrations/${name}`, 'utf8'));
    db.exec(`
      INSERT INTO account_security(account_id,epoch,active) VALUES('a',1,1),('b',1,1);
      INSERT INTO client(client_id,revision,active,sector_identifier) VALUES('rp',1,1,'rp.example'),('other',1,1,'other.example');
      INSERT INTO app_connection(account_id,client_id,grant_version,active) VALUES('a','rp',1,1),('b','other',1,1);
      INSERT INTO account_verified_email VALUES('a','owner@example.org',1,1,10,1);
      INSERT INTO client_email_policy VALUES('rp',1,1);
      INSERT INTO account_email_release(account_id,client_id,email_revision,account_epoch,client_revision,grant_version,active) VALUES('a','rp',1,1,1,1,1);
    `);
    const result = () =>
      db.prepare('SELECT account_id,client_id,email FROM eligible_verified_email_release').all();
    assert.deepEqual(
      result().map((row) => ({ ...row })),
      [{ account_id: 'a', client_id: 'rp', email: 'owner@example.org' }],
    );
    for (const mutation of [
      "UPDATE account_verified_email SET active=0,revision=revision+1 WHERE account_id='a'",
      "UPDATE account_verified_email SET email='new@example.org',revision=revision+1 WHERE account_id='a'",
      "UPDATE account_security SET epoch=epoch+1 WHERE account_id='a'",
      "UPDATE account_security SET active=0 WHERE account_id='a'",
      "UPDATE client SET active=0,revision=revision+1 WHERE client_id='rp'",
      "UPDATE client SET revision=revision+1 WHERE client_id='rp'",
      "UPDATE client_email_policy SET enabled=0 WHERE client_id='rp'",
      "UPDATE account_email_release SET active=0,revision=revision+1 WHERE account_id='a' AND client_id='rp'",
      "UPDATE app_connection SET grant_version=grant_version+1 WHERE account_id='a' AND client_id='rp'",
      "UPDATE app_connection SET active=0 WHERE account_id='a' AND client_id='rp'",
    ]) {
      db.exec('SAVEPOINT scenario');
      db.exec(mutation);
      assert.equal(result().length, 0, mutation);
      db.exec('ROLLBACK TO scenario; RELEASE scenario');
    }
    const before = db
      .prepare(
        "SELECT email_revision,release_revision FROM eligible_verified_email_release WHERE account_id='a' AND client_id='rp'",
      )
      .get()!;
    db.exec(
      "UPDATE account_email_release SET active=0,revision=revision+1 WHERE account_id='a' AND client_id='rp'; UPDATE account_email_release SET active=1,revision=revision+1 WHERE account_id='a' AND client_id='rp'",
    );
    assert.equal(
      db
        .prepare(
          "SELECT count(*) AS n FROM eligible_verified_email_release WHERE account_id='a' AND client_id='rp' AND email_revision=? AND release_revision=?",
        )
        .get(before.email_revision, before.release_revision)!.n,
      0,
    );
    assert.throws(() =>
      db.exec("UPDATE account_verified_email SET email='new@example.org' WHERE account_id='a'"),
    );
    db.exec(`INSERT INTO account_email_challenge(challenge_hash,account_id,email,account_epoch,expected_revision,expires_at) VALUES('${'x'.repeat(43)}','a','new@example.org',1,1,100);
      UPDATE account_email_challenge SET consumed_at=50 WHERE account_id='a';`);
    assert.throws(() =>
      db.exec("UPDATE account_email_challenge SET consumed_at=60 WHERE account_id='a'"),
    );
  } finally {
    db.close();
  }
});

test('confirmation requires owner session, unexpired challenge and exactly one winner', async () => {
  const harness = createTestHarness({
    root: new URL('../..', import.meta.url).pathname,
    workers: [
      {
        configPath: new URL('../../crates/worker/wrangler.jsonc', import.meta.url).pathname,
        vars: { MIKAKI_VERIFIED_EMAIL: 'on' },
      },
    ],
  });
  try {
    await harness.listen();
    const worker = harness.getWorker('mikaki-op-worker');
    await worker.applyD1Migrations('DB');
    const { DB } = await worker.getEnv();
    const now = Math.floor(Date.now() / 1000);
    const hash = (s: string) => createHash('sha256').update(s).digest('base64url');
    const token = randomBytes(32).toString('base64url');
    const cookie = randomBytes(32).toString('base64url');
    await DB.batch([
      DB.prepare("INSERT INTO account_security(account_id,epoch,active) VALUES('a',1,1),('b',1,1)"),
      DB.prepare("INSERT INTO credential(credential_id,account_id,active) VALUES('cred','a',1)"),
      DB.prepare(
        "INSERT INTO sso_session(sso_id,account_id,credential_id,epoch,expires_at,revoked) VALUES('s','a','cred',1,?,0)",
      ).bind(now + 600),
      DB.prepare("INSERT INTO sso_context(sso_id,secret_hash,auth_time) VALUES('s',?,?)").bind(
        hash(cookie),
        now,
      ),
      DB.prepare(
        "INSERT INTO account_email_challenge(challenge_hash,account_id,email,account_epoch,expected_revision,expires_at) VALUES(?,'a','owner@example.org',1,0,?)",
      ).bind(hash(token), now + 300),
    ]);
    const confirm = (t: string, c = cookie, origin = 'https://issuer.example') =>
      worker.fetch('https://issuer.example/account/email/confirm', {
        method: 'POST',
        headers: { origin, cookie: `__Host-op-sso=${c}`, 'content-type': 'application/json' },
        body: JSON.stringify({ token: t }),
      });
    const status = () =>
      worker.fetch('https://issuer.example/account/email', {
        headers: { cookie: `__Host-op-sso=${cookie}` },
      });
    assert.equal((await (await status()).json()).email, null);
    assert.equal((await confirm(token, cookie, 'https://wrong.example')).status, 403);
    assert.equal((await confirm(token, 'wrong')).status, 401);
    assert.equal((await confirm(randomBytes(32).toString('base64url'))).status, 409);
    const responses = await Promise.all([confirm(token), confirm(token)]);
    assert.deepEqual(responses.map((r) => r.status).sort(), [200, 409]);
    const row = await DB.prepare(
      "SELECT email,revision,account_epoch,active FROM account_verified_email WHERE account_id='a'",
    ).first();
    assert.equal(row.email, 'owner@example.org');
    assert.equal(row.revision, 1);
    assert.equal(row.active, 1);
    assert.equal((await confirm(token)).status, 409);
    await DB.batch([
      DB.prepare(
        "INSERT INTO client(client_id,revision,active,sector_identifier) VALUES('rp',1,1,'rp.example')",
      ),
      DB.prepare(
        "INSERT INTO app_connection(account_id,client_id,grant_version,active) VALUES('a','rp',1,1)",
      ),
    ]);
    const release = (action: string, client_id = 'rp', origin = 'https://issuer.example') =>
      worker.fetch('https://issuer.example/account/email/release', {
        method: 'POST',
        headers: { origin, cookie: `__Host-op-sso=${cookie}`, 'content-type': 'application/json' },
        body: JSON.stringify({ action, client_id }),
      });
    assert.equal((await release('grant')).status, 409);
    await setClientEmailPolicy(
      DB,
      'rp',
      { enabled: true, expected_client_revision: 1 },
      'operator',
      'test',
    );
    await assert.rejects(
      setClientEmailPolicy(
        DB,
        'rp',
        { enabled: false, expected_client_revision: 1 },
        'operator',
        'stale',
      ),
    );
    assert.equal((await release('grant', 'rp', 'https://evil.example')).status, 403);
    assert.equal((await release('grant', 'other')).status, 409);
    assert.equal((await release('grant')).status, 200);
    const statusBody = await (await status()).json();
    assert.equal(statusBody.email.email, 'owner@example.org');
    assert.equal(statusBody.clients[0].released, 1);
    assert.equal(
      (await DB.prepare('SELECT count(*) AS n FROM eligible_verified_email_release').first()).n,
      1,
    );
    await setClientEmailPolicy(
      DB,
      'rp',
      { enabled: false, expected_client_revision: 2 },
      'operator',
      'disable',
    );
    assert.equal(
      (await DB.prepare('SELECT count(*) AS n FROM eligible_verified_email_release').first()).n,
      0,
    );
    await setClientEmailPolicy(
      DB,
      'rp',
      { enabled: true, expected_client_revision: 3 },
      'operator',
      're-enable',
    );
    assert.equal(
      (await DB.prepare('SELECT count(*) AS n FROM eligible_verified_email_release').first()).n,
      0,
    );
    assert.equal((await release('revoke')).status, 200);
    assert.equal(
      (await DB.prepare('SELECT count(*) AS n FROM eligible_verified_email_release').first()).n,
      0,
    );
    const expired = randomBytes(32).toString('base64url');
    await DB.prepare(
      "INSERT INTO account_email_challenge(challenge_hash,account_id,email,account_epoch,expected_revision,expires_at) VALUES(?,'a','new@example.org',1,1,?)",
    )
      .bind(hash(expired), now - 1)
      .run();
    assert.equal((await confirm(expired)).status, 409);
    const foreign = randomBytes(32).toString('base64url');
    await DB.prepare(
      "INSERT INTO account_email_challenge(challenge_hash,account_id,email,account_epoch,expected_revision,expires_at) VALUES(?,'b','foreign@example.org',1,0,?)",
    )
      .bind(hash(foreign), now + 300)
      .run();
    assert.equal((await confirm(foreign)).status, 409);
    const stale = randomBytes(32).toString('base64url');
    await DB.prepare(
      "INSERT INTO account_email_challenge(challenge_hash,account_id,email,account_epoch,expected_revision,expires_at) VALUES(?,'a','stale@example.org',1,0,?)",
    )
      .bind(hash(stale), now + 300)
      .run();
    assert.equal((await confirm(stale)).status, 409);
    const epoch = randomBytes(32).toString('base64url');
    await DB.prepare(
      "INSERT INTO account_email_challenge(challenge_hash,account_id,email,account_epoch,expected_revision,expires_at) VALUES(?,'a','epoch@example.org',1,1,?)",
    )
      .bind(hash(epoch), now + 300)
      .run();
    const removal = await worker.fetch('https://issuer.example/account/email/remove', {
      method: 'POST',
      headers: { origin: 'https://issuer.example', cookie: `__Host-op-sso=${cookie}` },
    });
    assert.equal(removal.status, 200);
    assert.equal((await (await status()).json()).email, null);
    const removed = await DB.prepare(
      "SELECT email,active,revision FROM account_verified_email WHERE account_id='a'",
    ).first();
    assert.equal(removed.email, 'removed');
    assert.equal(removed.active, 0);
    assert.equal(removed.revision, 2);
    assert.equal(
      (
        await DB.prepare(
          "SELECT count(*) AS n FROM account_email_challenge WHERE account_id='a'",
        ).first()
      ).n,
      0,
    );
    assert.equal((await confirm(epoch)).status, 409);
    await DB.prepare("UPDATE account_security SET epoch=2 WHERE account_id='a'").run();
    assert.equal((await confirm(epoch)).status, 401);
  } finally {
    await harness.close();
  }
});

test('D1 refuses stale email grants and preserves one-use challenge state', async () => {
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
    await DB.batch([
      DB.prepare("INSERT INTO account_security(account_id,epoch,active) VALUES('a',1,1)"),
      DB.prepare(
        "INSERT INTO client(client_id,revision,active,sector_identifier) VALUES('rp',1,1,'rp.example')",
      ),
      DB.prepare(
        "INSERT INTO app_connection(account_id,client_id,grant_version,active) VALUES('a','rp',1,1)",
      ),
      DB.prepare("INSERT INTO account_verified_email VALUES('a','owner@example.org',1,1,10,1)"),
      DB.prepare("INSERT INTO client_email_policy VALUES('rp',1,1)"),
      DB.prepare(
        "INSERT INTO account_email_release(account_id,client_id,email_revision,account_epoch,client_revision,grant_version,active) VALUES('a','rp',1,1,1,1,1)",
      ),
      DB.prepare(
        "INSERT INTO account_email_challenge(challenge_hash,account_id,email,account_epoch,expected_revision,expires_at) VALUES(?,'a','new@example.org',1,1,100)",
      ).bind('x'.repeat(43)),
    ]);
    assert.equal(
      (await DB.prepare('SELECT count(*) AS n FROM eligible_verified_email_release').first()).n,
      1,
    );
    await DB.batch([
      DB.prepare(
        "UPDATE account_verified_email SET email='new@example.org',revision=2 WHERE account_id='a' AND revision=1",
      ),
      DB.prepare(
        "UPDATE account_email_challenge SET consumed_at=50 WHERE account_id='a' AND consumed_at IS NULL",
      ),
    ]);
    assert.equal(
      (await DB.prepare('SELECT count(*) AS n FROM eligible_verified_email_release').first()).n,
      0,
    );
    await assert.rejects(
      DB.prepare("UPDATE account_email_challenge SET consumed_at=60 WHERE account_id='a'").run(),
    );
  } finally {
    await harness.close();
  }
});

test('start delivers through local simulator, supersedes prior challenge and limits retries', async () => {
  const harness = createTestHarness({
    root: new URL('../..', import.meta.url).pathname,
    workers: [
      {
        configPath: new URL('../../crates/worker/wrangler.jsonc', import.meta.url).pathname,
        vars: { MIKAKI_VERIFIED_EMAIL: 'on' },
      },
    ],
  });
  try {
    await harness.listen();
    const worker = harness.getWorker('mikaki-op-worker');
    await worker.applyD1Migrations('DB');
    const { DB } = await worker.getEnv();
    const now = Math.floor(Date.now() / 1000);
    const cookie = randomBytes(32).toString('base64url');
    const digest = createHash('sha256').update(cookie).digest('base64url');
    await DB.batch([
      DB.prepare("INSERT INTO account_security(account_id,epoch,active) VALUES('a',1,1)"),
      DB.prepare("INSERT INTO credential(credential_id,account_id,active) VALUES('cred','a',1)"),
      DB.prepare(
        "INSERT INTO sso_session(sso_id,account_id,credential_id,epoch,expires_at,revoked) VALUES('s','a','cred',1,?,0)",
      ).bind(now + 600),
      DB.prepare("INSERT INTO sso_context(sso_id,secret_hash,auth_time) VALUES('s',?,?)").bind(
        digest,
        now,
      ),
      DB.prepare(
        "INSERT INTO account_email_challenge(challenge_hash,account_id,email,account_epoch,expected_revision,expires_at) VALUES(?,'a','old@example.org',1,0,?)",
      ).bind('x'.repeat(43), now + 300),
    ]);
    const start = (email: string) =>
      worker.fetch('https://issuer.example/account/email/start', {
        method: 'POST',
        headers: {
          origin: 'https://issuer.example',
          cookie: `__Host-op-sso=${cookie}`,
          'content-type': 'application/json',
        },
        body: JSON.stringify({ email }),
      });
    assert.equal((await start('bad address')).status, 400);
    assert.equal((await start('Case@example.org')).status, 202);
    assert.equal((await start('other@example.org')).status, 429);
    const rows = (
      await DB.prepare(
        'SELECT email,challenge_hash,consumed_at FROM account_email_challenge ORDER BY email',
      ).all()
    ).results;
    assert.equal(rows.length, 2);
    assert.ok(rows.find((r: any) => r.email === 'old@example.org').consumed_at);
    assert.equal(rows.find((r: any) => r.email === 'Case@example.org').challenge_hash.length, 43);
    assert.equal(
      (await DB.prepare('SELECT count(*) AS n FROM account_verified_email').first()).n,
      0,
    );
    await DB.prepare(
      "INSERT INTO account_email_challenge(challenge_hash,account_id,email,account_epoch,expected_revision,expires_at) VALUES(?,'a','expired@example.org',1,0,?)",
    )
      .bind('z'.repeat(43), now - 90000)
      .run();
    await worker.scheduled({ cron: '* * * * *', scheduledTime: new Date() });
    assert.equal(
      (
        await DB.prepare('SELECT count(*) AS n FROM account_email_challenge WHERE challenge_hash=?')
          .bind('z'.repeat(43))
          .first()
      ).n,
      0,
    );
  } finally {
    await harness.close();
  }
});
