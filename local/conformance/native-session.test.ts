import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHash, randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { createTestHarness } from 'wrangler';
import { activateWorkerPolicy } from '../../scripts/worker-policy-store.ts';

const issuer = 'https://mikaki.test';
const registration = JSON.parse(
  await readFile(
    new URL('../../apps/mikaki-client/mobile-client-registration.json', import.meta.url),
    'utf8',
  ),
);

test('first-party native account uses the OIDC pairwise namespace and fails closed on every live-session or registration change', async () => {
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
    await activateWorkerPolicy(
      DB,
      JSON.parse(
        await readFile(new URL('../generated/worker-policy.json', import.meta.url), 'utf8'),
      ),
      { actor: 'native-session-test', reason: 'first-party app session' },
    );
    const cookie = randomBytes(32).toString('base64url');
    const now = Math.floor(Date.now() / 1000);
    await DB.batch([
      DB.prepare("INSERT INTO account_security VALUES('owner',1,1)"),
      DB.prepare("INSERT INTO credential VALUES('credential','owner',1)"),
      DB.prepare("INSERT INTO sso_session VALUES('sso','owner','credential',1,?,0)").bind(
        now + 3600,
      ),
      DB.prepare("INSERT INTO sso_context VALUES('sso',?,?)").bind(
        createHash('sha256').update(cookie).digest('base64url'),
        now,
      ),
      DB.prepare(
        "INSERT INTO client(client_id,revision,active,client_type,auth_method,sector_identifier) VALUES(?,1,1,'native','none',?)",
      ).bind(registration.client_id, registration.sector_identifier),
      DB.prepare('INSERT INTO client_redirect_uri(client_id,redirect_uri) VALUES(?,?)').bind(
        registration.client_id,
        registration.redirect_uris[0],
      ),
    ]);
    const request = (origin: string | null = issuer, native = true, secret = cookie) =>
      worker.fetch(`${issuer}/native/session`, {
        method: 'POST',
        headers: {
          ...(origin ? { Origin: origin } : {}),
          ...(native ? { 'X-Mikaki-App': '1' } : {}),
          Cookie: `__Host-op-sso=${secret}`,
        },
      });
    assert.equal((await request(null)).status, 403);
    assert.equal((await request('https://evil.test')).status, 403);
    assert.equal(
      (
        await worker.fetch('https://evil.test/native/session', {
          method: 'POST',
          headers: {
            Origin: 'https://evil.test',
            'X-Mikaki-App': '1',
            Cookie: `__Host-op-sso=${cookie}`,
          },
        })
      ).status,
      404,
    );
    assert.equal(
      (
        await worker.fetch(`${issuer}/native/session?client_id=foreign`, {
          method: 'POST',
          headers: { Origin: issuer, 'X-Mikaki-App': '1', Cookie: `__Host-op-sso=${cookie}` },
        })
      ).status,
      400,
    );
    assert.equal((await request(issuer, false)).status, 403);
    assert.equal((await request(issuer, true, randomBytes(32).toString('base64url'))).status, 401);
    assert.equal((await worker.fetch(`${issuer}/native/session`)).status, 405);
    const first = await request();
    assert.equal(first.status, 200);
    assert.equal(first.headers.get('cache-control'), 'no-store');
    assert.equal(first.headers.get('access-control-allow-origin'), null);
    assert.equal(first.headers.get('set-cookie'), null);
    const projection = (await first.json()) as {
      subject: string;
      expires_at: number;
      client_id: string;
    };
    assert.deepEqual(Object.keys(projection).sort(), ['client_id', 'expires_at', 'subject']);
    assert.match(projection.subject, /^[A-Za-z0-9_-]{43}$/);
    assert.equal(projection.expires_at, now + 3600);
    assert.equal(projection.client_id, registration.client_id);
    assert.deepEqual(await (await request()).json(), projection);
    const subjects = await DB.prepare(
      'SELECT account_id,sector_identifier,sub FROM pairwise_subject',
    ).all();
    assert.deepEqual(subjects.results, [
      {
        account_id: 'owner',
        sector_identifier: registration.sector_identifier,
        sub: projection.subject,
      },
    ]);
    // Existing OIDC custody must remain addressable, without migrating to raw account IDs.
    const existing = randomBytes(32).toString('base64url');
    await DB.prepare("UPDATE pairwise_subject SET sub=? WHERE account_id='owner'")
      .bind(existing)
      .run();
    assert.equal(((await (await request()).json()) as typeof projection).subject, existing);
    for (const [change, restore] of [
      ['UPDATE sso_session SET revoked=1', 'UPDATE sso_session SET revoked=0'],
      ['UPDATE sso_session SET expires_at=1', `UPDATE sso_session SET expires_at=${now + 3600}`],
      ['UPDATE account_security SET epoch=2', 'UPDATE account_security SET epoch=1'],
      ['UPDATE account_security SET active=0', 'UPDATE account_security SET active=1'],
      ['UPDATE credential SET active=0', 'UPDATE credential SET active=1'],
      [
        "UPDATE client SET active=0,revision=revision+1 WHERE client_type='native'",
        "UPDATE client SET active=1,revision=revision+1 WHERE client_type='native'",
      ],
      [
        "UPDATE client SET revision=revision+1,sector_identifier='wrong.example' WHERE client_type='native'",
        "UPDATE client SET revision=revision+1,sector_identifier='app.mikaki.org' WHERE client_type='native'",
      ],
      ['UPDATE client_redirect_uri SET active=0', 'UPDATE client_redirect_uri SET active=1'],
    ]) {
      await DB.prepare(change).run();
      assert.equal((await request()).status, 401, change);
      await DB.prepare(restore).run();
      assert.equal((await request()).status, 200, restore);
    }
  } finally {
    await harness.close();
  }
});
