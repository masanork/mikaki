import assert from 'node:assert/strict';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { createTestHarness } from 'wrangler';
import { registerNativeClient } from '../../scripts/client-admin-store.ts';
import { activateWorkerPolicy } from '../../scripts/worker-policy-store.ts';

const issuer = 'https://mikaki.test';
const callback = 'https://rp.example/callback';
const alternate = 'https://rp.example/other-callback';
const client = randomUUID();
const secret = () => randomBytes(32).toString('base64url');
const hash = (value: string) => createHash('sha256').update(value).digest('base64url');

test('SSO reuses only the reviewed account, callback, scopes and live revisions', async (t) => {
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
      JSON.parse(await readFile('local/generated/worker-policy.json', 'utf8')),
      {
        actor: 'test',
        reason: 'SSO connection review',
      },
    );
    await registerNativeClient(
      DB,
      {
        client_id: client,
        sector_identifier: 'rp.example',
        redirect_uris: [callback, alternate],
      },
      'test',
      'review fixture',
    );
    const now = Math.floor(Date.now() / 1000);
    await DB.batch([
      DB.prepare("INSERT INTO account_security VALUES('account',1,1)"),
      DB.prepare("INSERT INTO credential VALUES('credential','account',1)"),
      DB.prepare(
        'INSERT INTO app_connection(account_id,client_id,grant_version,active) VALUES(?,?,1,1)',
      ).bind('account', client),
      DB.prepare("INSERT INTO sso_session VALUES('sso','account','credential',1,?,0)").bind(
        now + 3600,
      ),
      DB.prepare("INSERT INTO sso_context VALUES('sso',?,?)").bind(hash('cookie'), now),
    ]);
    async function authorize(changes: Record<string, string> = {}, authenticated = true) {
      const url = new URL('/authorize', issuer);
      url.search = new URLSearchParams({
        client_id: client,
        response_type: 'code',
        redirect_uri: callback,
        scope: 'openid',
        state: secret(),
        nonce: secret(),
        code_challenge: hash(secret()),
        code_challenge_method: 'S256',
        ...changes,
      }).toString();
      const response = await worker.fetch(url, {
        redirect: 'manual',
        headers: authenticated ? { cookie: '__Host-op-sso=cookie' } : {},
      });
      assert.equal(response.status, 302, await response.clone().text());
      return { response, url, location: new URL(response.headers.get('location')!) };
    }
    async function approve(redirect = callback, scope = 'openid') {
      // A seeded server approval represents an earlier successful Passkey login.
      // Real finish/enrollment persistence is covered by the browser journey.
      await DB.prepare(
        `UPDATE app_connection SET reviewed_redirect_uri=?,reviewed_scope=?,
        reviewed_client_revision=(SELECT revision FROM client WHERE client_id=?),
        reviewed_grant_version=grant_version WHERE account_id='account' AND client_id=?`,
      )
        .bind(redirect, scope, client, client)
        .run();
    }
    async function assertReview(changes: Record<string, string> = {}) {
      const codeCount = await DB.prepare('SELECT count(*) AS n FROM authorization_code').first('n');
      const pendingCount = await DB.prepare('SELECT count(*) AS n FROM login_transaction').first(
        'n',
      );
      const silent = await authorize({ ...changes, prompt: 'none' });
      assert.equal(silent.location.searchParams.get('error'), 'consent_required');
      assert.equal(silent.location.searchParams.get('code'), null);
      assert.equal(silent.location.searchParams.get('state'), silent.url.searchParams.get('state'));
      assert.equal(silent.location.searchParams.get('iss'), issuer);
      assert.equal(
        await DB.prepare('SELECT count(*) AS n FROM login_transaction').first('n'),
        pendingCount,
        'silent requests must not start an interactive transaction',
      );
      const interactive = await authorize(changes);
      assert.equal(interactive.location.origin + interactive.location.pathname, `${issuer}/login`);
      const cookie = interactive.response.headers.get('set-cookie')!.split(';')[0];
      const screen = await worker.fetch(interactive.location, { headers: { cookie } });
      assert.equal(screen.status, 200);
      assert.match(await screen.text(), /data-connection-review-required="true"/);
      const tx = interactive.location.searchParams.get('tx');
      const row = await DB.prepare(
        'SELECT client_revision,connection_review_required FROM login_transaction WHERE tx_id=?',
      )
        .bind(tx)
        .first();
      assert.equal(row.connection_review_required, 1);
      assert.equal(
        row.client_revision,
        await DB.prepare('SELECT revision FROM client WHERE client_id=?')
          .bind(client)
          .first('revision'),
      );
      assert.equal(
        await DB.prepare('SELECT count(*) AS n FROM authorization_code').first('n'),
        codeCount,
      );
    }

    await t.test('legacy approval has no implicit destination or scope approval', () =>
      assertReview(),
    );
    await t.test('a matching context can still use prompt=none without a login page', async () => {
      await approve();
      const result = await authorize({ prompt: 'none' });
      assert.ok(result.location.searchParams.get('code'));
      assert.equal(result.location.origin + result.location.pathname, callback);
    });
    await t.test('an additional registered destination requires explicit review', () =>
      assertReview({ redirect_uri: alternate }),
    );
    await t.test(
      'adding profile requires review, and scope order does not cause a new prompt',
      async () => {
        await assertReview({ scope: 'openid profile' });
        await approve(callback, 'openid profile');
        const result = await authorize({ scope: 'profile openid', prompt: 'none' });
        assert.ok(result.location.searchParams.get('code'));
        await assertReview({ scope: 'openid' });
        await approve();
      },
    );
    await t.test(
      'explicit consent, login and account selection all preserve mandatory review',
      async () => {
        for (const prompt of ['consent', 'login consent', 'login', 'select_account']) {
          const result = await authorize({ prompt });
          const tx = result.location.searchParams.get('tx');
          assert.ok(tx);
          assert.equal(
            await DB.prepare(
              'SELECT connection_review_required FROM login_transaction WHERE tx_id=?',
            )
              .bind(tx)
              .first('connection_review_required'),
            1,
          );
        }
      },
    );
    await t.test('max_age cannot hide a context change behind reauthentication', async () => {
      const changed = await authorize({ max_age: '0', scope: 'openid profile' });
      const tx = changed.location.searchParams.get('tx');
      assert.ok(tx);
      assert.equal(
        await DB.prepare('SELECT connection_review_required FROM login_transaction WHERE tx_id=?')
          .bind(tx)
          .first('connection_review_required'),
        1,
      );
      assert.equal(
        (
          await authorize({ max_age: '0', scope: 'openid profile', prompt: 'none' })
        ).location.searchParams.get('error'),
        'login_required',
      );
    });
    await t.test('grant or client revision changes invalidate previous context', async () => {
      await DB.prepare('UPDATE app_connection SET grant_version=grant_version+1').run();
      await assertReview();
      await approve();
      await DB.prepare('UPDATE client SET revision=revision+1 WHERE client_id=?')
        .bind(client)
        .run();
      await assertReview();
      await approve();
    });
    await t.test('an approval on another account cannot be reused', async () => {
      await DB.batch([
        DB.prepare("INSERT INTO account_security VALUES('other-account',1,1)"),
        DB.prepare("INSERT INTO credential VALUES('other-credential','other-account',1)"),
        DB.prepare(
          'INSERT INTO app_connection(account_id,client_id,grant_version,active) VALUES(?,?,1,1)',
        ).bind('other-account', client),
        DB.prepare("UPDATE sso_context SET secret_hash=? WHERE sso_id='sso'").bind(
          hash('old-cookie'),
        ),
        DB.prepare(
          "INSERT INTO sso_session VALUES('other-sso','other-account','other-credential',1,?,0)",
        ).bind(now + 3600),
        DB.prepare("INSERT INTO sso_context VALUES('other-sso',?,?)").bind(hash('cookie'), now),
      ]);
      await assertReview();
    });
    await t.test('signed-out silent requests still return login_required', async () => {
      assert.equal(
        (await authorize({ prompt: 'none' }, false)).location.searchParams.get('error'),
        'login_required',
      );
    });
  } finally {
    await harness.close();
  }
});
