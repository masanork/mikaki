import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
import { mkdir, readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { chromium } from '@playwright/test';
import { createTestHarness } from 'wrangler';
import { issueBootstrapInvite } from '../../scripts/enrollment-store.ts';
import { activateWorkerPolicy } from '../../scripts/worker-policy-store.ts';
import { startBrowserEvidence } from './support/browser-evidence.ts';
import { auditAccessibility } from './support/accessibility-audit.ts';

const root = new URL('../..', import.meta.url).pathname;
const issuer = 'https://mikaki.test';
const key = Buffer.alloc(32, 7).toString('base64url');
const hash = (value: string) => createHash('sha256').update(value).digest('base64url');
type ListPage = { entries: { id: string; status: string }[]; next_cursor: string | null };
const readList = async (response: { status: number; json(): Promise<unknown> }) => {
  assert.equal(response.status, 200);
  return (await response.json()) as ListPage;
};

test('confirmed waiting list, UV-bound approval, durable retry, expiration and single-use registration', async () => {
  const config = JSON.parse(await readFile(`${root}/crates/worker/wrangler.jsonc`, 'utf8'));
  config.main = new URL('./support/waitlist-mail-fixture.mjs', import.meta.url).pathname;
  config.d1_databases[0].migrations_dir = `${root}/crates/worker/migrations`;
  config.vars = { ...config.vars, MIKAKI_ISSUER: issuer, WAITLIST_MAIL_KEY: key };
  const harness = createTestHarness({ root, workers: [{ config }] });
  let browser;
  let evidence: Awaited<ReturnType<typeof startBrowserEvidence>> | undefined;
  let failure: unknown;
  try {
    await harness.listen();
    const worker = harness.getWorker('mikaki-op-worker');
    await worker.applyD1Migrations('DB');
    const { DB } = await worker.getEnv();
    await DB.batch([
      DB.prepare('CREATE TABLE fixture_mail_capture(id TEXT PRIMARY KEY,message TEXT NOT NULL)'),
      DB.prepare('CREATE TABLE fixture_mail_control(id INTEGER PRIMARY KEY,fail INTEGER NOT NULL)'),
      DB.prepare('INSERT INTO fixture_mail_control VALUES(1,0)'),
    ]);
    await activateWorkerPolicy(
      DB,
      JSON.parse(await readFile(`${root}/local/generated/worker-policy.json`, 'utf8')),
      { actor: 'test', reason: 'waitlist integration' },
    );
    const post = (path: string, body: unknown, origin = issuer) =>
      worker.fetch(`${issuer}${path}`, {
        method: 'POST',
        headers: { origin, 'content-type': 'application/json', 'CF-Connecting-IP': '192.0.2.10' },
        body: JSON.stringify(body),
      });
    assert.equal(
      (
        await post(
          '/waitlist/request',
          { email: 'alice@example.test', locale: 'ja' },
          'https://evil.test',
        )
      ).status,
      403,
    );
    assert.equal(
      (await post('/waitlist/request', { email: 'alice\r\nBcc:other@example.test', locale: 'ja' }))
        .status,
      400,
    );
    assert.equal(
      (await post('/waitlist/request', { email: 'Alice@example.test', locale: 'ja' })).status,
      202,
    );
    assert.equal(
      (await post('/waitlist/request', { email: 'alice@example.test', locale: 'ja' })).status,
      202,
    );
    assert.equal((await DB.prepare('SELECT count(*) AS n FROM enrollment_waitlist').first()).n, 1);
    assert.equal((await DB.prepare('SELECT count(*) AS n FROM fixture_mail_capture').first()).n, 1);
    assert.equal((await DB.prepare('SELECT count(*) AS n FROM account_security').first()).n, 0);
    assert.equal((await worker.fetch(`${issuer}/admin/waitlist`)).status, 403);
    const contact = await DB.prepare(
      'SELECT id,confirmation_hash,verified_at FROM enrollment_waitlist',
    ).first();
    const confirmation = JSON.parse(
      (await DB.prepare('SELECT message FROM fixture_mail_capture').first()).message,
    );
    const confirmationUrl = new URL(confirmation.text.match(/https:\/\/\S+/)[0]);
    const token = confirmationUrl.hash.slice('#confirm='.length);
    assert.equal(hash(token), contact.confirmation_hash);
    const mail = await DB.prepare(
      "SELECT id,token_hash FROM enrollment_mail WHERE kind='confirmation'",
    ).first();
    assert.equal(
      token,
      createHmac('sha256', Buffer.from(key, 'base64url'))
        .update(`mikaki-enrollment-mail-v1:confirmation:${mail.id}`)
        .digest('base64url'),
    );
    assert.equal(JSON.stringify(mail).includes(token), false);
    assert.equal(
      (await post('/admin/waitlist/start', { waitlist_id: contact.id, action: 'invite' })).status,
      403,
    );
    assert.equal((await post('/waitlist/confirm', { token: 'A'.repeat(43) })).status, 400);

    browser = await chromium.launch({ headless: true });
    const context = await browser.newContext();
    const page = await context.newPage();
    const openEnrollment = async () => {
      // Playwright does not route the second request of a fulfilled HTTP redirect.
      const pending = await worker.fetch(`${issuer}/enroll?lang=ja`, { redirect: 'manual' });
      assert.equal(pending.status, 302);
      const cookie = pending.headers.get('set-cookie')!.split(';')[0];
      await context.addCookies([
        {
          name: '__Host-op-browser',
          value: cookie.split('=')[1],
          domain: 'mikaki.test',
          path: '/',
          secure: true,
          httpOnly: true,
          sameSite: 'Lax',
        },
      ]);
      await page.goto(pending.headers.get('location')!);
    };
    evidence = await startBrowserEvidence(context, 'enrollment-waitlist');
    const errors: string[] = [];
    page.on('pageerror', (error) => errors.push(error.message));
    let lastFinish: { body: string; headers: Record<string, string> } | undefined;
    let raceStatuses: number[] = [];
    let raceFirstApproval = true;
    await page.route(
      (url) => url.hostname === 'mikaki.test',
      async (route) => {
        const request = route.request();
        const headers = await request.allHeaders();
        if (new URL(request.url()).pathname === '/admin/invitations/finish')
          lastFinish = { body: request.postData()!, headers };
        const init = {
          method: request.method(),
          headers,
          redirect: 'manual' as const,
          ...(request.postDataBuffer() ? { body: request.postDataBuffer() } : {}),
        };
        let response;
        if (new URL(request.url()).pathname === '/admin/invitations/finish' && raceFirstApproval) {
          raceFirstApproval = false;
          const responses = await Promise.all([
            worker.fetch(request.url(), init),
            worker.fetch(request.url(), init),
          ]);
          raceStatuses = responses.map((item) => item.status);
          response = responses.find((item) => item.ok) ?? responses[0];
        } else response = await worker.fetch(request.url(), init);
        await route.fulfill({
          status: response.status,
          headers: Object.fromEntries(response.headers),
          body: Buffer.from(await response.arrayBuffer()),
        });
      },
    );
    await mkdir('artifacts/waitlist-preview', { recursive: true });
    await page.goto(`${issuer}/waitlist?lang=en`);
    await page.getByLabel('Email address').fill('bob@example.test');
    await auditAccessibility(page, 'waitlist-form-en');
    await page.setViewportSize({ width: 390, height: 844 });
    await page.screenshot({ path: 'artifacts/waitlist-preview/form-mobile.png', fullPage: true });
    assert.equal(
      await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
      true,
    );
    await page.getByRole('button', { name: 'Send confirmation email' }).click();
    await page.getByRole('status').waitFor();
    const unverified = await DB.prepare(
      "SELECT id,verified_at FROM enrollment_waitlist WHERE email='bob@example.test'",
    ).first();
    assert.equal(unverified.verified_at, null);
    await page.setViewportSize({ width: 1280, height: 720 });
    await page.goto(confirmationUrl.href);
    await auditAccessibility(page, 'waitlist-confirmation-ja');
    const cdp = await context.newCDPSession(page);
    await cdp.send('WebAuthn.enable', { enableUI: false });
    await cdp.send('WebAuthn.addVirtualAuthenticator', {
      options: {
        protocol: 'ctap2',
        ctap2Version: 'ctap2_1',
        transport: 'internal',
        hasResidentKey: true,
        hasUserVerification: true,
        automaticPresenceSimulation: true,
        isUserVerified: true,
      },
    });
    await page.screenshot({ path: 'artifacts/waitlist-preview/confirmation.png', fullPage: true });
    assert.equal(new URL(page.url()).hash, '');
    assert.equal(
      (
        await DB.prepare(
          "SELECT verified_at FROM enrollment_waitlist WHERE email='alice@example.test'",
        ).first()
      ).verified_at,
      null,
    );
    await page.getByRole('button', { name: 'メールアドレスを確認' }).click();
    await page.getByRole('status').waitFor();
    assert.ok(
      (
        await DB.prepare(
          "SELECT verified_at FROM enrollment_waitlist WHERE email='alice@example.test'",
        ).first()
      ).verified_at,
    );
    const bootstrap = await issueBootstrapInvite(DB, 'test', 'waitlist administrator');
    await openEnrollment();
    await page.getByLabel('招待コード').fill(bootstrap.invitation);
    await page.getByRole('button', { name: '招待で登録する' }).click();
    await page.getByRole('heading', { name: '登録が完了しました' }).waitFor();
    await page.goto(`${issuer}/admin?lang=ja`);
    await page.getByRole('button', { name: '招待する', exact: true }).waitFor();
    assert.equal(await page.getByText('alice@example.test', { exact: true }).count(), 1);
    assert.equal(await page.getByText('bob@example.test', { exact: true }).count(), 0);
    await DB.prepare('UPDATE fixture_mail_control SET fail=1 WHERE id=1').run();
    await page.getByRole('button', { name: '招待する', exact: true }).click();
    await page.getByText('送信失敗', { exact: true }).waitFor();
    assert.equal(raceStatuses.filter((status) => status === 200).length, 1);
    assert.ok(raceStatuses.some((status) => status === 400 || status === 409));
    assert.ok(lastFinish);
    const replay = await worker.fetch(`${issuer}/admin/invitations/finish`, {
      method: 'POST',
      headers: lastFinish.headers,
      body: lastFinish.body,
    });
    assert.ok([400, 409].includes(replay.status));
    assert.equal(
      (await DB.prepare("SELECT count(*) AS n FROM enrollment_invite WHERE kind='normal'").first())
        .n,
      1,
    );
    const issued = await DB.prepare(
      "SELECT id,token_hash,state,attempts FROM enrollment_mail WHERE kind='invitation'",
    ).first();
    assert.equal(issued.state, 'failed');
    assert.equal(issued.attempts, 1);
    await DB.batch([
      DB.prepare('UPDATE fixture_mail_control SET fail=0 WHERE id=1'),
      DB.prepare(
        "UPDATE enrollment_mail SET next_attempt_at=unixepoch()-1 WHERE kind='invitation'",
      ),
      DB.prepare(
        "UPDATE enrollment_mail SET state='failed',next_attempt_at=0 WHERE waitlist_id=? AND kind='confirmation'",
      ).bind(unverified.id),
      DB.prepare('UPDATE enrollment_waitlist SET confirmation_hash=? WHERE id=?').bind(
        hash('superseded-confirmation'),
        unverified.id,
      ),
    ]);
    await worker.scheduled({ cron: '* * * * *', scheduledTime: new Date() });
    assert.equal(
      (
        await DB.prepare(
          "SELECT state FROM enrollment_mail WHERE waitlist_id=? AND kind='confirmation'",
        )
          .bind(unverified.id)
          .first()
      ).state,
      'cancelled',
    );
    assert.equal(
      (await DB.prepare('SELECT state FROM enrollment_mail WHERE id=?').bind(issued.id).first())
        .state,
      'sent',
    );
    const invitationMessage = JSON.parse(
      (
        await DB.prepare(
          "SELECT message FROM fixture_mail_capture WHERE json_extract(message,'$.subject')='mikakiへの招待'",
        ).first()
      ).message,
    );
    const invitation = /招待コード: ([A-Za-z0-9_-]{43})/.exec(invitationMessage.text)![1];
    assert.equal(hash(invitation), issued.token_hash);
    assert.equal(
      invitation,
      createHmac('sha256', Buffer.from(key, 'base64url'))
        .update(`mikaki-enrollment-mail-v1:invitation:${issued.id}`)
        .digest('base64url'),
    );
    const sso = (await context.cookies(issuer)).find((cookie) => cookie.name === '__Host-op-sso')!;
    const adminHeaders = {
      origin: issuer,
      cookie: `${sso.name}=${sso.value}`,
      'content-type': 'application/json',
    };
    assert.equal(
      (
        await worker.fetch(`${issuer}/admin/waitlist/start`, {
          method: 'POST',
          headers: adminHeaders,
          body: JSON.stringify({ waitlist_id: unverified.id, action: 'invite' }),
        })
      ).status,
      409,
    );
    assert.equal(
      (
        await worker.fetch(`${issuer}/admin/waitlist/start`, {
          method: 'POST',
          headers: adminHeaders,
          body: JSON.stringify({ waitlist_id: contact.id, action: 'resend' }),
        })
      ).status,
      409,
    );
    assert.equal(
      (
        await worker.fetch(`${issuer}/admin/waitlist/start`, {
          method: 'POST',
          headers: adminHeaders,
          body: JSON.stringify({ waitlist_id: contact.id, action: 'invite' }),
        })
      ).status,
      409,
    );
    await DB.prepare(
      "UPDATE enrollment_mail SET last_attempt_at=unixepoch()-61 WHERE kind='invitation'",
    ).run();
    await page.getByRole('button', { name: '一覧を更新' }).click();
    await page.getByRole('button', { name: '招待メールを再送' }).click();
    await page.getByText('招待メールを送信しました。', { exact: true }).waitFor();
    await page.setViewportSize({ width: 390, height: 844 });
    await page.screenshot({ path: 'artifacts/waitlist-preview/admin-mobile.png', fullPage: true });
    assert.equal(
      await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
      true,
    );
    assert.equal(
      (await DB.prepare("SELECT count(*) AS n FROM enrollment_invite WHERE kind='normal'").first())
        .n,
      1,
    );
    assert.equal(
      (
        await DB.prepare(
          "SELECT count(*) AS n FROM fixture_mail_capture WHERE json_extract(message,'$.subject')='mikakiへの招待'",
        ).first()
      ).n,
      2,
    );
    const codes = (
      await DB.prepare(
        "SELECT message FROM fixture_mail_capture WHERE json_extract(message,'$.subject')='mikakiへの招待'",
      ).all()
    ).results.map(
      (row: { message: string }) =>
        /招待コード: ([A-Za-z0-9_-]{43})/.exec(JSON.parse(row.message).text)![1],
    );
    assert.deepEqual(codes, [invitation, invitation]);
    const now = Math.floor(Date.now() / 1000);
    await DB.prepare('UPDATE enrollment_invite SET issued_at=?,expires_at=? WHERE invite_hash=?')
      .bind(now - 1000, now - 1, issued.token_hash)
      .run();
    await page.getByRole('button', { name: '一覧を更新' }).click();
    await page.getByText('期限切れ', { exact: true }).waitFor();
    await page.getByRole('button', { name: '招待する', exact: true }).click();
    await page.getByText('招待メールを送信しました。', { exact: true }).waitFor();
    assert.equal(
      (
        await DB.prepare('SELECT revoked FROM enrollment_invite WHERE invite_hash=?')
          .bind(issued.token_hash)
          .first()
      ).revoked,
      1,
    );
    const renewed = await DB.prepare(
      "SELECT id,token_hash FROM enrollment_mail WHERE kind='invitation' AND token_hash<>?",
    )
      .bind(issued.token_hash)
      .first();
    const newCode = createHmac('sha256', Buffer.from(key, 'base64url'))
      .update(`mikaki-enrollment-mail-v1:invitation:${renewed.id}`)
      .digest('base64url');
    assert.notEqual(newCode, invitation);
    await context.clearCookies();
    await openEnrollment();
    await page.getByLabel('招待コード').fill(newCode);
    await page.getByRole('button', { name: '招待で登録する' }).click();
    await page.getByRole('heading', { name: '登録が完了しました' }).waitFor();
    assert.equal((await DB.prepare('SELECT count(*) AS n FROM account_security').first()).n, 2);
    assert.equal(
      (
        await DB.prepare(
          "SELECT count(*) AS n FROM account_role WHERE role='admin' AND active=1",
        ).first()
      ).n,
      1,
    );
    assert.equal(
      (
        await worker.fetch(`${issuer}/admin/waitlist`, {
          headers: {
            cookie: (await context.cookies(issuer))
              .filter((c) => c.name === '__Host-op-sso')
              .map((c) => `${c.name}=${c.value}`)
              .join('; '),
          },
        })
      ).status,
      403,
    );
    const list = await worker.fetch(`${issuer}/admin/waitlist`, { headers: adminHeaders });
    assert.equal((await readList(list)).entries[0].status, 'registered');
    const inserts = Array.from({ length: 101 }, (_, index) => {
      const id = hash(`pagination:${index}`);
      return DB.prepare(
        "INSERT INTO enrollment_waitlist(id,email,locale,created_at,verified_at,confirmation_hash,confirmation_expires_at,confirmation_sent_at) VALUES(?,?,'en',?,?,?, ?,?)",
      ).bind(
        id,
        `page-${index}@example.test`,
        now + index + 1,
        now,
        hash(`confirmation:${index}`),
        now + 3600,
        now,
      );
    });
    await DB.batch(inserts);
    const firstPage = await readList(
      await worker.fetch(`${issuer}/admin/waitlist`, { headers: adminHeaders }),
    );
    assert.equal(firstPage.entries.length, 100);
    assert.equal(typeof firstPage.next_cursor, 'string');
    const secondPage = await readList(
      await worker.fetch(`${issuer}/admin/waitlist?cursor=${firstPage.next_cursor}`, {
        headers: adminHeaders,
      }),
    );
    assert.equal(secondPage.entries.length, 2);
    assert.equal(secondPage.next_cursor, null);
    assert.equal(
      new Set(
        [...firstPage.entries, ...secondPage.entries].map((entry: { id: string }) => entry.id),
      ).size,
      102,
    );
    assert.equal(
      (await worker.fetch(`${issuer}/admin/waitlist?cursor=bad`, { headers: adminHeaders })).status,
      400,
    );
    await DB.prepare('UPDATE enrollment_waitlist SET created_at=unixepoch()-2592001 WHERE id=?')
      .bind(unverified.id)
      .run();
    await worker.scheduled({ cron: '* * * * *', scheduledTime: new Date() });
    assert.equal(
      await DB.prepare('SELECT id FROM enrollment_waitlist WHERE id=?').bind(unverified.id).first(),
      null,
    );
    assert.equal(
      (await DB.prepare('SELECT count(*) AS n FROM enrollment_waitlist').first()).n,
      102,
    );
    await DB.prepare("UPDATE account_role SET active=0 WHERE role='admin'").run();
    assert.equal(
      (await worker.fetch(`${issuer}/admin/waitlist`, { headers: adminHeaders })).status,
      403,
    );
    assert.deepEqual(errors, []);
  } catch (error) {
    failure = error;
    throw error;
  } finally {
    await evidence?.finish(failure);
    await browser?.close();
    await harness.close();
  }
});

test('native email binding is simulated locally and unverified/expired requests grant no access', async () => {
  const harness = createTestHarness({
    root,
    workers: [
      {
        configPath: `${root}/crates/worker/wrangler.jsonc`,
        vars: { MIKAKI_ISSUER: issuer, WAITLIST_MAIL_KEY: key },
      },
    ],
  });
  try {
    await harness.listen();
    const worker = harness.getWorker('mikaki-op-worker');
    await worker.applyD1Migrations('DB');
    const { DB } = await worker.getEnv();
    const response = await worker.fetch(`${issuer}/waitlist/request`, {
      method: 'POST',
      headers: { origin: issuer, 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'local-only@example.test', locale: 'en' }),
    });
    assert.equal(response.status, 202);
    const mail = await DB.prepare('SELECT id,state FROM enrollment_mail').first();
    assert.equal(mail.state, 'sent');
    for (let attempt = 0; attempt < 4; attempt++) {
      assert.equal(
        (
          await worker.fetch(`${issuer}/waitlist/request`, {
            method: 'POST',
            headers: { origin: issuer, 'content-type': 'application/json' },
            body: JSON.stringify({ email: 'local-only@example.test', locale: 'en' }),
          })
        ).status,
        202,
      );
    }
    assert.equal(
      (
        await worker.fetch(`${issuer}/waitlist/request`, {
          method: 'POST',
          headers: { origin: issuer, 'content-type': 'application/json' },
          body: JSON.stringify({ email: 'local-only@example.test', locale: 'en' }),
        })
      ).status,
      429,
    );
    const token = createHmac('sha256', Buffer.from(key, 'base64url'))
      .update(`mikaki-enrollment-mail-v1:confirmation:${mail.id}`)
      .digest('base64url');
    await DB.prepare('UPDATE enrollment_waitlist SET confirmation_expires_at=unixepoch()-1').run();
    assert.equal(
      (
        await worker.fetch(`${issuer}/waitlist/confirm`, {
          method: 'POST',
          headers: { origin: issuer, 'content-type': 'application/json' },
          body: JSON.stringify({ token }),
        })
      ).status,
      400,
    );
    assert.equal(
      (await DB.prepare('SELECT verified_at FROM enrollment_waitlist').first()).verified_at,
      null,
    );
    assert.equal((await DB.prepare('SELECT count(*) AS n FROM account_security').first()).n, 0);
  } finally {
    await harness.close();
  }
});
