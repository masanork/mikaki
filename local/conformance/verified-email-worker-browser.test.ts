import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { readFile, readdir } from 'node:fs/promises';
import { createServer } from 'node:http';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { chromium, expect } from '@playwright/test';
import { build } from 'vite';
import { createTestHarness } from 'wrangler';

test('email browser controls use Worker, D1 and simulated email together', async () => {
  const root = fileURLToPath(new URL('../..', import.meta.url));
  const output = new URL('../generated/email-ui-worker/', import.meta.url);
  await build({
    configFile: fileURLToPath(new URL('../../crates/worker/ui/vite.config.ts', import.meta.url)),
    logLevel: 'error',
    build: {
      outDir: fileURLToPath(output),
      lib: {
        entry: fileURLToPath(new URL('./support/email-ui-entry.ts', import.meta.url)),
        formats: ['es'],
        fileName: () => 'email.js',
      },
    },
  });
  const script = await readFile(new URL('email.js', output));
  const harness = createTestHarness({
    root,
    workers: [
      {
        configPath: fileURLToPath(new URL('../../crates/worker/wrangler.jsonc', import.meta.url)),
        vars: { MIKAKI_ISSUER: 'https://issuer.example', MIKAKI_VERIFIED_EMAIL: 'on' },
      },
    ],
  });
  await harness.listen();
  const worker = harness.getWorker('mikaki-op-worker');
  await worker.applyD1Migrations('DB');
  const { DB } = await worker.getEnv();
  const now = Math.floor(Date.now() / 1000),
    cookie = randomBytes(32).toString('base64url');
  await DB.batch([
    DB.prepare("INSERT INTO account_security(account_id,epoch,active) VALUES('owner',1,1)"),
    DB.prepare("INSERT INTO credential(credential_id,account_id,active) VALUES('cred','owner',1)"),
    DB.prepare(
      "INSERT INTO sso_session(sso_id,account_id,credential_id,epoch,expires_at,revoked) VALUES('session','owner','cred',1,?,0)",
    ).bind(now + 600),
    DB.prepare("INSERT INTO sso_context(sso_id,secret_hash,auth_time) VALUES('session',?,?)").bind(
      createHash('sha256').update(cookie).digest('base64url'),
      now,
    ),
    DB.prepare(
      "INSERT INTO client(client_id,revision,active,sector_identifier) VALUES('example-app',1,1,'rp.example')",
    ),
    DB.prepare(
      "INSERT INTO app_connection(account_id,client_id,grant_version,active) VALUES('owner','example-app',1,1)",
    ),
    DB.prepare("INSERT INTO client_email_policy VALUES('example-app',1,1)"),
  ]);
  const dir = join(root, 'crates/worker/.wrangler/tmp/email');
  const mailFiles = async () =>
    (await readdir(dir, { recursive: true }).catch(() => [])).filter(
      (p) => p.includes('/email-text/') && p.endsWith('.txt'),
    );
  const before = new Set(await mailFiles());
  const server = createServer(async (req, res) => {
    try {
      if (req.url === '/') {
        res.writeHead(200, { 'content-type': 'text/html' });
        res.end(
          '<!doctype html><html lang="en"><body><script type="module" src="/email.js"></script></body></html>',
        );
        return;
      }
      if (req.url === '/email.js') {
        res.writeHead(200, { 'content-type': 'text/javascript' });
        res.end(script);
        return;
      }
      const chunks: Buffer[] = [];
      for await (const chunk of req) chunks.push(Buffer.from(chunk));
      const headers: Record<string, string> = { cookie: `__Host-op-sso=${cookie}` };
      if (req.headers['content-type']) headers['content-type'] = req.headers['content-type'];
      if (req.method === 'POST') headers.origin = 'https://issuer.example';
      const response = await worker.fetch(`https://issuer.example${req.url}`, {
        method: req.method,
        headers,
        body: req.method === 'POST' ? Buffer.concat(chunks) : undefined,
      });
      res.writeHead(response.status, {
        'content-type': response.headers.get('content-type') ?? 'application/json',
      });
      res.end(Buffer.from(await response.arrayBuffer()));
    } catch {
      res.writeHead(500);
      res.end();
    }
  }).listen(0, '127.0.0.1');
  await once(server, 'listening');
  const addr = server.address();
  if (!addr || typeof addr === 'string') throw new Error('missing server');
  const browser = await chromium.launch({ headless: true });
  try {
    const page = await browser.newPage();
    await page.goto(`http://127.0.0.1:${addr.port}/`);
    await page.getByText('Email and connected apps').click();
    await page.getByLabel('Email address').fill('owner@example.org');
    await page.getByRole('button', { name: 'Send confirmation code' }).click();
    await expect(page.getByRole('status')).toContainText('accepted for sending');
    let token = '';
    await expect
      .poll(async () => {
        const created = (await mailFiles()).filter((p) => !before.has(p));
        if (created.length !== 1) return '';
        const text = await readFile(join(dir, created[0]!), 'utf8').catch(() => '');
        token = text.match(/\b[A-Za-z0-9_-]{43}\b/)?.[0] ?? '';
        return token;
      })
      .toMatch(/^[A-Za-z0-9_-]{43}$/);
    await page.getByLabel('Confirmation code').fill(token);
    await page.getByRole('button', { name: 'Verify', exact: true }).click();
    await expect(page.getByText('Verified: owner@example.org')).toBeVisible();
    await page.getByRole('button', { name: 'Allow sharing' }).click();
    await expect(page.getByRole('button', { name: 'Stop sharing' })).toBeVisible();
    assert.equal(
      (await DB.prepare('SELECT count(*) AS n FROM eligible_verified_email_release').first()).n,
      1,
    );
    await page.getByRole('button', { name: 'Stop sharing' }).click();
    await expect(page.getByRole('button', { name: 'Allow sharing' })).toBeVisible();
    assert.equal(
      (await DB.prepare('SELECT count(*) AS n FROM eligible_verified_email_release').first()).n,
      0,
    );
    page.once('dialog', (dialog) => void dialog.accept());
    await page.getByRole('button', { name: 'Remove verified email' }).click();
    await expect(page.getByText('Verified: None')).toBeVisible();
  } finally {
    await browser.close();
    server.close();
    await once(server, 'close');
    await harness.close();
  }
});
