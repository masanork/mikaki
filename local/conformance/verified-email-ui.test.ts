import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { chromium, expect } from '@playwright/test';
import { build } from 'vite';

test('email UI provides confirmation and explicit per-app grant and withdrawal', async () => {
  const out = new URL('../generated/email-ui/', import.meta.url);
  await build({
    configFile: fileURLToPath(new URL('../../crates/worker/ui/vite.config.ts', import.meta.url)),
    logLevel: 'error',
    build: {
      outDir: fileURLToPath(out),
      lib: {
        entry: fileURLToPath(new URL('./support/email-ui-entry.ts', import.meta.url)),
        formats: ['es'],
        fileName: () => 'email.js',
      },
    },
  });
  const script = await readFile(new URL('email.js', out));
  let verified = false,
    grant = false;
  const server = createServer(async (req, res) => {
    if (req.url === '/email.js') {
      res.writeHead(200, { 'Content-Type': 'text/javascript' });
      res.end(script);
      return;
    }
    if (req.url === '/') {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(
        '<!doctype html><html lang="en"><body><script type="module" src="/email.js"></script></body></html>',
      );
      return;
    }
    if (req.url === '/account/email') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          email: verified ? { email: 'owner@example.org' } : null,
          clients: [{ client_id: 'example-app', released: grant ? 1 : 0 }],
        }),
      );
      return;
    }
    if (req.method === 'POST' && req.url?.startsWith('/account/email/')) {
      let body = '';
      for await (const chunk of req) body += chunk;
      const data = JSON.parse(body);
      if (req.url.endsWith('/start')) assert.equal(data.email, 'owner@example.org');
      else if (req.url.endsWith('/confirm')) {
        assert.equal(data.token, 'test-code');
        verified = true;
      } else if (req.url.endsWith('/remove')) {
        verified = false;
        grant = false;
      } else {
        assert.equal(data.client_id, 'example-app');
        grant = data.action === 'grant';
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end('{}');
      return;
    }
    res.writeHead(404);
    res.end();
  }).listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('server address unavailable');
  const browser = await chromium.launch({ headless: true });
  try {
    const page = await browser.newPage();
    await page.goto(`http://127.0.0.1:${address.port}/`);
    await page.getByText('Email and connected apps').click();
    await page.getByLabel('Email address').fill('owner@example.org');
    await page.getByRole('button', { name: 'Send confirmation code' }).click();
    await expect(page.getByRole('status')).toContainText('accepted for sending');
    await page.getByLabel('Confirmation code').fill('test-code');
    await page.getByRole('button', { name: 'Verify', exact: true }).click();
    await expect(page.getByText('Verified: owner@example.org')).toBeVisible();
    await page.getByRole('button', { name: 'Allow sharing' }).click();
    await expect(page.getByRole('button', { name: 'Stop sharing' })).toBeVisible();
    await page.getByRole('button', { name: 'Stop sharing' }).click();
    await expect(page.getByRole('button', { name: 'Allow sharing' })).toBeVisible();
    page.once('dialog', (dialog) => void dialog.accept());
    await page.getByRole('button', { name: 'Remove verified email' }).click();
    await expect(page.getByText('Verified: None')).toBeVisible();
  } finally {
    await browser.close();
    server.close();
    await once(server, 'close');
  }
});
