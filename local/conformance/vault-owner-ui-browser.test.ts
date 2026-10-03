import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHash, randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { createTestHarness } from 'wrangler';
import { chromium, expect } from '@playwright/test';
import { activateWorkerPolicy } from '../../scripts/worker-policy-store.ts';
import { auditAccessibility } from './support/accessibility-audit.ts';
import { parseThreadArchive } from '../../crates/worker/ui/vault-thread-archive.ts';

test('archive schema accepts human/AI messages and rejects malformed content', () => {
  const archive = {
    format_version: 1,
    title: 'Conversation',
    messages: [
      { speaker: 'Alice', actor: 'human', text: 'Hello', timestamp: '2026-10-03T00:00:00.000Z' },
    ],
  };
  assert.equal(parseThreadArchive(archive).messages[0]?.text, 'Hello');
  for (const invalid of [
    null,
    { ...archive, format_version: 2 },
    { ...archive, messages: [] },
    { ...archive, messages: [{ ...archive.messages[0], actor: 'system' }] },
    { ...archive, messages: [{ ...archive.messages[0], timestamp: 'yesterday' }] },
  ])
    assert.throws(() => parseThreadArchive(invalid));
});
test('new owner Vault uses one PRF for profile and conversation reads/writes, exact retries and local search; lock clears display', async () => {
  const origin = 'https://mikaki.test';
  const harness = createTestHarness({
    root: new URL('../..', import.meta.url).pathname,
    workers: [
      {
        configPath: new URL('../../crates/worker/wrangler.jsonc', import.meta.url).pathname,
        vars: { MIKAKI_ISSUER: origin },
      },
    ],
  });
  let browser: Awaited<ReturnType<typeof chromium.launch>> | undefined;
  try {
    await harness.listen();
    const worker = harness.getWorker('mikaki-op-worker');
    await worker.applyD1Migrations('DB');
    const { DB } = await worker.getEnv();
    const policy = JSON.parse(
      await readFile(new URL('../generated/worker-policy.json', import.meta.url), 'utf8'),
    );
    await activateWorkerPolicy(DB, policy, { actor: 'test', reason: 'Owner Vault UI' });
    const credential = randomBytes(32),
      id = credential.toString('base64url'),
      secret = randomBytes(32).toString('base64url'),
      now = Math.floor(Date.now() / 1000);
    await DB.batch([
      DB.prepare("INSERT INTO account_security VALUES('owner',1,1)"),
      DB.prepare("INSERT INTO credential VALUES(?,'owner',1)").bind(id),
      DB.prepare("INSERT INTO sso_session VALUES('session','owner',?,1,?,0)").bind(id, now + 3600),
      DB.prepare("INSERT INTO sso_context VALUES('session',?,?)").bind(
        createHash('sha256').update(secret).digest('base64url'),
        now,
      ),
    ]);
    browser = await chromium.launch({ headless: true });
    const context = await browser.newContext({ viewport: { width: 390, height: 844 } });
    let ceremonies = 0;
    await context.exposeFunction('recordCeremony', () => {
      ceremonies++;
    });
    await context.addInitScript(
      ({ credential }) => {
        let hidden = false;
        Object.defineProperty(document, 'visibilityState', {
          get: () => (hidden ? 'hidden' : 'visible'),
        });
        Object.defineProperty(window, 'setVaultHidden', {
          value: (value: boolean) => {
            hidden = value;
            document.dispatchEvent(new Event('visibilitychange'));
          },
        });
        class MockCredential {
          rawId = Uint8Array.from(credential).buffer;
          getClientExtensionResults() {
            return { prf: { results: { first: new Uint8Array(32).fill(0x71).buffer } } };
          }
        }
        Object.defineProperty(window, 'PublicKeyCredential', { value: MockCredential });
        Object.defineProperty(navigator, 'credentials', {
          value: {
            get: async () => {
              await (window as unknown as { recordCeremony: () => Promise<void> }).recordCeremony();
              return new MockCredential();
            },
          },
        });
      },
      { credential: [...credential] },
    );
    let lose = false,
      failSession = false;
    const recordBodies: string[] = [];
    const errors: string[] = [];
    await context.route(`${origin}/**`, async (route) => {
      const request = route.request();
      const path = new URL(request.url()).pathname;
      if (failSession && path === '/vault/session') {
        await route.fulfill({ status: 503 });
        return;
      }
      if (path.startsWith('/vault/records/') && request.method() === 'PUT')
        recordBodies.push(request.postData()!);
      const response = await worker.fetch(request.url(), {
        method: request.method(),
        headers: { ...(await request.allHeaders()), cookie: `__Host-op-sso=${secret}` },
        ...(request.postData() ? { body: request.postData()! } : {}),
      });
      const body = Buffer.from(await response.arrayBuffer());
      if (
        lose &&
        path === '/vault/records/personal/profile' &&
        request.method() === 'PUT' &&
        response.ok
      ) {
        lose = false;
        await route.abort();
        return;
      }
      await route.fulfill({
        status: response.status,
        headers: Object.fromEntries(response.headers),
        body,
      });
    });
    const page = await context.newPage();
    page.on('pageerror', (e) => errors.push(e.message));
    page.on('dialog', (d) => void d.accept());
    await page.goto(`${origin}/vault?lang=en`);
    await page.locator('#unlock').click();
    await expect(page.locator('#name')).toBeEnabled();
    await expect(page.locator('#name')).toBeFocused();
    assert.equal(ceremonies, 1);
    await page.evaluate(() =>
      (window as unknown as { setVaultHidden: (value: boolean) => void }).setVaultHidden(true),
    );
    await expect(page.locator('#name')).not.toBeVisible();
    await page.evaluate(() =>
      (window as unknown as { setVaultHidden: (value: boolean) => void }).setVaultHidden(false),
    );
    await expect(page.locator('#name')).toBeVisible();
    await page.locator('#reload-profile').click();
    await expect(page.locator('#archive-file')).toBeEnabled();
    assert.equal(ceremonies, 1);
    await page.locator('#name').fill('New owner');
    lose = true;
    await page.locator('#save').click();
    await expect(page.locator('#retry-write')).toBeVisible();
    await page.locator('#retry-write').click();
    await expect(page.locator('#retry-write')).toHaveCount(0);
    await expect(page.locator('#name')).toHaveValue('New owner');
    assert.equal(recordBodies[0], recordBodies[1]);
    assert.equal(ceremonies, 1);
    const archive = {
      format_version: 1,
      title: '申請の相談',
      messages: [
        {
          speaker: 'Alice',
          actor: 'human',
          text: '保育園の申請について相談したい',
          timestamp: '2026-10-03T00:00:00.000Z',
        },
        {
          speaker: 'Assistant',
          actor: 'ai',
          text: '必要な情報を整理しましょう',
          timestamp: '2026-10-03T00:01:00.000Z',
        },
      ],
    };
    await expect(page.locator('#archive-file')).toBeEnabled();
    await page.locator('#archive-file').setInputFiles({
      name: 'conversation.json',
      mimeType: 'application/json',
      buffer: Buffer.from(JSON.stringify(archive)),
    });
    await expect(page.getByRole('button', { name: '申請の相談', exact: true })).toBeVisible();
    await page.getByRole('button', { name: '申請の相談', exact: true }).click();
    await expect(page.getByText('必要な情報を整理しましょう', { exact: true })).toBeVisible();
    await page.locator('#thread-search').fill('保育園');
    await expect(page.getByRole('button', { name: '申請の相談', exact: true })).toBeVisible();
    await page.locator('#thread-search').fill('absent');
    await expect(page.getByRole('button', { name: '申請の相談', exact: true })).toHaveCount(0);
    await page.locator('#thread-search').fill('');
    await page.locator('#reload-profile').click();
    await expect(page.locator('#name')).toHaveValue('New owner');
    assert.equal(ceremonies, 1);
    await auditAccessibility(page, 'owner-vault-mobile');
    await page.screenshot({ path: '/private/tmp/mikaki-owner-vault-mobile.png', fullPage: true });
    await page.getByRole('button', { name: 'Lock Vault', exact: true }).click();
    await expect(page.locator('#name')).toHaveCount(0);
    await expect(page.getByText('必要な情報を整理しましょう', { exact: true })).toHaveCount(0);
    await page.getByRole('button', { name: 'Check session and reopen', exact: true }).click();
    await page.locator('#unlock').click();
    await expect(page.locator('#name')).toHaveValue('New owner');
    assert.equal(ceremonies, 2);
    await page.reload();
    await page.locator('#unlock').click();
    await expect(page.locator('#name')).toHaveValue('New owner');
    await expect(page.getByRole('button', { name: '申請の相談', exact: true })).toBeVisible();
    assert.equal(ceremonies, 3);
    await page.locator('#delete').click();
    await expect(page.locator('#name')).toHaveValue('');
    await page.locator('#name').fill('Recreated');
    await page.locator('#save').click();
    await expect(page.locator('#name')).toHaveValue('Recreated');
    assert.equal(ceremonies, 3);
    assert.deepEqual(errors, []);
    failSession = true;
    await page.evaluate(() =>
      (window as unknown as { setVaultHidden: (value: boolean) => void }).setVaultHidden(true),
    );
    await page.evaluate(() =>
      (window as unknown as { setVaultHidden: (value: boolean) => void }).setVaultHidden(false),
    );
    await expect(page.getByRole('heading', { name: 'Vault is locked', exact: true })).toBeVisible();
    await expect(page.locator('#name')).toHaveCount(0);
    assert.equal(ceremonies, 3);
    assert.ok(
      recordBodies.every((body) => !body.includes('New owner') && !body.includes('保育園')),
    );
  } finally {
    await browser?.close();
    await harness.close();
  }
});
