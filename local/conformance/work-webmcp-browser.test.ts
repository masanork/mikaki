/** Native Chromium WebMCP over actual Work UI, Native/D1/checkpoint and local Git.
 * Identity/provider mappings are synthetic; no remote resource is touched. */
import assert from 'node:assert/strict';
import { mkdir } from 'node:fs/promises';
import { test } from 'node:test';
import { chromium, expect, type BrowserContext, type Page } from '@playwright/test';
import { createSourceFixture } from './support/work-source-fixture.ts';
import { copyJobFixture } from './support/work-copy-job-fixture.ts';
import { auditAccessibility } from './support/accessibility-audit.ts';

async function browserTools(context: BrowserContext) {
  await context.addInitScript(() => {
    const api = (
      document as Document & {
        modelContext: {
          getTools(): Promise<{ name: string }[]>;
          executeTool(tool: unknown, args: unknown): Promise<unknown>;
        };
      }
    ).modelContext;
    Object.defineProperty(window, 'workTools', {
      value: {
        names: async () => (await api.getTools()).map((tool) => tool.name),
        call: async (name: string, args: unknown) => {
          const tool = (await api.getTools()).find((tool) => tool.name === name);
          if (!tool) return { ok: false, error: 'missing' };
          try {
            const result = await api.executeTool(tool, args);
            return typeof result === 'string' ? JSON.parse(result) : result;
          } catch {
            return { ok: false, error: 'browser_cancelled' };
          }
        },
      },
    });
    let hidden = false;
    Object.defineProperty(document, 'visibilityState', {
      configurable: true,
      get: () => (hidden ? 'hidden' : 'visible'),
    });
    Object.defineProperty(window, 'hideWorkTools', {
      value: () => {
        hidden = true;
        document.dispatchEvent(new Event('visibilitychange'));
      },
    });
  });
}
function tools(page: Page) {
  return {
    names: () =>
      page.evaluate(() =>
        (window as unknown as { workTools: { names(): Promise<string[]> } }).workTools.names(),
      ),
    call: (name: string, args: unknown = {}) =>
      page.evaluate(
        ({ name, args }) =>
          (
            window as unknown as { workTools: { call(name: string, args: unknown): Promise<any> } }
          ).workTools.call(name, args),
        { name, args },
      ),
  };
}
test('source and consent screens share WebMCP actions while retaining exact selection and human approval', async (t) => {
  const f = await createSourceFixture(undefined, true, 'product', true, 3600, true);
  await f.register('code', f.first, {
    role: 'code',
    label: 'Synthetic code',
    files: [],
    ...f.codeSource,
  });
  const browser = await chromium.launch({ args: ['--enable-blink-features=WebMCP,WebMCPTesting'] });
  const context = await browser.newContext({ viewport: { width: 1280, height: 1100 } });
  await browserTools(context);
  await context.addCookies([
    {
      name: '__Host-op-sso',
      value: f.first.cookie,
      domain: 'work.test',
      path: '/',
      secure: true,
      httpOnly: true,
      sameSite: 'Lax',
    },
  ]);
  const page = await context.newPage(),
    api = tools(page),
    errors: string[] = [],
    writes: string[] = [];
  page.on('pageerror', (error) => errors.push(error.message));
  page.on('dialog', (dialog) => void dialog.accept());
  let held = false,
    started: (() => void) | undefined,
    release: (() => void) | undefined;
  function releaseRead() {
    release?.();
    release = undefined;
  }
  await context.route('https://work.test/**', async (route) => {
    const request = route.request(),
      path = new URL(request.url()).pathname;
    if (request.method() !== 'GET' && path.startsWith('/work/')) writes.push(path);
    const response = await f.worker.fetch(request.url(), {
      method: request.method(),
      headers: await request.allHeaders(),
      body: request.postData() ?? undefined,
    });
    const body = Buffer.from(await response.arrayBuffer());
    if (held && path === '/work/sources/read') {
      held = false;
      started?.();
      await new Promise<void>((resolve) => {
        release = resolve;
      });
    }
    await route
      .fulfill({ status: response.status, headers: Object.fromEntries(response.headers), body })
      .catch(() => {});
  });
  const count = (table: 'work_preparation' | 'work_copy_consent' | 'work_credential_attempt') =>
    f.DB.prepare('SELECT count(*) AS n FROM ' + table).first('n');
  const shots = new URL('../../artifacts/work-webmcp/', import.meta.url).pathname;
  await mkdir(shots, { recursive: true });
  try {
    await t.test(
      'real tool discovery is opt-in and file contents need separate exact-selection permission',
      async () => {
        await page.goto('https://work.test/work/source-review?lang=en');
        await expect(page.getByRole('radio', { name: /Synthetic code/ })).toBeVisible();
        assert.deepEqual(await api.names(), []);
        const assetPath = 'https://work.test/work/browser-assistant.js';
        assert.equal((await f.worker.fetch(assetPath)).status, 401);
        assert.equal(
          (await f.worker.fetch(assetPath, { headers: { 'Sec-Fetch-Site': 'cross-site' } })).status,
          403,
        );
        assert.equal((await f.worker.fetch(assetPath + '?owner=other')).status, 400);
        assert.equal((await f.worker.fetch(assetPath, { method: 'POST' })).status, 404);
        await page.locator('#work-assistant-enabled').check();
        await expect.poll(api.names).toContain('mikaki_select_work_files');
        assert.equal(
          (
            await api.call('mikaki_select_work_files', {
              source_id: 'personal',
              paths: ['preferences/writing.md'],
            })
          ).ok,
          true,
        );
        assert.equal((await api.call('mikaki_select_work_code', { source_id: 'code' })).ok, true);
        await expect(page.getByRole('checkbox', { name: /preferences\/writing.md/ })).toBeChecked();
        await expect(page.getByRole('radio', { name: /Synthetic code/ })).toBeChecked();
        assert.equal(
          (await api.call('mikaki_read_work_file', { file_index: 0 })).error,
          'content_not_permitted',
        );
        const inspected = await api.call('mikaki_inspect_work_selection');
        assert.equal(inspected.ok, true);
        assert(!JSON.stringify(inspected).includes('結論'));
        await expect(page.locator('pre').filter({ hasText: '結論から書く。' })).toBeVisible();
        await page.locator('#work-assistant-content').check();
        const content = await api.call('mikaki_read_work_file', { file_index: 0 });
        assert.equal(content.ok, true);
        assert.equal(content.result.content, '結論から書く。\n');
        assert(!JSON.stringify(content).includes('SYNTHETIC_UNSELECTED'));
        assert.equal(
          (
            await api.call('mikaki_select_work_files', {
              source_id: 'other-owner',
              paths: ['secret'],
            })
          ).error,
          'not_selected',
        );
        assert.equal(
          (
            await api.call('mikaki_select_work_files', {
              source_id: 'personal',
              paths: ['missing'],
            })
          ).error,
          'not_selected',
        );
        await auditAccessibility(page, 'work-webmcp-source');
        await page.screenshot({ path: shots + '/source-en.png', fullPage: true });
      },
    );
    let preparation = '';
    await t.test(
      'preparation uses the same Native operation; review tools create no copy consent or effects',
      async () => {
        const result = await api.call('mikaki_prepare_work_copy');
        assert.equal(result.ok, true);
        preparation = result.result.prepared;
        assert(preparation);
        assert.equal(await count('work_preparation'), 1);
        assert.equal(await count('work_copy_consent'), 0);
        assert.equal(await count('work_credential_attempt'), 0);
        await expect(
          page.getByRole('link', { name: 'Review preparation', exact: true }),
        ).toHaveAttribute('href', '/work/preparation-review?lang=en#' + preparation);
        await page.getByRole('link', { name: 'Review preparation', exact: true }).click();
        await expect(page.locator('[data-work-action="approve_copy"]')).toBeVisible();
        assert.deepEqual(await api.names(), []);
        await page.locator('#work-assistant-enabled').check();
        await expect.poll(api.names).toContain('mikaki_review_work_action');
        assert.deepEqual(
          (await api.call('mikaki_review_work_action', { action: 'approve_copy' })).result,
          { status: 'review_required', action: 'approve_copy' },
        );
        assert.equal(await count('work_copy_consent'), 0);
        await expect(page.locator('[data-work-action="approve_copy"]')).toBeDisabled();
        await expect(page.locator('[data-work-action="inspect_copy"]')).toBeFocused();
        assert.equal((await api.call('mikaki_inspect_work_selection')).ok, true);
        await page.locator('[data-work-confirmation="approve_copy"]').check();
        await page.locator('[data-work-action="approve_copy"]').click();
        assert.equal(await count('work_copy_consent'), 1);
        assert.equal(await count('work_credential_attempt'), 0);
        assert.deepEqual(
          (await api.call('mikaki_review_work_action', { action: 'withdraw_copy' })).result,
          { status: 'review_required', action: 'withdraw_copy' },
        );
        await expect(page.locator('[data-work-action="withdraw_copy"]')).toBeVisible();
        assert.equal(
          await f.DB.prepare('SELECT active FROM work_copy_consent LIMIT 1').first('active'),
          1,
        );
      },
    );
    await t.test(
      'selection changes clear content permission and a hidden screen rejects a late file reply',
      async () => {
        await page.setViewportSize({ width: 375, height: 900 });
        await page.goto('https://work.test/work/source-review?lang=ja');
        await expect(page.getByRole('radio', { name: /Synthetic code/ })).toBeVisible();
        await page.locator('#work-assistant-enabled').check();
        await expect.poll(api.names).toContain('mikaki_select_work_files');
        await api.call('mikaki_select_work_files', {
          source_id: 'personal',
          paths: ['preferences/writing.md'],
        });
        await page.locator('#work-assistant-content').check();
        await api.call('mikaki_select_work_files', {
          source_id: 'personal',
          paths: ['decisions/long.md'],
        });
        await expect(page.locator('#work-assistant-content')).not.toBeChecked();
        assert.equal(
          (await api.call('mikaki_read_work_file', { file_index: 0 })).error,
          'content_not_permitted',
        );
        await api.call('mikaki_select_work_files', {
          source_id: 'personal',
          paths: ['preferences/writing.md'],
        });
        await page.locator('#work-assistant-content').check();
        await page.screenshot({ path: shots + '/source-ja-mobile.png', fullPage: true });
        assert.equal(
          await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
          true,
        );
        const waiting = new Promise<void>((resolve) => {
          started = resolve;
        });
        held = true;
        const denied = api.call('mikaki_read_work_file', { file_index: 0 });
        await waiting;
        await page.locator('#work-assistant-content').uncheck();
        releaseRead();
        const deniedResult = await denied;
        assert.equal(deniedResult.ok, false);
        assert(!JSON.stringify(deniedResult).includes('結論'));
        await page.locator('#work-assistant-content').check();
        const hiddenWaiting = new Promise<void>((resolve) => {
          started = resolve;
        });
        held = true;
        const pending = api.call('mikaki_read_work_file', { file_index: 0 });
        await hiddenWaiting;
        await page.evaluate(() => (window as unknown as { hideWorkTools(): void }).hideWorkTools());
        releaseRead();
        assert.equal((await pending).ok, false);
        await expect.poll(api.names).toHaveLength(0);
        await expect(page.locator('#work-assistant-enabled')).not.toBeChecked();
        await expect(page.locator('pre')).toHaveCount(0);
        assert.equal(await count('work_preparation'), 1);
        assert.equal(await count('work_credential_attempt'), 0);
      },
    );
    await t.test(
      'fresh Native source revocation refuses plaintext and clears the sharing choice',
      async () => {
        await page.goto('https://work.test/work/source-review?lang=en');
        await expect(page.getByRole('radio', { name: /Synthetic code/ })).toBeVisible();
        await page.locator('#work-assistant-enabled').check();
        await expect.poll(api.names).toContain('mikaki_select_work_files');
        await api.call('mikaki_select_work_files', {
          source_id: 'personal',
          paths: ['preferences/writing.md'],
        });
        await page.locator('#work-assistant-content').check();
        await f.DB.prepare(
          "UPDATE work_source_access SET access_revision=access_revision+1 WHERE owner_id=? AND source_id='personal'",
        )
          .bind(f.first.account)
          .run();
        const result = await api.call('mikaki_read_work_file', { file_index: 0 });
        assert.equal(result.ok, false);
        assert(!JSON.stringify(result).includes('結論'));
        await expect(page.locator('#work-assistant-content')).not.toBeChecked();
        await expect(page.locator('pre')).toHaveCount(0);
      },
    );
    assert.deepEqual(errors, []);
    assert.equal(writes.filter((path) => path === '/work/preparations').length, 1);
  } finally {
    releaseRead();
    await browser.close();
    await f.close();
  }
});

test('copy progress exposes Native status and focuses confirmation without starting or stopping the job', async () => {
  const f = await copyJobFixture({ LOCAL_COPY_TRIGGER_DISABLED: 'true' });
  const browser = await chromium.launch({ args: ['--enable-blink-features=WebMCP,WebMCPTesting'] });
  try {
    assert.equal((await f.approve()).status, 200);
    const context = await browser.newContext();
    await browserTools(context);
    await context.addCookies([
      {
        name: '__Host-op-sso',
        value: 'synthetic-delivery-session',
        domain: 'work.test',
        path: '/',
        secure: true,
        httpOnly: true,
        sameSite: 'Lax',
      },
    ]);
    const writes: string[] = [];
    await context.route('https://work.test/**', async (route) => {
      const request = route.request(),
        url = new URL(request.url());
      if (request.method() !== 'GET' && url.pathname.endsWith('/copy'))
        writes.push(request.method());
      const response = await f.productFetch(url.pathname + url.search, {
        method: request.method(),
        headers: await request.allHeaders(),
        body: request.postData() ?? undefined,
      });
      await route.fulfill({
        status: response.status,
        headers: Object.fromEntries(response.headers),
        body: Buffer.from(await response.arrayBuffer()),
      });
    });
    const page = await context.newPage(),
      api = tools(page);
    await page.goto('https://work.test/work/copy-review?lang=en#' + f.p.id);
    await expect(page.locator('[data-work-action="start_copy"]')).toBeVisible();
    await page.locator('#work-assistant-enabled').check();
    await expect.poll(api.names).toHaveLength(3);
    assert.equal((await api.call('mikaki_get_work_state')).result.copy.state, 'not_started');
    assert.deepEqual(
      (await api.call('mikaki_review_work_action', { action: 'start_copy' })).result,
      { status: 'review_required', action: 'start_copy' },
    );
    await expect(page.locator('[data-work-action="start_copy"]')).toBeDisabled();
    await expect(page.locator('[data-work-confirmation="start_copy"]')).toBeFocused();
    assert.deepEqual(writes, []);
    await page.locator('[data-work-confirmation="start_copy"]').check();
    await page.locator('[data-work-action="start_copy"]').click();
    await expect(page.locator('[data-work-action="stop_copy"]')).toBeVisible();
    assert.deepEqual(writes, ['POST']);
    assert.equal((await api.call('mikaki_get_work_state')).result.copy.state, 'queued');
    assert.deepEqual(
      (await api.call('mikaki_review_work_action', { action: 'stop_copy' })).result,
      { status: 'review_required', action: 'stop_copy' },
    );
    assert.deepEqual(writes, ['POST']);
    assert.equal((await f.copy()).body.record.job.state, 'queued');
    assert.equal((await f.remote()).counts.create ?? 0, 0);
    await page.getByRole('button', { name: 'Lock review', exact: true }).click();
    await expect.poll(api.names).toHaveLength(0);
  } finally {
    await browser.close();
    await f.close();
  }
});
