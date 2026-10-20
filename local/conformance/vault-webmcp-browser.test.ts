import assert from 'node:assert/strict';
import { withRetiredOwnerUi } from './support/retired-owner-ui.ts';
import { test } from 'node:test';
import { createHash, randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { createTestHarness } from 'wrangler';
import { chromium, expect } from '@playwright/test';
import { activateWorkerPolicy } from '../../scripts/worker-policy-store.ts';
import { auditAccessibility } from './support/accessibility-audit.ts';

test('retired editor component exposes selected WebMCP data and review-only edits; hide, cancellation and revocation close tools', async () => {
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
  let releaseRead: (() => void) | undefined;
  try {
    await harness.listen();
    const worker = await withRetiredOwnerUi(harness.getWorker('mikaki-op-worker'));
    await worker.applyD1Migrations('DB');
    const { DB } = await worker.getEnv();
    await activateWorkerPolicy(
      DB,
      JSON.parse(
        await readFile(new URL('../generated/worker-policy.json', import.meta.url), 'utf8'),
      ),
      { actor: 'test', reason: 'WebMCP browser contract' },
    );
    const credential = randomBytes(32),
      id = credential.toString('base64url'),
      secret = randomBytes(32).toString('base64url'),
      now = Math.floor(Date.now() / 1000);
    await DB.batch([
      DB.prepare("INSERT INTO account_security VALUES('owner',1,1)"),
      DB.prepare("INSERT INTO credential VALUES(?,'owner',1)").bind(id),
      DB.prepare(
        "INSERT INTO passkey_credential VALUES(?,'synthetic-key','synthetic-user',0,0,0,1)",
      ).bind(id),
      DB.prepare("INSERT INTO sso_session VALUES('session','owner',?,1,?,0)").bind(id, now + 3600),
      DB.prepare("INSERT INTO sso_context VALUES('session',?,?)").bind(
        createHash('sha256').update(secret).digest('base64url'),
        now,
      ),
    ]);
    browser = await chromium.launch({ args: ['--enable-blink-features=WebMCP,WebMCPTesting'] });
    const context = await browser.newContext();
    await context.addInitScript(
      ({ credential }) => {
        const api = (
          document as Document & {
            modelContext: {
              getTools: () => Promise<{ name: string }[]>;
              executeTool: (tool: unknown, args: unknown) => Promise<unknown>;
            };
          }
        ).modelContext;
        Object.defineProperty(window, 'webMcpTest', {
          value: {
            names: async () => (await api.getTools()).map((tool) => tool.name),
            call: async (name: string, args: unknown) => {
              const tool = (await api.getTools()).find((tool) => tool.name === name);
              if (!tool) return { ok: false, error: 'missing' };
              try {
                const value = await api.executeTool(tool, args);
                return typeof value === 'string' ? JSON.parse(value) : value;
              } catch {
                return { ok: false, error: 'browser_cancelled' };
              }
            },
          },
        });
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
          value: { get: async () => new MockCredential() },
        });
      },
      { credential: [...credential] },
    );
    let holdRead = false,
      readStarted!: () => void;
    const started = new Promise<void>((resolve) => {
      readStarted = resolve;
    });
    const readGate = new Promise<void>((resolve) => {
      releaseRead = resolve;
    });
    const writes: string[] = [];
    await context.route(`${origin}/**`, async (route) => {
      const request = route.request(),
        path = new URL(request.url()).pathname;
      if (path.startsWith('/vault/records/') && request.method() === 'PUT')
        writes.push(request.postData()!);
      const response = await worker.fetch(request.url(), {
        method: request.method(),
        headers: { ...(await request.allHeaders()), cookie: `__Host-op-sso=${secret}` },
        ...(request.postData() ? { body: request.postData()! } : {}),
      });
      const body = Buffer.from(await response.arrayBuffer());
      if (holdRead && path.startsWith('/vault/records/threads/') && request.method() === 'GET') {
        holdRead = false;
        readStarted();
        await readGate;
      }
      await route.fulfill({
        status: response.status,
        headers: Object.fromEntries(response.headers),
        body,
      });
    });
    const page = await context.newPage();
    const errors: string[] = [];
    page.on('pageerror', (error) => errors.push(error.message));
    page.on('dialog', (dialog) => void dialog.accept());
    const names = () =>
      page.evaluate(() =>
        (window as unknown as { webMcpTest: { names: () => string[] } }).webMcpTest.names(),
      );
    const call = (name: string, args: unknown = {}) =>
      page.evaluate(
        ({ name, args }) =>
          (
            window as unknown as {
              webMcpTest: { call: (name: string, args: unknown) => Promise<any> };
            }
          ).webMcpTest.call(name, args),
        { name, args },
      );
    await page.goto(`${origin}/vault?lang=en`);
    await expect.poll(names).toHaveLength(2);
    assert.equal((await call('mikaki_get_vault_state')).result.unlocked, false);
    await page.locator('#unlock').click();
    await expect(page.locator('#owner-note-save')).toBeEnabled();
    await page.locator('#webmcp-enabled').check();
    await expect.poll(names).toHaveLength(8);
    assert.equal(
      (await call('mikaki_search_selected', { query: 'sentence' })).error,
      'not_selected',
    );
    for (const title of ['Allowed conversation', 'Unselected secret']) {
      await page.locator('#archive-file').setInputFiles({
        name: 'archive.json',
        mimeType: 'application/json',
        buffer: Buffer.from(
          JSON.stringify({
            format_version: 1,
            title,
            messages: [
              {
                speaker: 'Alice',
                actor: 'human',
                text: `A sentence about ${title}`,
                timestamp: '2026-10-12T00:00:00.000Z',
              },
            ],
          }),
        ),
      });
      await expect(page.getByRole('button', { name: title, exact: true })).toBeVisible();
      await expect(page.locator('#archive-file')).toBeEnabled();
    }
    await page.getByLabel('Allowed conversation', { exact: true }).check();
    await expect
      .poll(async () => (await call('mikaki_list_selected')).result?.records.length)
      .toBe(1);
    const listing = await call('mikaki_list_selected'),
      thread = listing.result.records[0];
    assert.equal(thread.title, 'Allowed conversation');
    assert(!JSON.stringify(listing).includes('Unselected secret'));
    const found = await call('mikaki_search_selected', { query: 'sentence' });
    assert.equal(found.ok, true);
    assert.equal(found.result.hits.length, 1);
    assert.equal(found.result.hits[0].thread, thread.thread_id);
    assert.equal(
      (await call('mikaki_read_selected', { target: 'thread', thread_id: 'forbidden' })).error,
      'not_selected',
    );
    assert.equal((await call('mikaki_read_selected', { target: 'name' })).error, 'not_selected');
    assert.equal(
      (await call('mikaki_open_selected_thread', { thread_id: thread.thread_id })).ok,
      true,
    );
    await expect(page.locator('#thread-title')).toHaveText('Allowed conversation');
    await page.locator('#webmcp-name').check();
    await page.locator('#webmcp-note').check();
    await expect
      .poll(async () => (await call('mikaki_get_vault_state')).result?.selected.note)
      .toBe(true);
    const beforeDraft = writes.length;
    assert.equal((await call('mikaki_prepare_name_edit', { name: 'Assistant name' })).ok, true);
    await expect(page.locator('#name')).toHaveValue('Assistant name');
    assert.equal(writes.length, beforeDraft);
    assert.equal(
      (await call('mikaki_prepare_note_edit', { title: 'Draft note', text: 'Draft text' })).error,
      'unsaved_changes',
    );
    assert.equal(
      (await call('mikaki_review_vault_action', { action: 'save_name' })).result.status,
      'review_required',
    );
    assert.equal(writes.length, beforeDraft);
    await page.locator('#save').click();
    await expect(page.locator('#archive-file')).toBeEnabled();
    await expect
      .poll(async () => (await call('mikaki_read_selected', { target: 'name' })).result?.text)
      .toBe('Assistant name');
    const beforeNote = writes.length;
    assert.equal(
      (await call('mikaki_prepare_note_edit', { title: 'Draft note', text: 'Draft text' })).ok,
      true,
    );
    await expect(page.locator('#owner-note-title')).toHaveValue('Draft note');
    await expect(page.locator('#owner-note-text')).toHaveValue('Draft text');
    assert.equal(writes.length, beforeNote);
    await page.locator('#owner-note-save').click();
    await expect(page.locator('#owner-note-save')).toBeEnabled();
    await expect
      .poll(async () => (await call('mikaki_read_selected', { target: 'owner_note' })).result?.text)
      .toBe('Draft text');
    await auditAccessibility(page, 'vault-webmcp');
    assert(
      writes.every((body) => !body.includes('Assistant name') && !body.includes('Draft text')),
    );
    await page.locator('#webmcp-enabled').uncheck();
    await expect.poll(names).toHaveLength(2);
    await page.locator('#webmcp-enabled').check();
    await expect
      .poll(async () => (await call('mikaki_list_selected')).result?.records.length)
      .toBe(0);
    await page.getByLabel('Allowed conversation', { exact: true }).check();
    await expect
      .poll(async () => (await call('mikaki_list_selected')).result?.records.length)
      .toBe(1);
    holdRead = true;
    await page.evaluate(
      ({ id }) => {
        const w = window as unknown as {
          webMcpTest: { call: (name: string, args: unknown) => Promise<unknown> };
          pendingWebMcp?: Promise<unknown>;
        };
        w.pendingWebMcp = w.webMcpTest.call('mikaki_read_selected', {
          target: 'thread',
          thread_id: id,
        });
      },
      { id: thread.thread_id },
    );
    await started;
    await page.evaluate(() =>
      (window as unknown as { setVaultHidden: (value: boolean) => void }).setVaultHidden(true),
    );
    await expect.poll(names).toHaveLength(0);
    releaseRead!();
    const cancelled = await page.evaluate(
      () => (window as unknown as { pendingWebMcp: Promise<any> }).pendingWebMcp,
    );
    assert.equal(cancelled.error, 'cancelled');
    await page.evaluate(() =>
      (window as unknown as { setVaultHidden: (value: boolean) => void }).setVaultHidden(false),
    );
    await expect.poll(names).toHaveLength(2);
    await expect(page.locator('#webmcp-enabled')).not.toBeChecked();
    await expect
      .poll(async () => (await call('mikaki_get_vault_state')).result?.selected.threads)
      .toBe(0);
    await DB.prepare("UPDATE account_security SET active=0 WHERE account_id='owner'").run();
    assert.equal((await call('mikaki_get_vault_state')).ok, false);
    await expect.poll(names).toHaveLength(0);
    assert.deepEqual(errors, []);
  } finally {
    releaseRead?.();
    await browser?.close();
    await harness.close();
  }
});

test('installed Chromium native WebMCP registers, discovers, executes and unregisters a tool', async (t) => {
  const browser = await chromium.launch({ args: ['--enable-blink-features=WebMCP,WebMCPTesting'] });
  try {
    const page = await browser.newPage();
    await page.route('https://mikaki.test/**', (route) =>
      route.fulfill({
        contentType: 'text/html',
        body: '<!doctype html><title>WebMCP native contract</title>',
      }),
    );
    await page.goto('https://mikaki.test/');
    const result = await page.evaluate(async () => {
      const api = (
        document as Document & {
          modelContext?: {
            registerTool: (tool: unknown, options: unknown) => Promise<void>;
            getTools: () => Promise<{ name: string }[]>;
            executeTool: (tool: unknown, args: unknown) => Promise<unknown>;
          };
        }
      ).modelContext;
      if (!api?.registerTool || !api.getTools || !api.executeTool) return { available: false };
      const controller = new AbortController();
      await api.registerTool(
        {
          name: 'mikaki_native_probe',
          description: 'Read a synthetic test value',
          inputSchema: {
            type: 'object',
            properties: { value: { type: 'string' } },
            required: ['value'],
          },
          annotations: { readOnlyHint: true },
          execute: async ({ value }: { value: string }) => ({ value }),
        },
        { signal: controller.signal },
      );
      const tool = (await api.getTools()).find((tool) => tool.name === 'mikaki_native_probe');
      if (!tool) throw new Error('Native tool discovery failed');
      const output = await api.executeTool(tool, { value: 'synthetic' });
      controller.abort();
      return {
        available: true,
        output: typeof output === 'string' ? JSON.parse(output) : output,
        removed: !(await api.getTools()).some((tool) => tool.name === 'mikaki_native_probe'),
      };
    });
    if (!result.available) {
      t.skip(
        `Chromium ${browser.version()} does not expose the current native API; app-contract coverage uses a registration shim`,
      );
      return;
    }
    assert.deepEqual(result.output, { value: 'synthetic' });
    assert.equal(result.removed, true);
  } finally {
    await browser.close();
  }
});
