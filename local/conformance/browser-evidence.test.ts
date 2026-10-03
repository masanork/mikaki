import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile, stat, rm } from 'node:fs/promises';
import { chromium } from '@playwright/test';
import { diagnosticText, startBrowserEvidence } from './support/browser-evidence.ts';
import { drainBrowserRoutes } from './support/browser-route-teardown.ts';

test('route teardown waits for callbacks before closing their page', async () => {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  let markStarted = () => {};
  const started = new Promise<void>((resolve) => {
    markStarted = resolve;
  });
  let releaseRequest = () => {};
  const held = new Promise<void>((resolve) => {
    releaseRequest = resolve;
  });
  let drained = false;
  let handled = false;
  let draining: Promise<void> | undefined;
  try {
    await page.setContent('<h1>Route teardown fixture</h1>');
    await page.route('https://fixture.test/held', async (route) => {
      markStarted();
      await held;
      // This browser-backed call must still work after teardown has started.
      const headers = await route.request().allHeaders();
      assert.ok(headers['user-agent']);
      await route.fulfill({ status: 200, body: 'done' });
      handled = true;
    });
    await page.evaluate(() => {
      const image = new Image();
      image.src = 'https://fixture.test/held';
      document.body.append(image);
    });
    await started;
    draining = drainBrowserRoutes(page).then(() => {
      drained = true;
    });
    // A browser round trip lets an incorrect non-waiting unroute settle without
    // an arbitrary timeout. The held callback must keep teardown pending.
    await page.evaluate(() => document.title);
    assert.equal(drained, false);
    assert.equal(page.isClosed(), false);
    releaseRequest();
    await draining;
    assert.equal(handled, true);
  } finally {
    releaseRequest();
    await (draining ?? drainBrowserRoutes(page));
    await browser.close();
  }
});

test('route teardown preserves errors instead of ignoring them', async () => {
  const failure = new Error('Synthetic route teardown failure');
  await assert.rejects(
    drainBrowserRoutes({
      async unrouteAll(options) {
        assert.deepEqual(options, { behavior: 'wait' });
        throw failure;
      },
    }),
    (error) => error === failure,
  );
});

test('browser evidence survives an assertion failure and discards passing traces', async () => {
  const browser = await chromium.launch({ headless: true });
  let directory: string | null = null;
  try {
    const context = await browser.newContext();
    const evidence = await startBrowserEvidence(context, 'evidence-self-check');
    const page = await context.newPage();
    await page.setContent('<h1>Synthetic evidence fixture</h1>');
    await page.evaluate(() =>
      console.error(`Synthetic failure https://fixture.test/callback?code=${'s'.repeat(43)}`),
    );
    directory = await evidence.finish(new Error(`Deliberate self-check failure ${'t'.repeat(43)}`));
    assert.ok(directory, 'A failed browser test must leave usable evidence');
    assert.ok((await stat(`${directory}/trace.zip`)).size > 0);
    assert.ok((await stat(`${directory}/page-0.png`)).size > 0);
    const diagnostics = await readFile(`${directory}/diagnostics.json`, 'utf8');
    assert.match(diagnostics, /Synthetic failure https:\/\/fixture.test\/callback/);
    assert.doesNotMatch(diagnostics, /code=|s{43}|t{43}/);
    assert.equal(await evidence.finish(new Error('Repeated cleanup')), null);
    const passing = await startBrowserEvidence(context, 'passing-evidence-self-check');
    assert.equal(await passing.finish(), null);
  } finally {
    await browser.close();
    // Only the disposable directory returned by this test's recorder is removed.
    if (directory) await rm(directory, { recursive: true });
  }
});

test('diagnostic summaries omit callback queries and bearer-like secrets', () => {
  assert.equal(
    diagnosticText(`GET https://fixture.test/callback?code=${'s'.repeat(43)}&state=private`),
    'GET https://fixture.test/callback',
  );
  assert.equal(diagnosticText(`Bearer ${'s'.repeat(43)}`), '[redacted]');
});
