import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile, stat, rm } from 'node:fs/promises';
import { chromium } from '@playwright/test';
import { diagnosticText, startBrowserEvidence } from './support/browser-evidence.ts';

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
