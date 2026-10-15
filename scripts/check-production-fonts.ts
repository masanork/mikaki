/** Read-only checks against the same public font bytes qualified by the build. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { chromium, webkit, type Response } from '@playwright/test';
import { diagnosticText } from '../local/conformance/support/browser-evidence.ts';

type Target = { name: string; origin: string; path: string };
type Manifest = { files: { file: string; sha256: string }[] };
const production: Target[] = [
  { name: 'website', origin: 'https://mikaki.org', path: '/' },
  { name: 'auth', origin: 'https://auth.mikaki.org', path: '/waitlist?lang=ja' },
  { name: 'docs', origin: 'https://docs.mikaki.org', path: '/session?lang=ja' },
];
const directory = 'artifacts/production-fonts';
const digest = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('hex');

async function within<T>(operation: Promise<T>, milliseconds = 30_000): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      operation,
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => reject(new Error('Public font loading timed out')), milliseconds);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

export async function checkProductionFonts(targets: Target[] = production) {
  await mkdir(directory, { recursive: true });
  const manifest = JSON.parse(
    await readFile(new URL('../assets/fonts/manifest.json', import.meta.url), 'utf8'),
  ) as Manifest;
  const expected = new Map(manifest.files.map((font) => [font.file, font.sha256]));
  const cssDigest = digest(await readFile(new URL('../assets/fonts/fonts.css', import.meta.url)));
  const results: Record<string, unknown>[] = [];
  const failures: string[] = [];
  const engines = [chromium, webkit];
  const checks = await Promise.allSettled(
    engines.map(async (engine) => {
      const browser = await engine.launch({ headless: true });
      try {
        for (const target of targets) {
          const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
          const page = await context.newPage();
          const fonts: Response[] = [];
          const pageErrors: string[] = [];
          page.on('pageerror', (error) => pageErrors.push(diagnosticText(error.message)));
          page.on('response', (response) => {
            if (new URL(response.url()).pathname.startsWith('/fonts/')) fonts.push(response);
          });
          try {
            const response = await page.goto(new URL(target.path, target.origin).href);
            assert.equal(response?.status(), 200, `${target.name}: public page must load`);
            assert.equal(
              new URL(page.url()).origin,
              target.origin,
              'font review must stay on site',
            );
            const loaded = await within(
              page.evaluate(async () => {
                await document.fonts.ready;
                const probes = [
                  ['16px "Mikaki Bunsen Mincho"', '行政事務標準文字 葛'],
                  ['16px "Mikaki Bunsen Gothic"', '行政事務標準文字 葛'],
                  ['500 16px "Mikaki Latin"', 'The quick brown fox 0123456789'],
                  ['italic 500 16px "Mikaki Latin"', 'The quick brown fox 0123456789'],
                ];
                const counts = await Promise.all(
                  probes.map(
                    async ([font, text]) => (await document.fonts.load(font!, text)).length,
                  ),
                );
                return {
                  bodyFamily: getComputedStyle(document.body).fontFamily,
                  counts,
                  errors: [...document.fonts]
                    .filter((font) => font.status === 'error')
                    .map((font) => font.family),
                };
              }),
            );
            assert.match(loaded.bodyFamily, /Mikaki Bunsen (Mincho|Gothic)/);
            assert.match(loaded.bodyFamily, /Mikaki Latin/);
            assert.ok(
              loaded.counts.every((count) => count > 0),
              'every font probe must load a face',
            );
            assert.deepEqual(loaded.errors, [], 'all requested public WOFF2 chunks must decode');
            await page.screenshot({
              path: join(directory, `${target.name}-${engine.name()}-desktop.png`),
              fullPage: true,
            });
            await page.setViewportSize({ width: 390, height: 844 });
            await within(page.evaluate(() => document.fonts.ready.then(() => undefined)));
            assert.equal(
              await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1),
              true,
              `${target.name}: public page must fit a narrow viewport`,
            );
            await page.screenshot({
              path: join(directory, `${target.name}-${engine.name()}-mobile.png`),
              fullPage: true,
            });
            let cssChecked = false;
            const checkedFonts = new Set<string>();
            for (const asset of fonts) {
              const url = new URL(asset.url());
              assert.equal(url.origin, target.origin, 'fonts must be self-hosted');
              assert.equal(asset.status(), 200);
              assert.equal(asset.headers()['x-content-type-options'], 'nosniff');
              const bytes = await asset.body();
              if (url.pathname === '/fonts/fonts.css') {
                assert.match(asset.headers()['content-type'] ?? '', /^text\/css/);
                assert.equal(digest(bytes), cssDigest, 'public CSS must match the reviewed build');
                cssChecked = true;
              } else if (url.pathname.endsWith('.woff2')) {
                const filename = url.pathname.slice('/fonts/'.length);
                assert.match(asset.headers()['content-type'] ?? '', /^font\/woff2/);
                assert.match(asset.headers()['cache-control'] ?? '', /max-age=31536000/);
                assert.match(asset.headers()['cache-control'] ?? '', /immutable/);
                assert.equal(
                  digest(bytes),
                  expected.get(filename),
                  `public WOFF2 bytes differ: ${filename}`,
                );
                checkedFonts.add(filename);
              }
            }
            assert.equal(cssChecked, true, 'the public page must use the reviewed font stylesheet');
            assert.ok(
              checkedFonts.size >= 4,
              'both Japanese styles and Latin styles must be fetched',
            );
            assert.deepEqual(pageErrors, []);
            results.push({
              target: target.name,
              engine: engine.name(),
              origin: target.origin,
              body_family: loaded.bodyFamily,
              checked_chunks: checkedFonts.size,
              passed: true,
            });
          } catch (error) {
            const failure = `${target.name}/${engine.name()}: ${diagnosticText(String(error))}`;
            failures.push(failure);
            results.push({
              target: target.name,
              engine: engine.name(),
              passed: false,
              error: failure,
            });
            await page
              .screenshot({ path: join(directory, `${target.name}-${engine.name()}-failure.png`) })
              .catch(() => {});
          } finally {
            await context.close();
          }
        }
      } finally {
        await browser.close();
      }
    }),
  );
  for (const [index, check] of checks.entries()) {
    if (check.status === 'rejected') {
      const error = `${engines[index]!.name()}: ${diagnosticText(String(check.reason))}`;
      failures.push(error);
      results.push({ engine: engines[index]!.name(), passed: false, error });
    }
  }
  await writeFile(
    join(directory, 'report.json'),
    JSON.stringify(
      { checked_at: new Date().toISOString(), css_sha256: cssDigest, results },
      null,
      2,
    ) + '\n',
  );
  assert.deepEqual(failures, [], 'Public font verification failed');
  console.log(`Public font delivery and rendering passed for ${results.length} browser/site pairs`);
}

if (import.meta.main) {
  const override = process.env.MIKAKI_FONT_SMOKE_BASE_URL;
  await checkProductionFonts(
    override ? [{ name: 'local', origin: new URL(override).origin, path: '/' }] : production,
  );
}
