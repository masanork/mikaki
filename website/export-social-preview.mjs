import { chromium } from '@playwright/test';
import { readFile, mkdir } from 'node:fs/promises';

// Capture the existing hero with its woven renderer; no external assets are fetched.
// Run build:website first, then rebuild after updating these committed images.
const root = new URL('./', import.meta.url);
const browser = await chromium.launch({ headless: true });
try {
  const page = await browser.newPage({
    viewport: { width: 1200, height: 630 },
    deviceScaleFactor: 1,
    reducedMotion: 'reduce',
  });
  await page.route('**/*', async (route) => {
    const url = new URL(route.request().url());
    const files = {
      '/': 'index.html',
      '/en/': 'en/index.html',
      '/style.css': 'style.css',
      '/site.js': 'site.js',
      '/favicon.svg': 'favicon.svg',
    };
    if (url.origin !== 'https://mikaki.org' || !files[url.pathname]) {
      await route.abort();
      return;
    }
    const contentType = url.pathname.endsWith('.js')
      ? 'text/javascript'
      : url.pathname.endsWith('.css')
        ? 'text/css'
        : url.pathname.endsWith('.svg')
          ? 'image/svg+xml'
          : 'text/html';
    let body = await readFile(new URL(`public/${files[url.pathname]}`, root));
    if (url.pathname === '/style.css')
      body = Buffer.concat([
        body,
        Buffer.from(
          '\n.scene{height:630px;min-height:630px}main{padding-top:62px}.actions,.details,.prose,footer{display:none}',
        ),
      ]);
    await route.fulfill({ contentType, body });
  });
  await mkdir(new URL('social-preview/', root), { recursive: true });
  for (const lang of ['ja', 'en']) {
    await page.goto(`https://mikaki.org/${lang === 'en' ? 'en/' : ''}`);
    await page.evaluate(() => document.fonts.ready);
    await page.waitForFunction(
      () =>
        document.querySelector('.scene')?.getAttribute('data-renderer') === 'canvas' &&
        document.querySelector('canvas')?.height === 630,
    );
    await page.screenshot({ path: new URL(`social-preview/${lang}.png`, root).pathname });
  }
} finally {
  await browser.close();
}
