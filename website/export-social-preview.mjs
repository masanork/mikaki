import { chromium } from '@playwright/test';
import { readFile, mkdir } from 'node:fs/promises';

// Capture the public hero with its woven renderer; no external assets are fetched.
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
          '\n.site-header,.skip-link,.home-content,.site-footer,.actions,.hero-status,.motion-control{display:none!important}.hero{height:630px;min-height:630px}.hero-inner{padding:54px 72px}.hero-inner::before{content:"mikaki";display:block;font-size:26px;font-weight:650;margin-bottom:24px;color:#f4f8f2}',
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
