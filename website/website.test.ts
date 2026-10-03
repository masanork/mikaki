import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdir, readFile } from 'node:fs/promises';
import { chromium } from '@playwright/test';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { auditPublicWebsite } from './audit-public.ts';

test('public websites keep app callbacks code-free and render the woven material', async () => {
  const servers: ReturnType<typeof spawn>[] = [];
  async function start(config: string) {
    const child = spawn('node_modules/.bin/wrangler', ['dev', '--config', config, '--port', '0'], {
      cwd: new URL('../', import.meta.url).pathname,
      env: { ...process.env, WRANGLER_SEND_METRICS: 'false' },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    servers.push(child);
    const origin = await new Promise<string>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('Worker startup timed out')), 30_000);
      let output = '';
      const consume = (chunk: Buffer) => {
        output = (output + chunk.toString()).slice(-16_384);
        const match = output.match(/Ready on (http:\/\/[^\s]+)/);
        if (match) {
          clearTimeout(timer);
          resolve(match[1]);
        }
      };
      child.stdout!.on('data', consume);
      child.stderr!.on('data', consume);
      child.on('exit', (code) => {
        clearTimeout(timer);
        reject(new Error(`Worker exited ${code}: ${output}`));
      });
    });
    return {
      fetch(url: string, init?: RequestInit) {
        const target = new URL(url);
        return fetch(`${origin}${target.pathname}${target.search}`, init);
      },
    };
  }
  let browser;
  try {
    const app = await start('website/wrangler.app.jsonc');
    const site = await start('website/wrangler.jsonc');
    const callback = await app.fetch(
      'https://app.mikaki.org/oidc/native/callback?code=secret-code&state=secret-state',
      { redirect: 'manual' },
    );
    assert.equal(callback.status, 303);
    assert.equal(callback.headers.get('location'), '/native-link-help');
    assert.equal(callback.headers.get('cache-control'), 'no-store');
    assert.equal(callback.headers.get('referrer-policy'), 'no-referrer');
    assert.equal(await callback.text(), '');
    for (const path of ['/authorize', '/token', '/jwks', '/.well-known/apple-app-site-association'])
      assert.equal((await app.fetch(`https://app.mikaki.org${path}`)).status, 404);
    assert.equal(
      (await app.fetch('https://app.mikaki.org/oidc/native/callback', { method: 'POST' })).status,
      404,
    );
    const association = await app.fetch('https://app.mikaki.org/.well-known/assetlinks.json');
    assert.equal(association.status, 200, JSON.stringify(Object.fromEntries(association.headers)));
    const links = await association.json();
    const op = JSON.parse(
      await readFile(
        new URL('../crates/worker/wrangler.production.jsonc', import.meta.url),
        'utf8',
      ),
    );
    assert.deepEqual(links, [
      {
        relation: ['delegate_permission/common.handle_all_urls'],
        target: {
          namespace: 'android_app',
          package_name: 'app.tossa.mikaki',
          sha256_cert_fingerprints: [op.vars.MIKAKI_ANDROID_SHA256_CERT_FINGERPRINT],
        },
      },
    ]);
    const manifest = JSON.parse(await readFile(new URL('pages.json', import.meta.url), 'utf8')) as {
      slug: string;
    }[];
    const paths = ['ja', 'en'].flatMap((lang) =>
      manifest.map(({ slug }) => `/${lang === 'en' ? 'en/' : ''}${slug === 'index' ? '' : slug}`),
    );
    const fixtures = new Map<string, Response>();
    const audit = await auditPublicWebsite(async (url) => {
      const response = await site.fetch(url);
      fixtures.set(new URL(url).pathname, response.clone());
      return response;
    }, paths);
    assert.equal(audit.pages.length, paths.length);
    for (const failure of [
      {
        path: '/getting-started',
        from: '/screenshots/onboarding/enroll-ja.png',
        to: '/screenshots/onboarding/missing.png',
        error: /expected 200/,
      },
      {
        path: '/en/',
        from: 'rel="canonical" href="https://mikaki.org/en/"',
        to: 'rel="canonical" href="https://mikaki.org/"',
        error: /canonical/,
      },
      {
        path: '/getting-started',
        from: 'hreflang="en" href="https://mikaki.org/en/getting-started"',
        to: 'hreflang="en" href="https://mikaki.org/en/faq"',
        error: /hreflang/,
      },
      {
        path: '/vault',
        from: '</main>',
        to: '<a href="/faq#missing-section">More</a></main>',
        error: /missing fragment/,
      },
      {
        path: '/en/vault',
        from: '</main>',
        to: '<a href="/not-published">More</a></main>',
        error: /link missing from sitemap/,
      },
      {
        path: '/',
        from: '<script type="application/ld+json"',
        to: '<script type="application/json"',
        error: /structured data/,
      },
    ]) {
      await assert.rejects(
        auditPublicWebsite(async (url) => {
          const path = new URL(url).pathname;
          const response = fixtures.get(path)?.clone() ?? new Response('', { status: 404 });
          if (path !== failure.path) return response;
          const html = await response.text();
          assert.ok(html.includes(failure.from));
          return new Response(html.replaceAll(failure.from, failure.to), {
            headers: response.headers,
          });
        }, paths),
        failure.error,
      );
    }
    await assert.rejects(
      auditPublicWebsite(async (url) => {
        const response = fixtures.get(new URL(url).pathname)!.clone();
        if (new URL(url).pathname !== '/') return response;
        const headers = new Headers(response.headers);
        headers.set('X-Robots-Tag', 'noindex');
        return new Response(await response.arrayBuffer(), { headers });
      }, paths),
      /noindex/,
    );
    await assert.rejects(
      auditPublicWebsite(async (url) => {
        const response = fixtures.get(new URL(url).pathname)!.clone();
        if (new URL(url).pathname !== '/') return response;
        const headers = new Headers(response.headers);
        headers.set('Content-Security-Policy', "script-src 'self'");
        return new Response(await response.arrayBuffer(), { headers });
      }, paths),
      /JSON-LD blocked by CSP/,
    );
    for (const path of paths) {
      const response = await site.fetch(`https://mikaki.org${path}`);
      assert.equal(response.status, 200, path);
      const html = await response.text();
      assert.ok(html.includes(`rel="canonical" href="https://mikaki.org${path}"`), path);
      assert.match(html, /hreflang="en"/);
      assert.match(html, /application\/ld\+json/);
      assert.match(response.headers.get('content-security-policy') ?? '', /sha256-/);
      assert.ok(!html.includes('mikaki.tossa.app'));
      assert.doesNotMatch(html, /href="(?:integration|security)\.(?:html|md)"/);
      if (path === '/' || path === '/en/') {
        const prefix = path === '/' ? '' : 'en/';
        assert.ok(html.includes(`href="/${prefix}integration"`));
        assert.ok(html.includes(`href="/${prefix}security"`));
      }
    }
    for (const path of [
      '/sitemap.xml',
      '/robots.txt',
      '/llms.txt',
      '/catalog.jsonld',
      '/index.md',
      '/en/index.md',
    ])
      assert.equal((await site.fetch(`https://mikaki.org${path}`)).status, 200, path);
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();
    const errors: string[] = [];
    page.on('pageerror', (error) => errors.push(error.message));
    await page.route('https://**.mikaki.org/**', async (route) => {
      const req = route.request();
      const worker = new URL(req.url()).host === 'app.mikaki.org' ? app : site;
      const response = await worker.fetch(req.url(), { redirect: 'manual' });
      await route.fulfill({
        status: response.status,
        headers: Object.fromEntries(response.headers),
        body: Buffer.from(await response.arrayBuffer()),
      });
    });
    // The root host is also routed through the real static-assets Worker.
    await page.route('https://mikaki.org/**', async (route) => {
      const response = await site.fetch(route.request().url());
      await route.fulfill({
        status: response.status,
        headers: Object.fromEntries(response.headers),
        body: Buffer.from(await response.arrayBuffer()),
      });
    });
    await mkdir(new URL('../artifacts/website-preview/', import.meta.url), { recursive: true });
    for (const width of [1440, 375]) {
      await page.setViewportSize({ width, height: 900 });
      const previews = paths.map((path) => [
        'mikaki.org',
        path,
        `${path.replace(/^\/(en\/)?/, '') || 'landing'}${path.startsWith('/en/') ? '-en' : ''}`,
      ]);
      previews.push(
        ['app.mikaki.org', '/', 'app'],
        ['app.mikaki.org', '/native-link-help', 'app-help'],
      );
      for (const [host, path, name] of previews) {
        await page.goto(`https://${host}${path}`);
        await page.locator('h1').waitFor();
        await page.waitForFunction(
          () => document.querySelector('.scene')?.getAttribute('data-renderer') === 'canvas',
        );
        for (const image of await page.locator('.prose img').all()) {
          await image.scrollIntoViewIfNeeded();
          await image.evaluate((element: HTMLImageElement) => element.decode());
          assert.ok(await image.evaluate((element: HTMLImageElement) => element.naturalWidth > 0));
        }
        await page.evaluate(() => scrollTo(0, 0));
        assert.equal(await page.locator('.plaque').textContent(), host);
        assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
        await page.screenshot({
          path: new URL(`../artifacts/website-preview/${name}-${width}.png`, import.meta.url)
            .pathname,
          fullPage: true,
        });
      }
    }
    // A transient fractional scene must still allocate a drawable backing canvas.
    await page.goto('https://mikaki.org');
    await page.waitForFunction(() => document.querySelector('canvas')!.width > 0);
    await page.evaluate(() => {
      const scene = document.querySelector<HTMLElement>('.scene')!;
      scene.style.width = '0.1px';
      scene.style.height = '0.1px';
      scene.style.minHeight = '0';
    });
    await page.waitForFunction(
      () =>
        document.querySelector('canvas')!.width === 1 &&
        document.querySelector('canvas')!.height === 1,
    );
    // An emptied backing store must not crash an animation before the next resize.
    await page.evaluate(() => {
      document.querySelector('canvas')!.width = 0;
    });
    await page.waitForTimeout(150);
    await page.evaluate(() => {
      const scene = document.querySelector<HTMLElement>('.scene')!;
      scene.style.removeProperty('width');
      scene.style.removeProperty('height');
      scene.style.removeProperty('min-height');
    });
    await page.waitForFunction(() => document.querySelector('canvas')!.width > 1);
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await page.goto('https://mikaki.org');
    await page.waitForFunction(() => document.querySelector('canvas')!.width > 0);
    const frame = await page
      .locator('canvas')
      .evaluate((canvas) => (canvas as HTMLCanvasElement).toDataURL());
    await page.waitForTimeout(300);
    assert.equal(
      await page.locator('canvas').evaluate((canvas) => (canvas as HTMLCanvasElement).toDataURL()),
      frame,
    );
    assert.deepEqual(errors, []);
    const staticPage = await browser.newPage({ javaScriptEnabled: false });
    await staticPage.route('https://mikaki.org/**', async (route) => {
      const response = await site.fetch(route.request().url());
      await route.fulfill({
        status: response.status,
        headers: Object.fromEntries(response.headers),
        body: Buffer.from(await response.arrayBuffer()),
      });
    });
    await staticPage.goto('https://mikaki.org');
    assert.equal(await staticPage.locator('h1').textContent(), '自分の情報を、自分の手元に。');
    const proseLink = staticPage.locator('.prose p a').first();
    assert.equal(
      await proseLink.evaluate((link) => getComputedStyle(link).textDecorationLine),
      'underline',
    );
    const integrationLink = staticPage.locator('.prose li a[href="/integration"]');
    const navigation = staticPage.waitForResponse(
      (response) => response.url() === 'https://mikaki.org/integration',
    );
    await integrationLink.click();
    assert.equal((await navigation).status(), 200);
    assert.equal(new URL(staticPage.url()).pathname, '/integration');
    await staticPage.goto('https://mikaki.org');
    assert.equal(
      await staticPage.locator('.bolt').getAttribute('href'),
      'https://auth.mikaki.org/signin',
    );
    await staticPage.locator('.actions a[href="/getting-started"]').click();
    assert.equal(new URL(staticPage.url()).pathname, '/getting-started');
    assert.equal(await staticPage.locator('nav [aria-current="page"]').textContent(), 'はじめ方');
    assert.ok((await staticPage.locator('main').textContent())?.includes('招待コード'));
    // Section navigation must work with JavaScript disabled in both locales.
    for (const [path, label, title] of [
      ['/integration', 'このページの内容', '接続できないときの確認順序'],
      ['/en/integration', 'On this page', 'When integration fails'],
    ]) {
      await staticPage.goto(`https://mikaki.org${path}`);
      const contents = staticPage.getByRole('navigation', { name: label, exact: true });
      const link = contents.getByRole('link', { name: title, exact: true });
      await link.focus();
      await staticPage.keyboard.press('Enter');
      const target = staticPage.locator('h2:target');
      assert.equal(await target.innerText(), `${title}#`);
      assert.ok(await target.evaluate((heading) => heading.getBoundingClientRect().top >= 0));
      assert.ok(
        await target.evaluate((heading) => heading.getBoundingClientRect().top < innerHeight),
      );
    }
  } finally {
    await browser?.close();
    await Promise.all(
      servers.map(async (child) => {
        child.kill('SIGTERM');
        if (child.exitCode === null) await once(child, 'exit');
      }),
    );
  }
});
