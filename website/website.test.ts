import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdir, readFile } from 'node:fs/promises';
import { chromium } from '@playwright/test';
import { AxeBuilder } from '@axe-core/playwright';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { createHash } from 'node:crypto';
import { auditPublicWebsite, permitsScriptHash } from './audit-public.ts';

type HeaderRule = { path: string; lines: string[] };
const parseHeaderRules = (headers: string): HeaderRule[] =>
  headers
    .trim()
    .split(/\n\s*\n/)
    .map((block) => {
      const [path, ...lines] = block.split('\n');
      return { path, lines: lines.map((line) => line.trim()) };
    });

function policyForPath(rules: HeaderRule[], path: string, retainRootDefault = false) {
  let policies: string[] = [];
  for (const rule of rules) {
    if (rule.path !== '/*' && rule.path !== path) continue;
    for (const line of rule.lines) {
      if (line === '! Content-Security-Policy' && !(retainRootDefault && rule.path === '/'))
        policies = [];
      if (line.startsWith('Content-Security-Policy: '))
        policies.push(line.slice('Content-Security-Policy: '.length));
    }
  }
  return policies.join(', ');
}

test('generated website CSP avoids the deployed root detach bug and stays page-scoped', async () => {
  const headers = await readFile(new URL('public/_headers', import.meta.url), 'utf8');
  const rules = parseHeaderRules(headers);
  const manifest = JSON.parse(await readFile(new URL('pages.json', import.meta.url), 'utf8')) as {
    slug: string;
  }[];
  const paths = ['', 'en/'].flatMap((prefix) =>
    manifest.map(({ slug }) => `/${prefix}${slug === 'index' ? '' : slug}`),
  );
  assert.equal(rules[0].path, '/*');
  assert.deepEqual(
    rules.slice(1).map((rule) => rule.path),
    paths.filter((path) => path !== '/'),
  );
  assert.ok(rules.length <= 100);
  assert.ok(headers.split('\n').every((line) => line.length <= 2000));
  const baseline =
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'";
  for (const path of paths) {
    const file = path.endsWith('/') ? `${path}index.html` : `${path}.html`;
    const html = await readFile(new URL(`public${file}`, import.meta.url), 'utf8');
    const hashes = [
      ...html.matchAll(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/g),
    ].map((match) => `'sha256-${createHash('sha256').update(match[1]).digest('base64')}'`);
    assert.ok(hashes.length > 0, path);
    for (const retainRootDefault of [false, true]) {
      const csp = policyForPath(rules, path, retainRootDefault);
      assert.equal(csp.split(',').length, 1, `${path}: no intersecting default policy`);
      assert.equal(csp.replace(/ 'sha256-[^']+'/g, ''), baseline, path);
      assert.deepEqual(
        [...csp.matchAll(/'sha256-[^']+'/g)].map(([hash]) => hash).sort(),
        hashes.sort(),
        path,
      );
      for (const hash of hashes) assert.ok(permitsScriptHash(csp, hash), path);
    }
  }
  // Assets and missing pages retain all restrictions and only the root's required hashes.
  const rootPolicy = policyForPath(rules, '/', true);
  for (const path of ['/site.js', '/style.css', '/404.html', '/not-a-page'])
    assert.equal(policyForPath(rules, path, true), rootPolicy, path);
  const appHeaders = await readFile(new URL('app-public/_headers', import.meta.url), 'utf8');
  assert.equal(policyForPath(parseHeaderRules(appHeaders), '/'), baseline);
});

test('website CSP audit checks every policy and the effective script directive', () => {
  const hash = "'sha256-abc='";
  const allowed = `default-src 'none'; script-src 'self' ${hash}`;
  assert.ok(permitsScriptHash(allowed, hash));
  assert.ok(permitsScriptHash(`${allowed}, ${allowed}`, hash));
  assert.ok(permitsScriptHash(`${allowed}, frame-ancestors 'none'`, hash));
  assert.ok(permitsScriptHash(`default-src ${hash}`, hash));
  assert.ok(permitsScriptHash(`script-src 'none'; script-src-elem ${hash}`, hash));
  for (const csp of [
    null,
    '',
    `script-src 'self', ${allowed}`,
    `${allowed}, default-src 'none'`,
    `${allowed}; script-src-elem 'self'`,
    `script-src 'self'; script-src ${hash}`,
    `script-src 'self'; img-src ${hash}`,
    "script-src 'unsafe-inline'",
  ])
    assert.equal(permitsScriptHash(csp, hash), false, csp ?? 'missing CSP');

  // The old generated form passes local detach semantics but fails the deployed defect.
  const oldRules = parseHeaderRules(
    `/*\n  Content-Security-Policy: script-src 'self'\n\n/\n  ! Content-Security-Policy\n  Content-Security-Policy: ${allowed}\n`,
  );
  assert.ok(permitsScriptHash(policyForPath(oldRules, '/'), hash));
  assert.equal(permitsScriptHash(policyForPath(oldRules, '/', true), hash), false);
});

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
      async fetch(url: string, init?: RequestInit) {
        const target = new URL(url);
        const response = await fetch(`${origin}${target.pathname}${target.search}`, init);
        // Audits clone and retain fixtures, and some callers only inspect status.
        // Drain the local HTTP body before handing out reusable in-memory responses.
        // This keeps sockets/streams out of the later fault-injection and browser steps.
        try {
          const body = await response.arrayBuffer();
          return new Response([204, 205, 304].includes(response.status) ? null : body, {
            status: response.status,
            statusText: response.statusText,
            headers: response.headers,
          });
        } catch (cause) {
          throw new Error(`${config}: reading ${target.pathname}`, { cause });
        }
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
    for (const [host, worker] of [
      ['mikaki.org', site],
      ['app.mikaki.org', app],
    ] as const) {
      for (const lang of ['ja', 'en']) {
        const prefix = lang === 'ja' ? '' : '/en';
        for (const path of ['/missing-page', '/missing/nested-page']) {
          const response = await worker.fetch(`https://${host}${prefix}${path}`);
          assert.equal(response.status, 404);
          const html = await response.text();
          assert.ok(html.includes(`<html lang="${lang}">`));
          assert.ok(html.includes(lang === 'ja' ? 'ページが見つかりません' : 'Page not found'));
          assert.ok(html.includes('name="robots" content="noindex"'));
          const switchPath = lang === 'ja' ? '/en/404' : '/404';
          assert.ok(html.includes(`href="${switchPath}"`));
          const alternate = await worker.fetch(`https://${host}${switchPath}`);
          assert.equal(alternate.status, 200);
          assert.ok(
            (await alternate.text()).includes(`<html lang="${lang === 'ja' ? 'en' : 'ja'}">`),
          );
        }
      }
    }
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
    for (const retainedPolicy of ["script-src 'self'", "default-src 'none'"]) {
      await assert.rejects(
        auditPublicWebsite(async (url) => {
          const response = fixtures.get(new URL(url).pathname)!.clone();
          if (new URL(url).pathname !== '/') return response;
          const headers = new Headers(response.headers);
          // Reproduce a deployed duplicate field, not wrangler dev's successful detachment.
          headers.append('Content-Security-Policy', retainedPolicy);
          return new Response(await response.arrayBuffer(), { headers });
        }, paths),
        /JSON-LD blocked by CSP/,
      );
    }
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
    const context = await browser.newContext();
    const page = await context.newPage();
    const errors: string[] = [];
    page.on('pageerror', (error) => errors.push(error.message));
    page.on('console', (message) => {
      if (/content security policy/i.test(message.text())) errors.push(message.text());
    });
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
        ['app.mikaki.org', '/en/', 'app-en'],
        ['app.mikaki.org', '/en/native-link-help', 'app-help-en'],
      );
      for (const [host, path, name] of previews) {
        await page.goto(`https://${host}${path}`);
        await page.locator('h1').waitFor();
        if (await page.locator('canvas').count())
          await page.waitForFunction(
            () => document.querySelector('.scene')?.getAttribute('data-renderer') === 'canvas',
          );
        for (const image of await page.locator('.prose img').all()) {
          await image.scrollIntoViewIfNeeded();
          await image.evaluate((element: HTMLImageElement) => element.decode());
          assert.ok(await image.evaluate((element: HTMLImageElement) => element.naturalWidth > 0));
        }
        await page.evaluate(() => scrollTo(0, 0));
        assert.equal(await page.locator('main').count(), 1);
        assert.equal(await page.locator('h1').count(), 1);
        assert.equal(await page.locator('.primary-nav a').count(), 4);
        if (width === 1440) {
          const result = await new AxeBuilder({ page })
            .withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa'])
            .analyze();
          assert.deepEqual(
            result.violations.map(({ id, nodes }) => ({
              id,
              nodes: nodes.map(({ target, failureSummary }) => ({ target, failureSummary })),
            })),
            [],
            `${host}${path}: accessibility violations`,
          );
        }
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
    const motion = page.getByRole('button', { name: '背景の動きを停止', exact: true });
    await motion.click();
    assert.equal(await motion.getAttribute('aria-pressed'), 'true');
    const pausedFrame = await page
      .locator('canvas')
      .evaluate((canvas) => (canvas as HTMLCanvasElement).toDataURL());
    await page.waitForTimeout(300);
    assert.equal(
      await page.locator('canvas').evaluate((canvas) => (canvas as HTMLCanvasElement).toDataURL()),
      pausedFrame,
    );
    await page.reload();
    await page.waitForFunction(
      () => document.querySelector('.scene')?.getAttribute('data-paused') === 'true',
    );
    await motion.click();
    assert.equal(await motion.getAttribute('aria-pressed'), 'false');
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
    assert.ok(
      await page
        .getByRole('button', { name: '背景の動きを停止（端末設定）', exact: true })
        .isDisabled(),
    );
    // A 320-CSS-pixel viewport exercises the reflow width at 400% zoom on 1280px.
    // Apply WCAG text-spacing overrides and keep horizontal scrolling within code/tables.
    await page.setViewportSize({ width: 320, height: 900 });
    await page.route('https://mikaki.org/style.css', async (route) => {
      const response = await site.fetch(route.request().url());
      const headers = Object.fromEntries(response.headers);
      delete headers['content-length'];
      await route.fulfill({
        status: response.status,
        headers,
        body:
          (await response.text()) +
          '\n* { line-height: 1.5 !important; letter-spacing: .12em !important; word-spacing: .16em !important; } p { margin-bottom: 2em !important; }',
      });
    });
    for (const path of [
      '/',
      '/en/',
      '/api',
      '/en/specifications',
      '/getting-started',
      '/contact',
    ]) {
      await page.goto(`https://mikaki.org${path}`);

      assert.ok(
        await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
        `${path}: text spacing/reflow`,
      );
      assert.ok(await page.locator('h1').isVisible());
      assert.equal(await page.locator('.primary-nav a').count(), 4);
    }
    await page.unroute('https://mikaki.org/style.css');
    await page.goto('https://mikaki.org/api');
    const table = page.locator('.table-scroll').first();
    await table.focus();
    const beforeScroll = await table.evaluate((element) => element.scrollLeft);
    await page.keyboard.press('ArrowRight');
    await page.keyboard.press('ArrowRight');
    await page.waitForTimeout(200);
    assert.ok((await table.evaluate((element) => element.scrollLeft)) > beforeScroll);
    await page.emulateMedia({ forcedColors: 'active' });
    await page.goto('https://mikaki.org');
    assert.equal(
      await page.locator('canvas').evaluate((element) => getComputedStyle(element).display),
      'none',
    );
    await page.keyboard.press('Tab');
    const focus = await page.locator('.skip-link').evaluate((element) => ({
      width: getComputedStyle(element).outlineWidth,
      style: getComputedStyle(element).outlineStyle,
    }));
    assert.equal(focus.width, '3px');
    assert.equal(focus.style, 'solid');
    await page.emulateMedia({ forcedColors: 'none', media: 'print' });
    assert.equal(
      await page.locator('.site-header').evaluate((element) => getComputedStyle(element).display),
      'none',
    );
    assert.ok(await page.locator('h1').isVisible());
    await page.emulateMedia({ media: 'screen' });
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
    await staticPage.keyboard.press('Tab');
    assert.equal(await staticPage.evaluate(() => document.activeElement?.className), 'skip-link');
    await staticPage.keyboard.press('Enter');
    assert.equal(await staticPage.evaluate(() => document.activeElement?.id), 'main-content');
    const proseLink = staticPage.locator('.prose p a').first();
    assert.equal(
      await proseLink.evaluate((link) => getComputedStyle(link).textDecorationLine),
      'underline',
    );
    const integrationLink = staticPage.locator('.guide-card a[href="/integration"]');
    const navigation = staticPage.waitForResponse(
      (response) => response.url() === 'https://mikaki.org/integration',
    );
    await integrationLink.click();
    assert.equal((await navigation).status(), 200);
    assert.equal(new URL(staticPage.url()).pathname, '/integration');
    await staticPage.goto('https://mikaki.org');
    assert.equal(
      await staticPage
        .locator('.header-tools a[href^="https://auth.mikaki.org/signin"]')
        .getAttribute('href'),
      'https://auth.mikaki.org/signin',
    );
    await staticPage.locator('.actions a[href="/getting-started"]').click();
    assert.equal(new URL(staticPage.url()).pathname, '/getting-started');
    assert.equal(
      await staticPage.locator('.section-nav [aria-current="page"]').textContent(),
      'はじめ方',
    );
    assert.ok((await staticPage.locator('main').textContent())?.includes('招待コード'));
    // Section navigation must work with JavaScript disabled in both locales.
    for (const [path, label, title] of [
      ['/integration', 'このページの内容', '接続できないときの確認順序'],
      ['/en/integration', 'On this page', 'When integration fails'],
    ]) {
      await staticPage.goto(`https://mikaki.org${path}`);
      await staticPage.locator('.contents-disclosure summary').click();
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
