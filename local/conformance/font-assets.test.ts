import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { chromium, webkit } from '@playwright/test';

const root = new URL('../../assets/fonts/', import.meta.url);
const manifest = JSON.parse(readFileSync(new URL('manifest.json', root), 'utf8')) as {
  subsetter: { lock_sha256: string };
  sources: { id: string; codepoints: number; variation_sequences: number }[];
  files: { file: string; family: string; range?: string; sha256: string; bytes: number }[];
};
const coverage = JSON.parse(readFileSync(new URL('coverage.json', root), 'utf8')) as {
  reference: { codepoints: number };
  styles: Record<
    'Mincho' | 'Gothic',
    {
      codepoints: number;
      variation_sequences: number;
      administrative_covered: number;
      administrative_missing: number;
      missing_codepoints: string[];
    }
  >;
};

test('Bunsen inventory preserves both styles and records the accepted administrative gap', () => {
  assert.deepEqual(
    manifest.sources.map(({ id, codepoints, variation_sequences }) => ({
      id,
      codepoints,
      variation_sequences,
    })),
    [
      { id: 'bunsen-mincho', codepoints: 64778, variation_sequences: 26259 },
      { id: 'bunsen-mincho-ext', codepoints: 50367, variation_sequences: 10068 },
      { id: 'bunsen-mincho-pup', codepoints: 6705, variation_sequences: 0 },
      { id: 'bunsen-gothic', codepoints: 64778, variation_sequences: 26259 },
      { id: 'bunsen-gothic-ext', codepoints: 50367, variation_sequences: 10068 },
      { id: 'bunsen-gothic-pup', codepoints: 6705, variation_sequences: 0 },
    ],
  );
  assert.equal(coverage.reference.codepoints, 9420);
  for (const style of ['Mincho', 'Gothic'] as const) {
    const result = coverage.styles[style];
    assert.equal(result.codepoints, 121850);
    assert.equal(result.variation_sequences, 26313);
    assert.equal(result.administrative_covered, 6705);
    assert.equal(result.administrative_missing, 2715);
    assert.equal(result.missing_codepoints.length, 2715);
    assert.equal(new Set(result.missing_codepoints).size, 2715);
    assert.ok(result.missing_codepoints.includes('U+10030B'));
  }
  assert.deepEqual(
    coverage.styles.Mincho.missing_codepoints,
    coverage.styles.Gothic.missing_codepoints,
  );
  for (const license of ['Bunsen-CC0.txt', 'Bunsen-FONTLOG.txt', 'Inter-OFL.txt'])
    assert.ok(readFileSync(new URL(license, root)).byteLength > 0);
  assert.equal(
    manifest.subsetter.lock_sha256,
    createHash('sha256')
      .update(readFileSync(new URL('../../scripts/fonts.lock.json', import.meta.url)))
      .digest('hex'),
    'Font inputs/toolchain must match the committed lock',
  );
  assert.deepEqual(
    readdirSync(root).sort(),
    [
      ...manifest.files.map(({ file }) => file),
      'Bunsen-CC0.txt',
      'Bunsen-FONTLOG.txt',
      'Inter-OFL.txt',
      'NOTICE.txt',
      'coverage.json',
      'fonts.css',
      'manifest.json',
    ].sort(),
    'Only inventoried fonts and their metadata may be shipped',
  );
  for (const file of manifest.files) {
    const bytes = readFileSync(new URL(file.file, root));
    assert.equal(bytes.subarray(0, 4).toString(), 'wOF2', file.file);
    assert.equal(bytes.length, file.bytes, file.file);
    assert.equal(createHash('sha256').update(bytes).digest('hex'), file.sha256, file.file);
  }
});

for (const engine of [chromium, webkit]) {
  test(`${engine.name()} renders both Bunsen stacks, IVS and PUP, and decodes every chunk`, async () => {
    const files = new Map(
      manifest.files.map((file) => [`/fonts/${file.file}`, readFileSync(new URL(file.file, root))]),
    );
    files.set('/fonts/fonts.css', readFileSync(new URL('fonts.css', root)));
    const html = `<!doctype html><html lang="ja"><meta charset="utf-8"><link rel="stylesheet" href="/fonts/fonts.css"><style>body{padding:24px}p{font-size:32px;margin:12px 0}textarea{font:inherit;max-width:100%}</style><h1>Bunsen / Inter</h1><p id="latin">Identity on your terms.</p><p id="latin-italic" style="font-style:italic;font-weight:600">Your information. In your hands.</p><p id="japanese">氏名 葛 葛󠄂 葛󠄃 辻󠄂 𠮷</p><p id="extension">&#x31350;</p><p id="variation-base">&#x3402;</p><p id="base-ivs">&#x3402;&#xE0100;</p><p id="extension-ivs">&#x3614;&#xE0100;</p><p id="administrative">&#x100000;</p><p id="unsupported">&#x10030B;</p><textarea id="editor"></textarea></html>`;
    files.set('/', Buffer.from(html));
    files.set('/favicon.ico', Buffer.alloc(0));
    const requested: string[] = [];
    const server = createServer((request, response) => {
      const path = new URL(request.url ?? '/', 'http://localhost').pathname;
      const data = files.get(path);
      if (!data) {
        response.writeHead(404).end();
        return;
      }
      requested.push(path);
      response.writeHead(200, {
        'Content-Type': path.endsWith('.css')
          ? 'text/css'
          : path.endsWith('.woff2')
            ? 'font/woff2'
            : 'text/html; charset=utf-8',
      });
      response.end(data);
    });
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    const address = server.address();
    assert.ok(address && typeof address === 'object');
    const browser = await engine.launch({ headless: true });
    const evidence = new URL(`../../artifacts/font-rendering/${engine.name()}/`, import.meta.url);
    mkdirSync(evidence, { recursive: true });
    const context = await browser.newContext({
      viewport: { width: 1000, height: 1000 },
      deviceScaleFactor: 2,
    });
    await context.tracing.start({ screenshots: true, snapshots: true });
    const diagnostics: unknown[] = [];
    try {
      const page = await context.newPage();
      const errors: string[] = [];
      page.on('console', (message) => {
        if (message.type() === 'error') errors.push(message.text());
      });
      page.on('pageerror', (error) => errors.push(error.message));
      await page.goto(`http://127.0.0.1:${address.port}/`);
      const cdp = engine === chromium ? await context.newCDPSession(page) : undefined;
      if (cdp) {
        await cdp.send('DOM.enable');
        await cdp.send('CSS.enable');
      }
      for (const style of ['Mincho', 'Gothic']) {
        await page.locator('#editor').fill('');
        await page.evaluate((style) => {
          document.documentElement.dataset.fontFamily = style.toLowerCase();
        }, style);
        await page.evaluate(async () => {
          await document.fonts.ready;
        });
        const samples = [
          ['#latin', 'Mikaki Latin'],
          ['#latin-italic', 'Mikaki Latin'],
          ['#extension', `Mikaki Bunsen ${style}`],
          ['#variation-base', `Mikaki Bunsen ${style}`],
          ['#base-ivs', `Mikaki Bunsen ${style}`],
          ['#extension-ivs', `Mikaki Bunsen ${style}`],
          ['#administrative', `Mikaki Bunsen ${style}`],
        ];
        for (const [selector, expected] of samples) {
          // CSS Font Loading plus a same-engine canvas comparison works in WebKit
          // as well as Chromium. CDP below adds a Chromium platform-font check.
          const result = await page.evaluate(
            async ({ selector, expected }) => {
              const element = document.querySelector(selector)!;
              const text = element.textContent!;
              const computed = getComputedStyle(element);
              const loaded = await document.fonts.load(
                `${computed.fontStyle} ${computed.fontWeight} 48px "${expected}"`,
                text,
              );
              const render = (value: string, family: string) => {
                const canvas = document.createElement('canvas');
                canvas.width = 1400;
                canvas.height = 100;
                const ctx = canvas.getContext('2d')!;
                ctx.font = `${computed.fontStyle} ${computed.fontWeight} 48px ${family}`;
                ctx.fillText(value, 10, 65);
                const pixels = ctx.getImageData(0, 0, canvas.width, canvas.height).data;
                let hash = 2166136261;
                for (const byte of pixels) hash = Math.imul(hash ^ byte, 16777619);
                return `${ctx.measureText(value).width}:${hash >>> 0}`;
              };
              return {
                loaded: loaded.length,
                actual: render(text, getComputedStyle(element).fontFamily),
                expected: render(text, `"${expected}"`),
                fallback: render('\u{10ffff}', `"${expected}"`),
              };
            },
            { selector, expected },
          );
          assert.ok(result.loaded > 0, `${selector}: expected font was not loaded`);
          assert.equal(
            result.actual,
            result.expected,
            `${style} ${selector}: wrong glyph/fallback`,
          );
          assert.notEqual(
            result.actual,
            result.fallback,
            `${selector}: unexpected system fallback`,
          );
          const target = page.locator(selector);
          // DOM font fallback can differ from Canvas in WebKit. Compare text
          // advances independently of the primary font's line-box metrics.
          const actualDOM = await target.evaluate((element) => {
            const range = document.createRange();
            range.selectNodeContents(element);
            return range.getBoundingClientRect().width;
          });
          const originalFamily = await target.evaluate(
            (element) => (element as HTMLElement).style.fontFamily,
          );
          await target.evaluate((element, family) => {
            (element as HTMLElement).style.fontFamily = `"${family}"`;
          }, expected);
          await page.evaluate(async () => {
            await document.fonts.ready;
          });
          const expectedDOM = await target.evaluate((element) => {
            const range = document.createRange();
            range.selectNodeContents(element);
            return range.getBoundingClientRect().width;
          });
          await target.evaluate((element, family) => {
            (element as HTMLElement).style.fontFamily = family;
          }, originalFamily);
          assert.ok(
            Math.abs(actualDOM - expectedDOM) < 0.02,
            `${style} ${selector}: DOM advance ${actualDOM} differs from expected ${expectedDOM}`,
          );
          diagnostics.push({ style, selector, family: expected, ...result });
          if (cdp) {
            const { root: documentNode } = await cdp.send('DOM.getDocument');
            const { nodeId } = await cdp.send('DOM.querySelector', {
              nodeId: documentNode.nodeId,
              selector,
            });
            const { fonts } = await cdp.send('CSS.getPlatformFontsForNode', { nodeId });
            assert.ok(
              fonts.some(
                (font) =>
                  font.isCustomFont &&
                  (font.familyName === expected ||
                    font.familyName === expected.replace('Mikaki Bunsen ', 'Bunsen') ||
                    (expected === 'Mikaki Latin' && font.familyName === 'Inter Variable')),
              ),
              JSON.stringify(fonts),
            );
            assert.ok(
              fonts.every((font) => font.isCustomFont),
              `${selector}: unexpected system fallback`,
            );
          }
        }
        const distinctions = await page.evaluate(async (style) => {
          const family = `Mikaki Bunsen ${style}`;
          await document.fonts.load(`48px "${family}"`, '葛󠄂葛󠄃');
          await document.fonts.load(`48px "${family}PUP"`, '\u{100000}\u{100001}');
          const render = (text: string, font: string) => {
            const canvas = document.createElement('canvas');
            canvas.width = 100;
            canvas.height = 100;
            const ctx = canvas.getContext('2d')!;
            ctx.font = `48px "${font}"`;
            ctx.fillText(text, 10, 65);
            return canvas.toDataURL();
          };
          return {
            ivs: render('葛󠄂', family) !== render('葛󠄃', family),
            pup: render('\u{100000}', family) !== render('\u{100001}', family),
          };
        }, style);
        assert.deepEqual(
          distinctions,
          { ivs: true, pup: true },
          'IVS variants and PUP glyphs must remain distinct',
        );
        const dynamicCodepoint = 0x30000;
        const dynamicFont = manifest.files.find(
          (file) =>
            file.family === `Mikaki Bunsen ${style}` &&
            file.range?.split(',').some((range) => {
              const [start, end = start] = range.slice(2).split('-');
              return (
                dynamicCodepoint >= parseInt(start!, 16) && dynamicCodepoint <= parseInt(end!, 16)
              );
            }),
        );
        assert.ok(dynamicFont, 'The dynamic editor sample must have a shipped font');
        assert.ok(
          !requested.includes(`/fonts/${dynamicFont.file}`),
          'The editor sample must require a previously unloaded chunk',
        );
        const dynamicRequest = page.waitForRequest((request) =>
          request.url().endsWith(`/${dynamicFont.file}`),
        );
        await page.locator('#editor').fill(`${String.fromCodePoint(dynamicCodepoint)} 𠮷 葛󠄂`);
        await dynamicRequest;
        await page.evaluate(async () => {
          await document.fonts.ready;
        });
        for (const width of [1000, 390]) {
          await page.setViewportSize({ width, height: 1000 });
          await page.screenshot({
            path: new URL(`${style.toLowerCase()}-${width}.png`, evidence).pathname,
            fullPage: true,
          });
        }
      }
      assert.equal(
        await page.locator('#unsupported').textContent(),
        String.fromCodePoint(0x10030b),
        'Unsupported characters must retain their original codepoint',
      );
      const fontRequests = requested.filter((path) => path.endsWith('.woff2'));
      assert.ok(
        fontRequests.length <= 24,
        `IVS downloaded unrelated chunks: ${fontRequests.length}`,
      );
      diagnostics.push({
        requests: fontRequests,
        bytes: fontRequests.reduce((sum, path) => sum + files.get(path)!.length, 0),
      });
      const failures = await page.evaluate(
        async (names) => {
          const failed: string[] = [];
          for (let start = 0; start < names.length; start += 16) {
            await Promise.all(
              names.slice(start, start + 16).map(async (name, index) => {
                try {
                  await new FontFace(`decode-${start + index}`, `url('/fonts/${name}')`).load();
                } catch {
                  failed.push(name);
                }
              }),
            );
          }
          return failed;
        },
        manifest.files.map(({ file }) => file),
      );
      assert.deepEqual(failures, [], 'All chunks must pass the browser font sanitizer');
      assert.deepEqual(errors, []);
    } finally {
      writeFileSync(new URL('results.json', evidence), JSON.stringify(diagnostics, null, 2) + '\n');
      await context.tracing.stop({ path: new URL('trace.zip', evidence).pathname });
      await browser.close();
      server.close();
      await once(server, 'close');
    }
  });
}
