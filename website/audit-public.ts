import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const origin = 'https://mikaki.org';
const decode = (text: string) =>
  text
    .replace(/&amp;/g, '&')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'");
const tags = (html: string, name: string) =>
  [...html.matchAll(new RegExp(`<${name}\\b[^>]*>`, 'g'))].map((match) =>
    Object.fromEntries(
      [...match[0].matchAll(/([\w:-]+)="([^"]*)"/g)].map((m) => [m[1], decode(m[2])]),
    ),
  );

/** Audit real responses, including internal links; never follow links outside the public site. */
export async function auditPublicWebsite(
  request: (url: string) => Promise<Response> = (url) =>
    fetch(url, { signal: AbortSignal.timeout(10_000) }),
  expectedPaths?: string[],
) {
  async function get(path: string, type: string) {
    const response = await request(`${origin}${path}`);
    assert.equal(response.status, 200, `${path}: expected 200`);
    assert.ok(response.headers.get('content-type')?.includes(type), `${path}: content type`);
    assert.doesNotMatch(
      response.headers.get('x-robots-tag') ?? '',
      /noindex|none/i,
      `${path}: noindex header`,
    );
    return response;
  }
  const sitemap = await (await get('/sitemap.xml', 'xml')).text();
  const urls = [...sitemap.matchAll(/<loc>([^<]+)<\/loc>/g)].map((m) => new URL(decode(m[1])));
  assert.ok(urls.length > 0 && urls.length <= 50, 'bounded nonempty sitemap');
  for (const url of urls) {
    assert.equal(url.origin, origin);
    assert.equal(url.search + url.hash, '');
    assert.doesNotMatch(url.pathname, /\.html$/);
  }
  const paths = urls.map((url) => url.pathname);
  assert.equal(new Set(paths).size, paths.length, 'duplicate sitemap URL');
  if (expectedPaths) assert.deepEqual([...paths].sort(), [...expectedPaths].sort());
  const robots = await (await get('/robots.txt', 'text/plain')).text();
  assert.ok(robots.includes(`Sitemap: ${origin}/sitemap.xml`));
  assert.doesNotMatch(robots, /^Disallow:\s*\/\s*$/m, 'site-wide crawl block');
  const catalog = await (await get('/catalog.jsonld', 'json')).text();
  JSON.parse(catalog);
  const llms = await (await get('/llms.txt', 'text/plain')).text();
  const pages = new Map<string, { title: string; html: string; links: string[] }>();
  const titles = new Set<string>();
  const images = new Map<string, { width: number; height: number }>();
  for (const path of paths) {
    const response = await get(path, 'text/html');
    const html = await response.text();
    const lang = path.startsWith('/en/') ? 'en' : 'ja';
    assert.ok(html.includes(`<html lang="${lang}">`), `${path}: language`);
    assert.equal((html.match(/<h1\b/g) ?? []).length, 1, `${path}: single h1`);
    const title = html.match(/<title>([^<]+)<\/title>/)?.[1];
    assert.ok(title && !titles.has(title), `${path}: missing or duplicate title`);
    titles.add(title);
    const meta = tags(html, 'meta');
    const links = tags(html, 'link');
    const value = (key: string) => meta.find((m) => m.name === key || m.property === key)?.content;
    assert.ok(value('description')?.trim(), `${path}: description`);
    assert.doesNotMatch(value('robots') ?? '', /noindex|none/i, `${path}: noindex meta`);
    assert.equal(
      links.find((l) => l.rel === 'canonical')?.href,
      `${origin}${path}`,
      `${path}: canonical`,
    );
    assert.equal(value('og:url'), `${origin}${path}`);
    for (const locale of ['ja', 'en', 'x-default']) {
      const slug = path.replace(/^\/en\//, '/');
      const target = locale === 'en' ? `/en${slug}` : slug;
      assert.equal(
        links.find((l) => l.hreflang === locale)?.href,
        `${origin}${target}`,
        `${path}: hreflang ${locale}`,
      );
    }
    const image = `${origin}/social-preview/${lang}.png`;
    assert.equal(value('og:image'), image);
    assert.equal(value('twitter:image'), image);
    assert.equal(value('twitter:card'), 'summary_large_image');
    assert.ok(value('og:image:alt')?.trim());
    assert.equal(
      links.find((l) => l.type === 'application/ld+json')?.href,
      '/catalog.jsonld',
      `${path}: catalog alternate`,
    );
    assert.equal(links.find((l) => l.rel === 'help')?.href, '/llms.txt', `${path}: discovery help`);
    const markdown = links.find((l) => l.type === 'text/markdown')?.href;
    assert.ok(markdown, `${path}: Markdown alternate`);
    const markdownUrl = new URL(markdown, `${origin}${path}`);
    assert.equal(markdownUrl.origin, origin);
    assert.ok((await (await get(markdownUrl.pathname, 'text/')).text()).length > 100);
    const scripts = [
      ...html.matchAll(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/g),
    ];
    assert.ok(scripts.length > 0, `${path}: structured data`);
    for (const script of scripts) {
      const data = JSON.parse(script[1]);
      assert.equal(data['@context'], 'https://schema.org');
      const hash = createHash('sha256').update(script[1]).digest('base64');
      assert.ok(
        response.headers.get('content-security-policy')?.includes(`'sha256-${hash}'`),
        `${path}: JSON-LD blocked by CSP`,
      );
    }
    for (const image of tags(html, 'img')) {
      assert.ok(image.alt?.trim(), `${path}: image alt`);
      const url = new URL(image.src, `${origin}${path}`);
      assert.equal(url.origin, origin, `${path}: image origin`);
      assert.equal(url.search + url.hash, '', `${path}: image URL`);
      if (!images.has(url.pathname)) {
        assert.ok(images.size < 100, 'bounded content images');
        const png = Buffer.from(await (await get(url.pathname, 'image/png')).arrayBuffer());
        assert.equal(png.subarray(0, 8).toString('hex'), '89504e470d0a1a0a');
        images.set(url.pathname, { width: png.readUInt32BE(16), height: png.readUInt32BE(20) });
      }
      const dimensions = images.get(url.pathname)!;
      assert.equal(Number(image.width), dimensions.width, `${path}: image width`);
      assert.equal(Number(image.height), dimensions.height, `${path}: image height`);
    }
    const anchors = tags(html, 'a').map((a) => new URL(a.href, `${origin}${path}`));
    for (const link of anchors) {
      if (
        lang === 'en' &&
        link.origin === 'https://auth.mikaki.org' &&
        ['/signin', '/enroll'].includes(link.pathname)
      )
        assert.equal(link.searchParams.get('lang'), 'en', `${path}: English authentication link`);
    }
    pages.set(path, {
      title,
      html,
      links: anchors.filter((a) => a.origin === origin).map((a) => a.href),
    });
    assert.ok(catalog.includes(`${origin}${path}`), `${path}: catalog`);
  }
  for (const [path, page] of pages) {
    for (const href of page.links) {
      const url = new URL(href);
      const target = pages.get(url.pathname);
      assert.ok(target, `${path}: link missing from sitemap: ${url.pathname}`);
      if (url.hash) {
        const id = decodeURIComponent(url.hash.slice(1));
        assert.ok(
          tags(target.html, '[a-zA-Z][a-zA-Z0-9]*').some((tag) => tag.id === id),
          `${path}: missing fragment ${href}`,
        );
      }
    }
  }
  const reached = new Set(['/']);
  const pending = ['/'];
  while (pending.length) {
    for (const href of pages.get(pending.shift()!)?.links ?? []) {
      const path = new URL(href).pathname;
      if (!reached.has(path)) {
        reached.add(path);
        pending.push(path);
      }
    }
  }
  assert.deepEqual([...reached].sort(), [...paths].sort(), 'orphan sitemap page');
  for (const lang of ['ja', 'en']) {
    const png = Buffer.from(
      await (await get(`/social-preview/${lang}.png`, 'image/png')).arrayBuffer(),
    );
    assert.equal(png.subarray(0, 8).toString('hex'), '89504e470d0a1a0a');
    assert.equal(png.readUInt32BE(16), 1200);
    assert.equal(png.readUInt32BE(20), 630);
  }
  for (const match of llms.matchAll(/\]\((https:\/\/mikaki\.org\/[^)]+)\)/g)) {
    const url = new URL(match[1]);
    if (!['/sitemap.xml', '/catalog.jsonld'].includes(url.pathname))
      assert.ok(pages.has(url.pathname), 'llms.txt page link');
  }
  return {
    origin,
    checked_at: new Date().toISOString(),
    pages: [...pages].map(([path, page]) => ({ path, title: page.title })),
    checks: [
      'metadata',
      'hreflang',
      'structured-data-csp',
      'internal-links',
      'reachability',
      'markdown',
      'sitemap',
      'robots',
      'catalog',
      'social-images',
      'content-images',
    ],
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const report = await auditPublicWebsite();
  mkdirSync('artifacts', { recursive: true });
  writeFileSync('artifacts/website-findability.json', `${JSON.stringify(report, null, 2)}\n`);
  console.log(`Public website findability passed for ${report.pages.length} pages`);
}
