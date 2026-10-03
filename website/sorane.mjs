import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, copyFileSync, mkdirSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { register } from 'tsx/esm/api';

register();
const { renderMarkdown, escapeHtml } = await import('@sorane/core');
const { parseConcept } = await import('@sorane/okf');
const site = fileURLToPath(new URL('./', import.meta.url));
const pages = JSON.parse(readFileSync(join(site, 'pages.json'), 'utf8'));
const slugs = new Set(pages.map((page) => page.slug));
if (slugs.size !== pages.length) throw new Error('Duplicate page slug');
for (const locale of ['', 'en/']) {
  const contentSlugs = readdirSync(join(site, 'content', locale))
    .filter((file) => file.endsWith('.md'))
    .map((file) => file.slice(0, -3));
  if (contentSlugs.length !== slugs.size || contentSlugs.some((slug) => !slugs.has(slug)))
    throw new Error(`Page manifest and content differ: ${locale || 'ja'}`);
}
const cli = join(site, '../node_modules/@sorane/cli/bin/sorane.mjs');
const report = JSON.parse(
  execFileSync(process.execPath, [cli, 'validate', '--cwd', site, '--json'], { encoding: 'utf8' }),
);
if (!report.ok) throw new Error(JSON.stringify(report));
execFileSync(process.execPath, [cli, 'build', '--cwd', site, '--clean'], { stdio: 'inherit' });
// Cloudflare static assets redirect .html URLs to their extensionless form.
const canonicalUrls = (text) =>
  text.replace(/https:\/\/mikaki\.org\/((?:en\/)?)([a-z0-9-]+)\.html/g, (url, prefix, slug) =>
    slugs.has(slug) ? `https://mikaki.org/${prefix}${slug === 'index' ? '' : slug}` : url,
  );
const screenshotDir = join(site, 'screenshots/onboarding');
mkdirSync(join(site, 'public/screenshots/onboarding'), { recursive: true });
for (const file of readdirSync(screenshotDir).filter((file) => file.endsWith('.png')))
  copyFileSync(join(screenshotDir, file), join(site, 'public/screenshots/onboarding', file));
const pageHashes = new Map();
for (const lang of ['ja', 'en']) {
  const prefix = lang === 'ja' ? '' : 'en/';
  const other = lang === 'ja' ? 'en/' : '';
  const ja = lang === 'ja';
  const imageUrl = `https://mikaki.org/social-preview/${lang}.png`;
  const imageAlt = ja
    ? 'mikaki — 自分の情報を、自分の手元に。パスキーでサインイン。'
    : 'mikaki — Your information. In your hands. Sign in with a passkey.';
  mkdirSync(join(site, 'public/social-preview'), { recursive: true });
  copyFileSync(
    join(site, `social-preview/${lang}.png`),
    join(site, `public/social-preview/${lang}.png`),
  );
  for (const { slug } of pages) {
    const rel = `${prefix}${slug}.html`;
    mkdirSync(join(site, 'public', prefix), { recursive: true });
    const { concept } = parseConcept(
      rel,
      rel.replace('.html', '.md'),
      readFileSync(join(site, 'content', `${prefix}${slug}.md`), 'utf8'),
    );
    const generated = canonicalUrls(readFileSync(join(site, 'dist', rel), 'utf8'));
    const head = generated
      .match(/<head>([\s\S]*?)<\/head>/)?.[1]
      .replace(/<link rel="stylesheet"[^>]*>/g, '')
      .replace(
        'name="twitter:card" content="summary"',
        'name="twitter:card" content="summary_large_image"',
      )
      .replace(/(?:href|src)="([^":]+)"/g, (full, url) =>
        full.replace(url, new URL(url, 'https://mikaki.org/').pathname),
      );
    if (!head) throw new Error(`Missing Sorane metadata: ${rel}`);
    const hashes = new Set();
    for (const match of head.matchAll(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/g))
      hashes.add(`'sha256-${createHash('sha256').update(match[1]).digest('base64')}'`);
    pageHashes.set(`/${prefix}${slug === 'index' ? '' : slug}`, hashes);
    const links = pages
      .map(
        (page) =>
          `<a href="/${prefix}${page.slug === 'index' ? '' : page.slug}"${page.slug === slug ? ' aria-current="page"' : ''}>${escapeHtml(page.labels[lang])}</a>`,
      )
      .join('');
    const nav = `<nav class="footlinks" aria-label="${ja ? 'mikakiについて' : 'About mikaki'}">${links}<a href="/${other}${slug === 'index' ? '' : slug}" lang="${ja ? 'en' : 'ja'}" hreflang="${ja ? 'en' : 'ja'}">${ja ? 'English' : '日本語'}</a></nav>`;
    const home = slug === 'index';
    const signin = `https://auth.mikaki.org/signin${ja ? '' : '?lang=en'}`;
    const hero = `<div class="kicker">Your identity. Your choice.</div><h1>${ja ? '自分の情報を、<br>自分の手元に。' : 'Your information.<br>In your hands.'}</h1><p>${ja ? 'Passkeyでサインイン。<br>必要な情報だけを、選んだ相手に。' : 'Sign in with a passkey.<br>Share only what you choose, with whom you choose.'}</p><div class="actions"><a class="bolt" href="${signin}">${ja ? 'Webでサインイン' : 'Sign in on the Web'} ↗</a><a class="quiet" href="/${prefix}getting-started">${ja ? 'はじめての方へ' : 'Getting started'}</a><a class="quiet" href="https://app.mikaki.org">${ja ? 'アプリについて' : 'About the app'} ↗</a></div><section class="details"><div><h2>Passkey</h2><p>${ja ? 'パスワードを使わず、いつもの端末で。' : 'Use your device, without a password.'}</p></div><div><h2>Vault</h2><p>${ja ? '保存した情報は、Passkeyで開く。' : 'Open your stored information with a passkey.'}</p></div><div><h2>${ja ? '選んで共有' : 'Choose what to share'}</h2><p>${ja ? '共有する情報と相手を、自分で選ぶ。' : 'You choose the information and the recipient.'}</p></div></section>`;
    // Sorane renders Markdown sibling links as .html; emit the public routes directly.
    let content = renderMarkdown(concept.body).replace(
      /href="([a-z0-9-]+)\.html([?#][^"]*)?"/g,
      (link, slug, suffix = '') =>
        slugs.has(slug) ? `href="/${prefix}${slug === 'index' ? '' : slug}${suffix}"` : link,
    );
    content = content.replace(
      /<img src="(?:\.\.\/){1,2}(screenshots\/onboarding\/([a-z-]+\.png))"([^>]*)>/g,
      (_, src, file, attributes) => {
        const png = readFileSync(join(screenshotDir, file));
        if (png.subarray(0, 8).toString('hex') !== '89504e470d0a1a0a')
          throw new Error(`Invalid PNG: ${file}`);
        return `<img src="/${src}"${attributes} width="${png.readUInt32BE(16)}" height="${png.readUInt32BE(20)}" loading="lazy" decoding="async">`;
      },
    );
    if (home) {
      // Keep the introduction before the three purpose-based guide sections.
      const [introduction, ...guides] = content.split(/(?=<h2\b)/);
      content = `${introduction}<div class="guide-grid">${guides
        .map((guide) => `<section class="guide-card">${guide}</section>`)
        .join('')}</div>`;
    } else {
      // Reuse Sorane's rendered heading IDs, including duplicate-heading suffixes.
      const headings = [...content.matchAll(/<h2 id="([^"]+)">([\s\S]*?)<\/h2>/g)];
      if (headings.length >= 3) {
        const items = headings
          .map(([, id, heading]) => {
            const label = heading
              .replace(/<a class="heading-anchor"[\s\S]*?<\/a>/g, '')
              .replace(/<[^>]*>/g, '');
            return `<li><a href="#${id}">${label}</a></li>`;
          })
          .join('');
        const label = ja ? 'このページの内容' : 'On this page';
        const contents = `<nav class="contents" aria-label="${label}"><p class="contents-title">${label}</p><ul>${items}</ul></nav>`;
        content = content.replace(/(?=<h2\b)/, contents);
      }
    }
    const body = `${home ? hero : `<h1 class="article-title">${escapeHtml(concept.title)}</h1>`}<section class="prose${home ? ' home-prose' : ''}">${nav}${content}</section>`;
    const social = `<meta property="og:image" content="${imageUrl}"><meta property="og:image:type" content="image/png"><meta property="og:image:width" content="1200"><meta property="og:image:height" content="630"><meta property="og:image:alt" content="${escapeHtml(imageAlt)}"><meta name="twitter:image" content="${imageUrl}"><meta name="twitter:image:alt" content="${escapeHtml(imageAlt)}">`;
    const html = `<!doctype html><html lang="${lang}"><head>${head}${social}<link rel="icon" href="/favicon.svg"><link rel="stylesheet" href="/style.css"><script type="module" src="/site.js"></script></head><body><div class="scene ${home ? '' : 'small'}"><div class="fence" aria-hidden="true"></div><canvas aria-hidden="true"></canvas><header><a class="brand" href="/${prefix}">mikaki</a><span class="plaque">mikaki.org</span></header><main>${body}</main><footer><span>御垣 — mikaki</span><nav class="footlinks"><a href="${signin}">${ja ? 'サインイン' : 'Sign in'}</a><a href="https://github.com/masanork/mikaki">GitHub ↗</a></nav></footer></div></body></html>`;
    writeFileSync(join(site, 'public', rel), html);
    copyFileSync(
      join(site, 'dist', rel.replace('.html', '.md')),
      join(site, 'public', rel.replace('.html', '.md')),
    );
  }
}
for (const file of ['sitemap.xml', 'robots.txt', 'llms.txt', 'catalog.jsonld'])
  writeFileSync(
    join(site, 'public', file),
    canonicalUrls(readFileSync(join(site, 'dist', file), 'utf8')),
  );
const llms = join(site, 'public/llms.txt');
const guideLinks = ['ja', 'en'].flatMap((lang) =>
  pages.map(
    (page) =>
      `- [${page.labels[lang]} (${lang})](https://mikaki.org/${lang === 'en' ? 'en/' : ''}${page.slug === 'index' ? '' : page.slug})`,
  ),
);
writeFileSync(
  llms,
  readFileSync(llms, 'utf8').replace(/^.*\[OKF bundle\].*\n/gm, '') +
    '\n## Guides\n\n' +
    guideLinks.join('\n') +
    '\n',
);
const headers = join(site, 'public/_headers');
// Workers static assets allow at most 2,000 characters per header-file line.
// A site-wide list grows with every translated page; authorize only each page's JSON-LD.
const defaults = readFileSync(headers, 'utf8');
const policy = defaults.match(/^  Content-Security-Policy: (.+)$/m)?.[1];
if (!policy) throw new Error('Missing default Content-Security-Policy');
const withHashes = (hashes) =>
  policy.replace("script-src 'self'", `script-src 'self' ${[...hashes].join(' ')}`);
const rootHashes = pageHashes.get('/');
if (!rootHashes?.size) throw new Error('Missing root-page Content-Security-Policy hashes');
// Deployed Workers Assets can retain the broad policy when an exact / rule detaches it:
// https://github.com/cloudflare/workers-sdk/issues/11351 (not reproduced by wrangler dev).
// Authorize only the root's hashes in the broad policy and never override CSP at /.
const rules = [...pageHashes]
  .filter(([path]) => path !== '/')
  .map(
    ([path, hashes]) =>
      `${path}\n  ! Content-Security-Policy\n  Content-Security-Policy: ${withHashes(hashes)}\n`,
  );
// Global rules still cover non-HTML assets and 404s. .html aliases redirect before headers.
const output = defaults.replace(policy, withHashes(rootHashes)) + '\n' + rules.join('\n');
if (rules.length + 1 > 100 || output.split('\n').some((line) => line.length > 2000))
  throw new Error('Static-asset header rules exceed Cloudflare limits');
writeFileSync(headers, output);
console.log(`Sorane metadata and content ready: ${report.warning_count} validation warnings.`);
