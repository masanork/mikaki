// Share the existing bilingual Markdown, rendered articles and visual design.
// Marketing-site output remains independently deployable during the cutover.
import '../../website/build.mjs';
import { readFileSync, writeFileSync, mkdirSync, copyFileSync, cpSync, rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { pages, groups, escape, route } from '../../website/layout.mjs';

const app = fileURLToPath(new URL('./', import.meta.url));
const source = fileURLToPath(new URL('../../website/public/', import.meta.url));
const output = join(app, 'dist');
const origin = 'https://docs.mikaki.org';
const guides = pages.filter(({ slug }) => !['index', 'contact', 'integration-demo'].includes(slug));
const guideSlugs = new Set(guides.map(({ slug }) => slug));
const navigation = groups.map((group) => ({
  ...group,
  pages: group.pages.filter((slug) => guideSlugs.has(slug)),
}));
rmSync(output, { recursive: true, force: true });
mkdirSync(output, { recursive: true });
for (const file of ['style.css', 'favicon.svg'])
  copyFileSync(join(source, file), join(output, file));
cpSync(join(source, 'screenshots'), join(output, 'screenshots'), { recursive: true });
cpSync(join(source, 'social-preview'), join(output, 'social-preview'), { recursive: true });
const publicLink = (slug, lang, suffix = '') =>
  route(
    slug,
    lang,
    ['contact', 'index', 'integration-demo'].includes(slug) ? 'https://mikaki.org' : '',
  ) + suffix;
const links = (html, lang) =>
  html
    .replace(
      /https:\/\/mikaki\.org\/((?:en\/)?)([a-z0-9-]+)(?=[/#?"<\s]|$)/g,
      (url, prefix, slug) => (guideSlugs.has(slug) ? `${origin}/${prefix}${slug}` : url),
    )
    .replace(
      /href="\/(en\/)?(contact|integration-demo)([?#][^"]*)?"/g,
      (_, prefix = '', slug, suffix = '') => `href="https://mikaki.org/${prefix}${slug}${suffix}"`,
    )
    .replace(
      /href="([a-z0-9-]+)\.(?:html|md)([?#][^"]*)?"/g,
      (_, slug, suffix = '') => `href="${publicLink(slug, lang, suffix)}"`,
    );
const pageHashes = new Map();
const sitemap = [];
for (const lang of ['ja', 'en']) {
  const ja = lang === 'ja',
    prefix = ja ? '' : 'en/',
    other = ja ? 'en' : 'ja';
  mkdirSync(join(output, prefix), { recursive: true });
  const destinations = navigation
    .map((group) => `<a href="${route(group.entry, lang)}">${escape(group.labels[lang])}</a>`)
    .join('');
  const header = (slug) =>
    `<a class="skip-link" href="#main-content">${ja ? '本文へ移動' : 'Skip to content'}</a><header class="site-header"><div class="header-inner"><a class="brand" href="${route('index', lang)}">mikaki Docs</a><nav class="primary-nav" aria-label="${ja ? '主要メニュー' : 'Main navigation'}">${destinations}</nav><div class="header-tools"><a class="language-link" href="${route(slug, other)}" lang="${other}">${ja ? 'English' : '日本語'}</a><a class="button button-small button-outline" href="/session?lang=${lang}">${ja ? 'ログイン状態' : 'Login state'}</a></div></div></header>`;
  const footer = `<footer class="site-footer"><div class="footer-inner"><a href="https://mikaki.org/${prefix}">${ja ? 'mikakiの公式サイト' : 'mikaki official website'}</a><a href="https://mikaki.org/${prefix}contact">${ja ? '相談する' : 'Contact'}</a><a href="https://github.com/masanork/mikaki/tree/main/apps/mikaki-docs">GitHub</a></div></footer>`;
  const label = (slug) => escape(guides.find((page) => page.slug === slug).labels[lang]);
  const cards = navigation
    .map(
      (group) =>
        `<section class="guide-card"><h2>${escape(group.labels[lang])}</h2><ul>${group.pages.map((slug) => `<li><a href="${route(slug, lang)}">${label(slug)}</a></li>`).join('')}</ul></section>`,
    )
    .join('');
  for (const slug of ['index', ...guides.map((page) => page.slug)]) {
    const home = slug === 'index',
      path = route(slug, lang);
    let head, body;
    if (home) {
      const title = ja ? 'mikakiのドキュメント' : 'mikaki documentation';
      const description = ja
        ? '使い方、よくある質問、アプリ連携、API参照、運用情報をまとめています。'
        : 'Guides, frequently asked questions, integration, API reference and operations.';
      head = `<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title} · mikaki Docs</title><meta name="description" content="${description}"><link rel="canonical" href="${origin}${path}"><link rel="alternate" hreflang="ja" href="${origin}/"><link rel="alternate" hreflang="en" href="${origin}/en/">`;
      body = `<main class="app-main" id="main-content" tabindex="-1"><h1>${title}</h1><p>${description}</p><div class="guide-grid">${cards}</div></main>`;
    } else {
      const html = readFileSync(join(source, `${prefix}${slug}.html`), 'utf8');
      head = html
        .match(/<head>([\s\S]*?)<\/head>/)?.[1]
        .replace(/<script type="module"[^>]*><\/script>/g, '');
      const article = html.match(/<article class="prose">([\s\S]*?)<\/article>/)?.[1];
      if (!head || !article) throw new Error(`Missing rendered guide: ${lang}/${slug}`);
      const group = navigation.find((group) => group.pages.includes(slug));
      const sidebar = `<aside class="guide-sidebar"><nav class="section-nav" aria-label="${escape(group.labels[lang])}"><p class="section-label">${escape(group.labels[lang])}</p><ul>${group.pages.map((page) => `<li><a href="${route(page, lang)}"${page === slug ? ' aria-current="page"' : ''}>${label(page)}</a></li>`).join('')}</ul></nav></aside>`;
      body = `<div class="article-layout">${sidebar}<main class="article-main" id="main-content" tabindex="-1"><header class="article-header"><p class="eyebrow">${escape(group.labels[lang])}</p><h1 class="article-title">${label(slug)}</h1></header><article class="prose">${article}</article></main></div>`;
      writeFileSync(
        join(output, `${prefix}${slug}.md`),
        links(readFileSync(join(source, `${prefix}${slug}.md`), 'utf8'), lang),
      );
    }
    const hashes = new Set(
      [...head.matchAll(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/g)].map(
        (match) =>
          `'sha256-${createHash('sha256').update(links(match[1], lang)).digest('base64')}'`,
      ),
    );
    pageHashes.set(path, hashes);
    writeFileSync(
      join(output, `${prefix}${slug}.html`),
      links(
        `<!doctype html><html lang="${lang}"><head>${head}${home ? '<link rel="icon" href="/favicon.svg"><link rel="stylesheet" href="/style.css">' : ''}</head><body>${header(slug)}${body}${footer}</body></html>`,
        lang,
      ),
    );
    sitemap.push(`${origin}${path}`);
  }
  writeFileSync(
    join(output, `${prefix}404.html`),
    `<!doctype html><html lang="${lang}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${ja ? 'ページが見つかりません' : 'Page not found'} · mikaki Docs</title><meta name="robots" content="noindex"><link rel="stylesheet" href="/style.css"></head><body>${header('index')}<main class="app-main" id="main-content"><h1>${ja ? 'ページが見つかりません' : 'Page not found'}</h1><a href="/${prefix}">${ja ? 'ドキュメントへ戻る' : 'Back to the documentation'}</a></main>${footer}</body></html>`,
  );
}
const policy = (hashes) =>
  `default-src 'none'; script-src 'self' ${[...hashes].join(' ')}; style-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'`;
const headers =
  `/*\n  Content-Security-Policy: ${policy(pageHashes.get('/'))}\n  Referrer-Policy: no-referrer\n  X-Content-Type-Options: nosniff\n  Cache-Control: public, max-age=300\n\n` +
  [...pageHashes]
    .filter(([path]) => path !== '/')
    .map(
      ([path, hashes]) =>
        `${path}\n  ! Content-Security-Policy\n  Content-Security-Policy: ${policy(hashes)}\n`,
    )
    .join('\n');
if (headers.split('\n').some((line) => line.length > 2000) || pageHashes.size > 100)
  throw new Error('Asset header limits exceeded');
writeFileSync(join(output, '_headers'), headers);
writeFileSync(
  join(output, 'sitemap.xml'),
  `<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${sitemap.map((url) => `<url><loc>${url}</loc></url>`).join('')}</urlset>`,
);
writeFileSync(
  join(output, 'robots.txt'),
  `User-agent: *\nAllow: /\nDisallow: /session\nDisallow: /callback\nSitemap: ${origin}/sitemap.xml\n`,
);
writeFileSync(
  join(output, 'llms.txt'),
  `# mikaki Docs\n\n${sitemap.map((url) => `- ${url}`).join('\n')}\n`,
);
console.log(`Docs ready: ${sitemap.length} bilingual pages from shared Markdown.`);
