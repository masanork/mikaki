import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, copyFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { register } from 'tsx/esm/api';

register();
const { renderMarkdown, escapeHtml } = await import('@sorane/core');
const { parseConcept } = await import('@sorane/okf');
const site = fileURLToPath(new URL('./', import.meta.url));
const cli = join(site, '../node_modules/@sorane/cli/bin/sorane.mjs');
const report = JSON.parse(
  execFileSync(process.execPath, [cli, 'validate', '--cwd', site, '--json'], { encoding: 'utf8' }),
);
if (!report.ok) throw new Error(JSON.stringify(report));
execFileSync(process.execPath, [cli, 'build', '--cwd', site, '--clean'], { stdio: 'inherit' });
// Cloudflare static assets redirect .html URLs to their extensionless form.
const canonicalUrls = (text) =>
  text.replace(
    /https:\/\/mikaki\.org\/((?:en\/)?)(index|integration|security)\.html/g,
    (_, prefix, slug) => `https://mikaki.org/${prefix}${slug === 'index' ? '' : slug}`,
  );
const hashes = new Set();
for (const lang of ['ja', 'en']) {
  const prefix = lang === 'ja' ? '' : 'en/';
  const other = lang === 'ja' ? 'en/' : '';
  const ja = lang === 'ja';
  for (const slug of ['index', 'integration', 'security']) {
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
      .replace(/(?:href|src)="([^":]+)"/g, (full, url) =>
        full.replace(url, new URL(url, `https://mikaki.org/${rel}`).pathname),
      );
    if (!head) throw new Error(`Missing Sorane metadata: ${rel}`);
    for (const match of head.matchAll(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/g))
      hashes.add(`'sha256-${createHash('sha256').update(match[1]).digest('base64')}'`);
    const nav = `<nav class="footlinks" aria-label="${ja ? 'mikakiについて' : 'About mikaki'}"><a href="/${prefix}">${ja ? '概要' : 'Overview'}</a><a href="/${prefix}integration">${ja ? 'アプリ連携' : 'Integration'}</a><a href="/${prefix}security">${ja ? '対応状況' : 'Status'}</a><a href="/${other}${slug === 'index' ? '' : slug}" lang="${ja ? 'en' : 'ja'}" hreflang="${ja ? 'en' : 'ja'}">${ja ? 'English' : '日本語'}</a></nav>`;
    const home = slug === 'index';
    const hero = `<div class="kicker">Your identity. Your choice.</div><h1>${ja ? '自分の情報を、<br>自分の手元に。' : 'Your information.<br>In your hands.'}</h1><p>${ja ? 'Passkeyでサインイン。<br>必要な情報だけを、選んだ相手に。' : 'Sign in with a passkey.<br>Share only what you choose, with whom you choose.'}</p><div class="actions"><a class="bolt" href="https://auth.mikaki.org/signin">${ja ? 'Webでサインイン' : 'Sign in on the Web'} ↗</a><a class="quiet" href="https://app.mikaki.org">${ja ? 'アプリについて' : 'About the app'} ↗</a></div><section class="details"><div><h2>Passkey</h2><p>${ja ? 'パスワードを使わず、いつもの端末で。' : 'Use your device, without a password.'}</p></div><div><h2>Vault</h2><p>${ja ? '保存した情報は、Passkeyで開く。' : 'Open your stored information with a passkey.'}</p></div><div><h2>${ja ? '選んで共有' : 'Choose what to share'}</h2><p>${ja ? '共有する情報と相手を、自分で選ぶ。' : 'You choose the information and the recipient.'}</p></div></section>`;
    const body = `${home ? hero : `<h1 class="article-title">${escapeHtml(concept.title)}</h1>`}<section class="prose">${nav}${renderMarkdown(concept.body)}</section>`;
    const html = `<!doctype html><html lang="${lang}"><head>${head}<link rel="icon" href="/favicon.svg"><link rel="stylesheet" href="/style.css"><script type="module" src="/site.js"></script></head><body><div class="scene ${home ? '' : 'small'}"><div class="fence" aria-hidden="true"></div><canvas aria-hidden="true"></canvas><header><a class="brand" href="/${prefix}">mikaki</a><span class="plaque">mikaki.org</span></header><main>${body}</main><footer><span>御垣 — mikaki</span><nav class="footlinks"><a href="https://auth.mikaki.org/signin">${ja ? 'サインイン' : 'Sign in'}</a><a href="https://github.com/masanork/mikaki">GitHub ↗</a></nav></footer></div></body></html>`;
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
writeFileSync(llms, readFileSync(llms, 'utf8').replace(/^.*\[OKF bundle\].*\n/gm, ''));
const headers = join(site, 'public/_headers');
writeFileSync(
  headers,
  readFileSync(headers, 'utf8').replace(
    "script-src 'self'",
    `script-src 'self' ${[...hashes].join(' ')}`,
  ),
);
console.log(`Sorane metadata and content ready: ${report.warning_count} validation warnings.`);
