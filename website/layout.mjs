import { readFileSync } from 'node:fs';

export const pages = JSON.parse(readFileSync(new URL('pages.json', import.meta.url), 'utf8'));
export const groups = JSON.parse(readFileSync(new URL('navigation.json', import.meta.url), 'utf8'));
export const escape = (value) =>
  String(value).replace(
    /[&<>"']/g,
    (character) =>
      ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character],
  );
export const route = (slug, lang, origin = '') =>
  `${origin}/${lang === 'en' ? 'en/' : ''}${slug === 'index' ? '' : slug}`;
export const groupFor = (slug) => groups.find((group) => group.pages.includes(slug));
export const labelFor = (slug, lang) => pages.find((page) => page.slug === slug)?.labels[lang];
const covered = groups.flatMap((group) => group.pages);
if (
  new Set(covered).size !== covered.length ||
  groups.some((group) => !group.pages.includes(group.entry)) ||
  covered.some((slug) => !labelFor(slug, 'ja') || !labelFor(slug, 'en')) ||
  pages.some((page) => !['index', 'contact'].includes(page.slug) && !covered.includes(page.slug))
)
  throw new Error('Navigation must assign every guide to exactly one valid group');

export function header(lang, slug, { origin = '', languageUrl } = {}) {
  const ja = lang === 'ja';
  const group = groupFor(slug);
  const primary = groups
    .map(
      (item) =>
        `<a href="${route(item.entry, lang, origin)}"${group?.id === item.id ? ' aria-current="true"' : ''}>${escape(item.labels[lang])}</a>`,
    )
    .join('');
  const other = lang === 'ja' ? 'en' : 'ja';
  return `<a class="skip-link" href="#main-content">${ja ? '本文へ移動' : 'Skip to content'}</a><header class="site-header"><div class="header-inner"><a class="brand" href="${route('index', lang, origin)}" aria-label="${ja ? 'mikaki ホーム' : 'mikaki home'}"><span class="brand-mark" aria-hidden="true"></span><span>mikaki</span></a><nav class="primary-nav" aria-label="${ja ? '主要メニュー' : 'Main navigation'}">${primary}<a href="${route('contact', lang, origin)}"${slug === 'contact' ? ' aria-current="page"' : ''}>${ja ? '相談する' : 'Contact'}</a></nav><div class="header-tools"><a class="language-link" href="${escape(languageUrl ?? route(slug, other, origin))}" lang="${other}" hreflang="${other}" aria-label="${ja ? 'Switch to English' : '日本語に切り替える'}">${ja ? 'English' : '日本語'}</a><a class="button button-small button-outline" href="https://auth.mikaki.org/signin${ja ? '' : '?lang=en'}">${ja ? 'サインイン' : 'Sign in'}</a></div></div></header>`;
}

export function footer(lang, { origin = '' } = {}) {
  const ja = lang === 'ja';
  const columns = groups
    .map(
      (group) =>
        `<div><h2>${escape(group.labels[lang])}</h2><ul>${group.pages.map((slug) => `<li><a href="${route(slug, lang, origin)}">${escape(labelFor(slug, lang))}</a></li>`).join('')}</ul></div>`,
    )
    .join('');
  return `<footer class="site-footer"><div class="footer-inner"><div class="footer-intro"><a class="brand" href="${route('index', lang, origin)}">mikaki</a><p>${ja ? 'パスキーから始まる、<br>自分で選べる認証。' : 'Passkey sign-in.<br>Identity on your terms.'}</p><p class="footer-status">${ja ? 'Rust製OSS・実験公開' : 'Open source Rust · Experimental service'}</p></div><nav class="footer-nav" aria-label="${ja ? 'サイトマップ' : 'Sitemap'}">${columns}<div><h2>${ja ? 'プロジェクト' : 'Project'}</h2><ul><li><a href="${route('index', lang, origin)}">${ja ? 'mikakiについて' : 'About mikaki'}</a></li><li><a href="${route('contact', lang, origin)}">${escape(labelFor('contact', lang))}</a></li><li><a href="https://app.mikaki.org${ja ? '/' : '/en/'}">${ja ? 'アプリについて' : 'About the app'}</a></li><li><a href="https://github.com/masanork/mikaki">GitHub</a></li></ul></div></nav></div><div class="footer-bottom"><span>御垣 — mikaki</span><span>${ja ? '自分の情報を、自分の手元に。' : 'Your information. In your hands.'}</span></div></footer>`;
}

export function breadcrumbs(slug, lang) {
  const group = groupFor(slug);
  return `<nav class="breadcrumbs" aria-label="${lang === 'ja' ? '現在位置' : 'Breadcrumb'}"><ol><li><a href="${route('index', lang)}">${lang === 'ja' ? 'ホーム' : 'Home'}</a></li>${group && group.entry !== slug ? `<li><a href="${route(group.entry, lang)}">${escape(group.labels[lang])}</a></li>` : ''}<li><span aria-current="page">${escape(labelFor(slug, lang))}</span></li></ol></nav>`;
}

export function sectionNav(slug, lang) {
  const group = groupFor(slug);
  if (!group) return '';
  return `<aside class="guide-sidebar"><nav class="section-nav" aria-label="${escape(group.labels[lang])}"><p class="section-label">${escape(group.labels[lang])}</p><ul>${group.pages.map((page) => `<li><a href="${route(page, lang)}"${page === slug ? ' aria-current="page"' : ''}>${escape(labelFor(page, lang))}</a></li>`).join('')}</ul></nav><div class="sidebar-support"><p>${lang === 'ja' ? '招待や連携について' : 'Invitations and integration'}</p><a href="${route('contact', lang)}">${lang === 'ja' ? '相談窓口を見る' : 'Find the right contact'}</a></div></aside>`;
}

export function hero(lang) {
  const ja = lang === 'ja';
  return `<section class="scene hero" aria-labelledby="hero-title"><div class="fence" aria-hidden="true"></div><canvas aria-hidden="true"></canvas><div class="hero-inner"><p class="eyebrow">${ja ? 'パスキー認証 / OpenID Connect' : 'Passkeys / OpenID Connect'}</p><h1 id="hero-title">${ja ? '自分の情報を、<br>自分の手元に。' : 'Your information.<br>In your hands.'}</h1><p class="hero-lead">${ja ? 'パスキーでサインイン。<br>必要な情報だけを、選んだ相手に。' : 'Sign in with a passkey.<br>Share only what you choose, with whom you choose.'}</p><div class="actions"><a class="button button-primary" href="${route('getting-started', lang)}">${ja ? '使いはじめる' : 'Get started'}</a><a class="button button-hero" href="${route('integration', lang)}">${ja ? 'アプリを接続する' : 'Connect your application'}</a></div><a class="hero-status" href="${route('operations', lang)}">${ja ? '招待制の実験公開 — 提供条件を確認する' : 'Experimental, invitation-based access — Service conditions'}</a><button class="motion-control" type="button" aria-pressed="false" hidden data-pause-label="${ja ? '背景の動きを停止' : 'Pause background animation'}">${ja ? '背景の動きを停止' : 'Pause background animation'}</button></div></section>`;
}
