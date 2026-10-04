import { build } from 'esbuild';
import { weaveProfile } from '../crates/worker/ui/woven-gate.ts';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { header, footer, escape } from './layout.mjs';
const op = JSON.parse(
  await readFile(new URL('../crates/worker/wrangler.production.jsonc', import.meta.url)),
);
const base = new URL('./', import.meta.url);
for (const dir of ['public', 'app-public']) {
  await mkdir(new URL(dir, base), { recursive: true });
  await build({
    entryPoints: [new URL('site.ts', base).pathname],
    outfile: new URL(`${dir}/site.js`, base).pathname,
    bundle: true,
    format: 'esm',
    minify: true,
  });
  const profile = weaveProfile(dir === 'public' ? 'https://mikaki.org' : 'https://app.mikaki.org');
  const css = await readFile(new URL('style.css', base), 'utf8');
  await writeFile(
    new URL(`${dir}/style.css`, base),
    `${css}\n.scene{--hue:${profile.hue};--step:${profile.spacing / 2}px;--angle:${profile.grainAngle}deg}`,
  );
  await writeFile(
    new URL(`${dir}/favicon.svg`, base),
    await readFile(new URL('../branding/mikaki-mark.svg', base)),
  );
  await writeFile(
    new URL(`${dir}/_headers`, base),
    `/*
  Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'
  Referrer-Policy: no-referrer
  X-Content-Type-Options: nosniff
  Cache-Control: public, max-age=300
`,
  );
}
const document = (host, title, body, lang = 'ja', path = '/', noindex = false) => {
  const ja = lang === 'ja';
  const origin = 'https://mikaki.org';
  const app = host === 'app.mikaki.org';
  const languageUrl = path.startsWith('/en/') ? path.replace('/en/', '/') : `/en${path}`;
  return `<!doctype html><html lang="${lang}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="description" content="${app ? (ja ? 'mikakiアプリとWeb版の利用案内。' : 'Using the mikaki application and Web service.') : ja ? 'mikakiの公式サイト。' : 'The official mikaki website.'}">${noindex ? '<meta name="robots" content="noindex">' : `<link rel="canonical" href="https://${host}${path}">`}<title>${escape(title)} · mikaki</title><link rel="icon" href="/favicon.svg"><link rel="stylesheet" href="/style.css"></head><body>${header(lang, 'index', { origin, languageUrl })}<main class="app-main" id="main-content" tabindex="-1"><p class="eyebrow">${app ? (ja ? 'mikakiアプリ' : 'mikaki application') : 'mikaki'}</p>${body}</main>${footer(lang, { origin })}</body></html>`;
};
for (const lang of ['ja', 'en']) {
  const ja = lang === 'ja';
  const prefix = ja ? '' : 'en/';
  await mkdir(new URL(`app-public/${prefix}`, base), { recursive: true });
  await writeFile(
    new URL(`app-public/${prefix}index.html`, base),
    document(
      'app.mikaki.org',
      ja ? 'mikakiアプリ' : 'mikaki application',
      `<h1>${ja ? 'Webでも、アプリでも。' : 'On the Web. On your device.'}</h1><div class="prose"><p>${ja ? '通常のサインインは、アプリをインストールせずWebブラウザーから利用できます。' : 'For normal sign-in, use your Web browser without installing an application.'}</p><p>${ja ? '身分証の読み取りなど、端末の機能を使う場面ではmikakiアプリを利用します。アプリの一般向け配布は準備中です。' : 'The mikaki application supports workflows that use device features, such as reading identity documents. General distribution is in preparation.'}</p><p>${ja ? 'このドメインは、アプリのサインインからアプリへ戻るためのリンクも受け取ります。Web版の登録・ログインは、以下の案内から始められます。' : 'This domain also receives links that return an application sign-in to the app. Use the links below to get started on the Web.'}</p></div><div class="actions"><a class="button button-primary" href="https://auth.mikaki.org/signin${ja ? '' : '?lang=en'}">${ja ? 'Webでサインイン' : 'Sign in on the Web'}</a><a class="button button-outline" href="https://mikaki.org/${prefix}getting-started">${ja ? 'はじめ方を読む' : 'Read the setup guide'}</a></div><div class="prose"><h2>${ja ? '開発者向けの情報' : 'For developers'}</h2><p><a href="https://github.com/masanork/mikaki/tree/main/apps/mikaki-client">${ja ? 'アプリのソースを見る' : 'Browse the application source'}</a></p></div>`,
      lang,
      `/${prefix}`,
    ),
  );
  await writeFile(
    new URL(`app-public/${prefix}native-link-help.html`, base),
    document(
      'app.mikaki.org',
      ja ? 'アプリに戻れませんでした' : 'Unable to return to the application',
      `<h1>${ja ? 'アプリに戻れませんでした' : 'Unable to return to the application'}</h1><div class="prose"><p>${ja ? 'アプリを開いて、サインインをやり直してください。' : 'Open the application and start sign-in again.'}</p><h2>${ja ? 'Androidをお使いの場合' : 'On Android'}</h2><p>${ja ? '設定の「アプリ」→「mikaki」→「デフォルトで開く」で、app.mikaki.org のリンクを許可します。' : 'In Settings, open Apps → mikaki → Open by default, and allow app.mikaki.org links.'}</p><h2>${ja ? 'iPhoneをお使いの場合' : 'On iPhone'}</h2><p>${ja ? 'アプリを開いて、もう一度サインインしてください。' : 'Open the application and try signing in again.'}</p></div><div class="actions"><a class="button button-outline" href="/${prefix}">${ja ? 'アプリの案内へ戻る' : 'Back to the application guide'}</a></div>`,
      lang,
      `/${prefix}native-link-help`,
      true,
    ),
  );
}
await mkdir(new URL('app-public/.well-known', base), { recursive: true });
await writeFile(
  new URL('app-public/.well-known/assetlinks.json', base),
  JSON.stringify([
    {
      relation: ['delegate_permission/common.handle_all_urls'],
      target: {
        namespace: 'android_app',
        package_name: 'app.tossa.mikaki',
        sha256_cert_fingerprints: [op.vars.MIKAKI_ANDROID_SHA256_CERT_FINGERPRINT],
      },
    },
  ]),
);
for (const dir of ['public', 'app-public']) {
  for (const lang of ['ja', 'en']) {
    const ja = lang === 'ja';
    const prefix = ja ? '' : 'en/';
    await mkdir(new URL(`${dir}/${prefix}`, base), { recursive: true });
    await writeFile(
      new URL(`${dir}/${prefix}404.html`, base),
      document(
        dir === 'public' ? 'mikaki.org' : 'app.mikaki.org',
        ja ? 'ページが見つかりません' : 'Page not found',
        ja
          ? '<h1>ページが見つかりません</h1><div class="prose"><p>リンクが変更されたか、URLが正しくない可能性があります。</p><p><a href="https://mikaki.org/">mikakiのホームへ戻る</a></p></div>'
          : '<h1>Page not found</h1><div class="prose"><p>The link may have changed, or the URL may be incorrect.</p><p><a href="https://mikaki.org/en/">Back to the mikaki homepage</a></p></div>',
        lang,
        `/${prefix}404`,
        true,
      ),
    );
  }
}

await import('./sorane.mjs');

// Search Console ownership verification applies only to the public website.
await writeFile(
  new URL('public/google39c752b3da515c0e.html', base),
  await readFile(new URL('verification/google39c752b3da515c0e.html', base)),
);
