import { build } from 'esbuild';
import { weaveProfile } from '../crates/worker/ui/woven-gate.ts';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
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
const document = (host, title, body, small = false) =>
  `<!doctype html><html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="description" content="Passkeyでサインイン。自分の情報を、自分の手元に。"><title>${title} · mikaki</title><link rel="icon" href="/favicon.svg"><link rel="stylesheet" href="/style.css"><script type="module" src="/site.js"></script></head><body><div class="scene ${small ? 'small' : ''}"><div class="fence" aria-hidden="true"></div><canvas aria-hidden="true"></canvas><header><a class="brand" href="https://mikaki.org">mikaki</a><span class="plaque">${host}</span></header><main>${body}</main><footer><span>御垣 — mikaki</span><nav class="footlinks"><a href="https://auth.mikaki.org">サインインについて</a><a href="https://github.com/masanork/mikaki">GitHub ↗</a></nav></footer></div></body></html>`;
await writeFile(
  new URL('app-public/index.html', base),
  document(
    'app.mikaki.org',
    'mikakiアプリ',
    `<div class="kicker">mikaki app</div><h1>手元から、<br>つながる。</h1><p>mikakiアプリのサインインを、このドメインで受け取ります。<br>Web版はアプリなしでサインインできます。</p><p>身分証の読み取りなど、端末の機能を使う場面ではアプリを利用します。アプリの一般向け配布は準備中です。</p><div class="actions"><a class="bolt" href="https://auth.mikaki.org/signin">Webでサインイン ↗</a><a class="quiet" href="https://github.com/masanork/mikaki/tree/main/apps/mikaki-client">アプリのソース ↗</a></div>`,
    true,
  ),
);
await writeFile(
  new URL('app-public/native-link-help.html', base),
  document(
    'app.mikaki.org',
    'アプリに戻れませんでした',
    `<div class="kicker">Return to app</div><h1>アプリに戻れませんでした</h1><p>アプリからサインインをやり直してください。</p><p>Androidでは、設定の「アプリ」→「mikaki」→「デフォルトで開く」で、app.mikaki.org のリンクを許可します。iPhoneではアプリを開いて、もう一度お試しください。</p><div class="actions"><a class="quiet" href="/">アプリについて ↗</a></div>`,
    true,
  ),
);
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
for (const dir of ['public', 'app-public'])
  await writeFile(
    new URL(`${dir}/404.html`, base),
    document(
      dir === 'public' ? 'mikaki.org' : 'app.mikaki.org',
      'ページが見つかりません',
      '<h1>ページが見つかりません</h1><a class="quiet" href="/">トップへ ↗</a>',
      true,
    ),
  );

await import('./sorane.mjs');
