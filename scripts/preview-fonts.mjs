import { chromium, webkit } from '@playwright/test';
import { readFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { once } from 'node:events';

const fonts = new URL('../assets/fonts/', import.meta.url);
const manifest = JSON.parse(readFileSync(new URL('manifest.json', fonts), 'utf8'));
const files = new Map(
  manifest.files.map(({ file }) => [`/fonts/${file}`, readFileSync(new URL(file, fonts))]),
);
files.set('/fonts/fonts.css', readFileSync(new URL('fonts.css', fonts)));
const coverage = JSON.parse(readFileSync(new URL('coverage.json', fonts), 'utf8'));
const article = (family, label) =>
  `<article class="font-${family}"><h2>${label}</h2><div class="label">見出し · 28px</div><p class="headline">自分の情報を、自分の手元に。</p><div class="label">本文 · 16px</div><p class="body">パスキーでサインイン。<br>必要な情報だけを、選んだ相手に。<br>氏名や住所の異体字を保持して表示します。</p><button>セッションを確認</button><div class="label">補足 · 13px</div><p class="small">アカウント情報を確認できます。<br>ログアウトすると、この端末のセッションを終了します。</p><div class="label">通常字・IVS・補助平面 · 30px</div><p class="names">葛　葛󠄂　葛󠄃<br>辻　辻󠄂　辻󠄃<br>𠮷　髙　﨑　邉　邊</p><div class="label">Bunsen PUP · Plane 16 PUA</div><p class="names">&#x100000;　&#x100001;　&#x100002;</p><div class="label">Inter Variable · 16px</div><p class="body">Your information. In your hands.</p><div class="label">合成太字 · 16px</div><p class="body"><strong>氏名と住所を確認してください。</strong></p></article>`;
const html = `<!doctype html><html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>mikaki 日本語フォント比較</title><link rel="stylesheet" href="/fonts/fonts.css"><style>
*{box-sizing:border-box}body{margin:0;padding:40px;background:#f6f7f2;color:#223c32}
header,.caption,.label{font-family:var(--font-sans)}header h1{font-size:24px}
.caption{font-size:14px;line-height:1.8;color:#52645b}.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:24px;margin-top:28px}
article{border:1px solid #d6ded4;border-radius:12px;padding:28px;background:white}article h2{margin-top:0;font:600 18px 'Mikaki Latin',system-ui,sans-serif}
.label{font-size:12px;margin-top:24px;color:#52645b}.headline{font-size:28px;line-height:1.5;margin:12px 0 22px}.body{font-size:16px;line-height:1.9}.small{font-size:13px;line-height:1.8}.names{font-size:30px;line-height:1.7;margin:8px 0}button{font:inherit;padding:10px 20px;color:white;background:#285441;border:0;border-radius:7px}
@media(max-width:700px){body{padding:20px}.grid{grid-template-columns:1fr}}
</style></head><body><header><h1>Bunsen Mincho / Gothic ＋ Inter</h1></header><p class="caption">両書体とも本体・Ext・PUPを自己配信。追加明朝での補完は行いません。<br>追加文字の${coverage.reference.codepoints.toLocaleString('en-US')}文字中${coverage.styles.Mincho.administrative_covered.toLocaleString('en-US')}文字を収録、${coverage.styles.Mincho.administrative_missing.toLocaleString('en-US')}文字はKAGEの整備待ちです。</p><div class="grid">${article('mincho', 'Bunsen Mincho')}${article('gothic', 'Bunsen Gothic')}</div></body></html>`;
files.set('/', Buffer.from(html));
const server = createServer((request, response) => {
  const path = new URL(request.url ?? '/', 'http://localhost').pathname;
  const data = files.get(path);
  if (!data) {
    response.writeHead(404).end();
    return;
  }
  response.writeHead(200, {
    'Content-Type': path.endsWith('.css')
      ? 'text/css'
      : path.endsWith('.woff2')
        ? 'font/woff2'
        : path.endsWith('.ttf')
          ? 'font/ttf'
          : 'text/html',
  });
  response.end(data);
});
server.listen(Number(process.env.MIKAKI_FONT_PREVIEW_PORT ?? 0), '127.0.0.1');
await once(server, 'listening');
if (process.argv.includes('--serve')) {
  console.log(`Font preview: http://127.0.0.1:${server.address().port}/`);
  await new Promise(() => {});
}
for (const engine of [chromium, webkit]) {
  const browser = await engine.launch({ headless: true });
  try {
    const page = await browser.newPage({
      viewport: { width: 1200, height: 1200 },
      deviceScaleFactor: 2,
    });
    await page.goto(`http://127.0.0.1:${server.address().port}/`);
    await page.evaluate(async () => {
      await document.fonts.ready;
    });
    if (!(await page.evaluate(() => [...document.fonts].every((face) => face.status !== 'error'))))
      throw new Error('Comparison font failed to load');
    if (engine === chromium) {
      const cdp = await page.context().newCDPSession(page);
      await cdp.send('DOM.enable');
      await cdp.send('CSS.enable');
      const { root } = await cdp.send('DOM.getDocument');
      for (const selector of ['.font-mincho .body', '.font-gothic .body']) {
        const { nodeId } = await cdp.send('DOM.querySelector', { nodeId: root.nodeId, selector });
        const { fonts } = await cdp.send('CSS.getPlatformFontsForNode', { nodeId });
        console.log(
          selector,
          fonts.map((font) => `${font.familyName}: ${font.glyphCount}`).join(', '),
        );
      }
    }
    const suffix = engine === webkit ? '-webkit' : '';
    const directory = new URL('../docs/font-preview/', import.meta.url);
    mkdirSync(directory, { recursive: true });
    writeFileSync(new URL('index.html', directory), html);
    await page.screenshot({
      path: new URL(`comparison${suffix}.png`, directory).pathname,
      fullPage: true,
    });
    await page.setViewportSize({ width: 390, height: 844 });
    await page.screenshot({
      path: new URL(`comparison-mobile${suffix}.png`, directory).pathname,
      fullPage: true,
    });
  } finally {
    await browser.close();
  }
}

server.close();
await once(server, 'close');
