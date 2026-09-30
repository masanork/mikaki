import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const root = new URL('../../../', import.meta.url);
const source = readFileSync(new URL('branding/mikaki-mark.svg', root), 'utf8');
const opening = source.match(/^<svg[^>]*>/)[0];
const body = source.slice(opening.length).replace(/<\/svg>\s*$/, '');
const background = `<defs><linearGradient id="mikaki-background" x2="1" y2="1"><stop stop-color="#173c59"/><stop offset="1" stop-color="#081b2d"/></linearGradient></defs>`;
const icon = `${opening}${background}<rect width="1024" height="1024" rx="224" fill="url(#mikaki-background)"/>${body}</svg>\n`;
const write = (path, content) => writeFileSync(new URL(path, root), content);
write('apps/mikaki-client/branding/app-icon.svg', icon);
write('apps/mikaki-client/branding/android-foreground.svg', source);
write(
  'apps/mikaki-client/branding/android-monochrome.svg',
  source.replace(/#(?:e2f3ff|7ac8e9|54a2db|c1e7fa)/g, '#fff'),
);
write('apps/mikaki-client/ui/brand-icon.svg', icon);
write('branding/favicon.svg', icon);
mkdirSync(fileURLToPath(new URL('local/ui/public', root)), { recursive: true });
write('local/ui/public/favicon.svg', icon);
