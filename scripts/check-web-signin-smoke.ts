import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

export function checkWebSigninPage(html: string, locale: 'ja' | 'en'): void {
  const expected = [
    `<html lang="${locale}">`,
    'data-owner-login="true"',
    'data-enrollment="false"',
    'data-rp-id="auth.mikaki.org"',
    `data-rp-uri="https://auth.mikaki.org/vault?lang=${locale}"`,
    'src="/login/login.js"',
  ];
  for (const marker of expected) {
    assert.ok(html.includes(marker), `Web entry is missing ${marker}`);
  }
  assert.ok(/data-tx="[A-Za-z0-9_-]{43}"/.test(html), 'Web entry needs a login transaction');
  assert.ok(/data-challenge="[A-Za-z0-9_-]{43}"/.test(html), 'Web entry needs a Passkey challenge');
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  for (const entry of ['signin', 'vault']) {
    for (const locale of ['ja', 'en'] as const) {
      checkWebSigninPage(readFileSync(`web-${entry}-${locale}.html`, 'utf8'), locale);
    }
  }
  console.log('Public Web signin and Vault entries passed in Japanese and English');
}
