import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

export function checkWebSigninPage(html: string, locale: 'ja' | 'en', finalUrl: string): void {
  let destination: URL;
  try {
    destination = new URL(finalUrl);
  } catch {
    assert.fail('Invalid final Web entry URL');
  }
  assert.equal(destination.origin, 'https://auth.mikaki.org');
  assert.equal(destination.pathname, '/login');
  assert.ok(!destination.username && !destination.password, 'Unexpected URL credentials');
  assert.equal(destination.hash, '');
  assert.deepEqual([...destination.searchParams.keys()].sort(), ['lang', 'tx']);
  assert.equal(destination.searchParams.get('lang'), locale);
  const transaction = destination.searchParams.get('tx')!;
  assert.ok(/^[A-Za-z0-9_-]{43}$/.test(transaction), 'Invalid Web login transaction');
  assert.ok(
    html.includes(`data-tx="${transaction}"`),
    'Web entry transaction differs from final login URL',
  );
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
  assert.ok(readFileSync('login.js').byteLength > 0, 'Login JavaScript is empty');
  assert.ok(readFileSync('login.css').byteLength > 0, 'Login stylesheet is empty');
  for (const entry of ['signin', 'vault']) {
    for (const locale of ['ja', 'en'] as const) {
      checkWebSigninPage(
        readFileSync(`web-${entry}-${locale}.html`, 'utf8'),
        locale,
        readFileSync(`web-${entry}-${locale}.url`, 'utf8').trim(),
      );
    }
  }
  console.log('Public Web signin and Vault entries passed in Japanese and English');
}
