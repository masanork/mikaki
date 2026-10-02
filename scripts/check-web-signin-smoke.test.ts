import assert from 'node:assert/strict';
import { test } from 'node:test';
import { checkWebSigninPage } from './check-web-signin-smoke.ts';

function page(locale: 'ja' | 'en') {
  return `<html lang="${locale}"><div data-owner-login="true" data-enrollment="false"
    data-rp-id="auth.mikaki.org" data-rp-uri="https://auth.mikaki.org/vault?lang=${locale}"
    data-tx="${'t'.repeat(43)}" data-challenge="${'c'.repeat(43)}"></div>
    <script type="module" src="/login/login.js"></script></html>`;
}

test('public Web entry checks reject locale, RP, and transaction regressions', () => {
  for (const locale of ['ja', 'en'] as const) {
    const html = page(locale);
    checkWebSigninPage(html, locale);
    for (const invalid of [
      html.replace(`<html lang="${locale}">`, '<html lang="other">'),
      html.replace('data-owner-login="true"', 'data-owner-login="false"'),
      html.replace('data-enrollment="false"', 'data-enrollment="true"'),
      html.replace('data-rp-id="auth.mikaki.org"', 'data-rp-id="old.example"'),
      html.replace('/vault?lang=', '/oidc/native/callback?lang='),
      html.replace('data-tx="', 'data-missing-tx="'),
      html.replace('data-challenge="', 'data-missing-challenge="'),
      html.replace('/login/login.js', '/missing.js'),
    ]) {
      assert.throws(() => checkWebSigninPage(invalid, locale));
    }
  }
});
