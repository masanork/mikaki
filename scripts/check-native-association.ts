/** Verify public Android association and callback-host isolation. No login credentials. */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash, randomBytes } from 'node:crypto';

const fingerprint = process.env.MIKAKI_EXPECTED_ANDROID_FINGERPRINT;
assert.ok(fingerprint && /^(?:[0-9A-F]{2}:){31}[0-9A-F]{2}$/.test(fingerprint));
assert.deepEqual(JSON.parse(readFileSync('assetlinks.json', 'utf8')), [
  {
    relation: ['delegate_permission/common.handle_all_urls'],
    target: {
      namespace: 'android_app',
      package_name: 'app.tossa.mikaki',
      sha256_cert_fingerprints: [fingerprint],
    },
  },
]);
assert.equal(readFileSync('native-callback-status.txt', 'utf8').trim(), '404');
assert.equal(readFileSync('native-authorize-status.txt', 'utf8').trim(), '404');
const headers = readFileSync('native-callback-headers.txt', 'utf8');
assert.match(headers, /^cache-control:.*\bno-store\b/im);
assert.match(headers, /^referrer-policy:\s*no-referrer\s*$/im);
console.log(
  'Android signing association and callback-host isolation match the expected configuration',
);

// Start one unauthenticated login transaction to qualify the registration.
// Do not follow the browser redirect, authenticate, or exchange any code.
const registration = JSON.parse(
  readFileSync('apps/mikaki-client/mobile-client-registration.json', 'utf8'),
);
const issuer = 'https://mikaki.tossa.app';
const authorize = new URL(`${issuer}/authorize`);
const random = () => randomBytes(32).toString('base64url');
for (const [name, value] of Object.entries({
  response_type: 'code',
  client_id: registration.client_id,
  redirect_uri: registration.redirect_uris[0],
  scope: 'openid',
  state: random(),
  nonce: random(),
  code_challenge: createHash('sha256').update(random()).digest('base64url'),
  code_challenge_method: 'S256',
}))
  authorize.searchParams.set(name, value as string);
const response = await fetch(authorize, {
  redirect: 'manual',
  signal: AbortSignal.timeout(30_000),
});
assert.equal(response.status, 302, 'registered native client must reach browser login');
const location = new URL(response.headers.get('location')!);
assert.equal(location.origin, issuer);
assert.equal(location.pathname, '/login');
assert.ok(location.searchParams.get('tx'));
console.log('Registered mobile public client reaches the OP browser login with S256 PKCE');
