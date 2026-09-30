/** Verify public Android association and callback-host isolation. No login credentials. */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

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
console.log('Android signing association and callback-host isolation match the expected configuration');
