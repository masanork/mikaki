import assert from 'node:assert/strict';
import { test } from 'node:test';
import { weaveProfile } from '../../crates/worker/ui/woven-gate.ts';

test('woven material retains its origin-derived profile and canonical URL identity', () => {
  assert.deepEqual(weaveProfile('https://mikaki.org'), {
    hue: 125,
    spacing: 49,
    strip: 0.24,
    aspect: 1.13,
    pattern: 1,
    bend: 0.15444444444444444,
    grainAngle: 4,
  });
  assert.deepEqual(
    weaveProfile('https://mikaki.org:443/path?q=1'),
    weaveProfile('https://mikaki.org'),
  );
  assert.deepEqual(
    weaveProfile('https://例え.テスト'),
    weaveProfile('https://xn--r8jz45g.xn--zckzah'),
  );
  assert.deepEqual(weaveProfile('http://[::1]:80/path'), weaveProfile('http://[::1]'));
  assert.throws(() => weaveProfile('not a URL'), TypeError);
});
