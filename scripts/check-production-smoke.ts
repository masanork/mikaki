/** Validate public issuer responses fetched by the production smoke workflow. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';

const issuer = 'https://mikaki.tossa.app';
assert.equal(readFileSync('health.txt', 'utf8'), 'ok');
const discovery = JSON.parse(readFileSync('discovery.json', 'utf8')) as Record<string, unknown>;
assert.equal(discovery.issuer, issuer);
assert.equal(discovery.jwks_uri, `${issuer}/jwks`);
const jwks = JSON.parse(readFileSync('jwks.json', 'utf8')) as Record<string, unknown>;
assert.ok(Array.isArray(jwks.keys) && jwks.keys.length > 0);
const expectedVersion = process.env.MIKAKI_EXPECTED_VERSION_ID?.trim();
const expectedCommit = process.env.MIKAKI_EXPECTED_SOURCE_COMMIT?.trim();
const expectedJs = process.env.MIKAKI_EXPECTED_LOGIN_JS_SHA256?.trim();
const expectedCss = process.env.MIKAKI_EXPECTED_LOGIN_CSS_SHA256?.trim();
let loginAssets: { js_sha256: string; css_sha256: string } | undefined;
if (expectedJs || expectedCss) {
  assert.ok(expectedVersion && expectedCommit, 'login asset checks require runtime identity');
  assert.ok(expectedJs && expectedCss, 'both login asset hashes must be supplied');
  assert.match(expectedJs, /^[a-f0-9]{64}$/i);
  assert.match(expectedCss, /^[a-f0-9]{64}$/i);
  const digest = (file: string) => createHash('sha256').update(readFileSync(file)).digest('hex');
  loginAssets = { js_sha256: digest('login.js'), css_sha256: digest('login.css') };
  assert.equal(
    loginAssets.js_sha256,
    expectedJs.toLowerCase(),
    'login JavaScript differs from reviewed build',
  );
  assert.equal(
    loginAssets.css_sha256,
    expectedCss.toLowerCase(),
    'login stylesheet differs from reviewed build',
  );
}
assert.equal(
  Boolean(expectedVersion),
  Boolean(expectedCommit),
  'expected version and commit must be supplied together',
);
if (expectedVersion && expectedCommit) {
  assert.match(expectedVersion, /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i);
  assert.match(expectedCommit, /^[0-9a-f]{40}$/i);
  const version = JSON.parse(readFileSync('version.json', 'utf8')) as Record<string, unknown>;
  assert.equal(version.worker, 'mikaki-op');
  assert.equal(version.version_id, expectedVersion);
  assert.equal(version.source_commit, expectedCommit);
  assert.equal(version.source_clean, true);
  assert.equal(readFileSync('ready-status.txt', 'utf8').trim(), '204');
  mkdirSync('artifacts', { recursive: true });
  writeFileSync(
    'artifacts/production-smoke.json',
    `${JSON.stringify({ issuer, checked_at: new Date().toISOString(), version_id: expectedVersion, source_commit: expectedCommit, health: 'ok', discovery: 'ok', jwks: 'ok', readiness: 'ok', ...(loginAssets ? { login_assets: loginAssets } : {}) }, null, 2)}\n`,
  );
  console.log(
    `public endpoints match Worker version ${expectedVersion} and commit ${expectedCommit}`,
  );
} else {
  console.log(
    'health, Discovery, and JWKS are publicly reachable; runtime provenance was not checked',
  );
}
