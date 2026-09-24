/** Validate public issuer responses fetched by the production smoke workflow. */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const issuer = 'https://mikaki.tossa.app';
assert.equal(readFileSync('health.txt', 'utf8'), 'ok');
const discovery = JSON.parse(readFileSync('discovery.json', 'utf8')) as Record<string, unknown>;
assert.equal(discovery.issuer, issuer);
assert.equal(discovery.jwks_uri, `${issuer}/jwks`);
const jwks = JSON.parse(readFileSync('jwks.json', 'utf8')) as Record<string, unknown>;
assert.ok(Array.isArray(jwks.keys) && jwks.keys.length > 0);
console.log('health, Discovery, and JWKS are publicly reachable');
