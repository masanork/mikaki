import { readFile, writeFile } from 'node:fs/promises';
import { arch, platform, release } from 'node:os';
import { digest } from '../oid4vp/probe.ts';
import { scenarios } from './cases.ts';
import { profile } from './probe.ts';

const versions: Record<string, string> = {};
for (const name of [
  '@openid4vc/openid4vci',
  '@openid4vc/oauth2',
  '@openid4vc/utils',
  '@openeudi/openid4vp',
  'jose',
]) {
  const pkg: { version: string } = JSON.parse(
    await readFile(new URL(`../node_modules/${name}/package.json`, import.meta.url), 'utf8'),
  );
  versions[name] = pkg.version;
}
if (
  versions['@openid4vc/openid4vci'] !== profile.issuerLibraryVersion ||
  versions.jose !== '6.2.12'
)
  throw new Error('Probe dependencies do not match the pinned profile');
const results: { id: string; layer: string; passed: boolean }[] = [];
for (const scenario of scenarios) {
  try {
    await scenario.run();
    results.push({ id: scenario.id, layer: scenario.layer, passed: true });
  } catch {
    results.push({ id: scenario.id, layer: scenario.layer, passed: false });
  }
}
const report = {
  generated_at: new Date().toISOString(),
  scope: 'synthetic-component-probe',
  protocol: 'OpenID4VCI 1.0 Final (2025-09-16)',
  flow: 'Anonymous Pre-Authorized Code with separate six-digit tx_code; immediate single dc+sd-jwt credential',
  profile,
  installed_versions: versions,
  dependency_lock_sha256: digest(
    await readFile(new URL('../package-lock.json', import.meta.url), 'utf8'),
  ),
  independent_issuer:
    'OWF @openid4vc/openid4vci protocol library; JOSE callback, code/token/nonce ledgers and SD-JWT signing are Mikaki fixtures',
  wallet: 'Mikaki receipt harness and shared encrypted OID4VP fixture store',
  holder:
    'Dedicated disposable ES256 key, public jwk proof and separately encrypted private-key envelope',
  transport:
    'In-process Web Request/Response with HTTPS .test endpoints; no network/TLS or external application test',
  trust: 'Exact synthetic issuer and pinned public JWK; no public issuer trust/discovery claim',
  environment: { node: process.version, platform: platform(), release: release(), arch: arch() },
  devices: [],
  results,
  passed: results.every((r) => r.passed),
};
await writeFile(
  new URL('./results-2026-09-29.json', import.meta.url),
  JSON.stringify(report, null, 2) + '\n',
);
console.log(JSON.stringify({ passed: report.passed, scenarios: results.length }));
if (!report.passed) process.exitCode = 1;
