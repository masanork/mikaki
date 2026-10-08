import { readFile, writeFile } from 'node:fs/promises';
import { arch, platform, release } from 'node:os';
import { digest } from '../oid4vp/probe.ts';
import { dpopProfile } from './probe.ts';
import { scenarios } from './cases.ts';
import { networkScenarios } from './network.ts';

const versions: Record<string, string> = {};
for (const name of ['@openid4vc/oauth2', '@openid4vc/openid4vci', '@openeudi/openid4vp', 'jose']) {
  versions[name] = JSON.parse(
    await readFile(new URL(`../node_modules/${name}/package.json`, import.meta.url), 'utf8'),
  ).version;
}
if (versions['@openid4vc/oauth2'] !== dpopProfile.libraryVersion || versions.jose !== '6.2.12')
  throw new Error('Unexpected probe versions');
const results: Array<{ id: string; layer: string; passed: boolean }> = [];
for (const scenario of [...scenarios, ...networkScenarios]) {
  try {
    await scenario.run();
    results.push({ id: scenario.id, layer: scenario.layer, passed: true });
  } catch {
    results.push({ id: scenario.id, layer: scenario.layer, passed: false });
  }
}
const report = {
  generated_at: new Date().toISOString(),
  scope: 'Synthetic DPoP component and loopback HTTPS receipt qualification',
  protocol: 'RFC 9449; FAPI 2.0 Final clock-skew subset only',
  profile: dpopProfile,
  installed_versions: versions,
  dependency_lock_sha256: digest(
    await readFile(new URL('../package-lock.json', import.meta.url), 'utf8'),
  ),
  implementation_sha256: digest(await readFile(new URL('./probe.ts', import.meta.url), 'utf8')),
  network_source_sha256: digest(await readFile(new URL('./network.ts', import.meta.url), 'utf8')),
  verifier:
    'OWF OAuth2 0.7.0 DPoP protocol verification; JOSE signature callback; post-verification bounded in-memory replay gate',
  issuance:
    'DPoP-required wrapper over the anonymous pre-authorized issuer fixture; not client authentication or a FAPI AS',
  transport:
    'Loopback TCP routing for fixed https://issuer.mikaki.test authority; certificate trust and hostname checks enabled; no redirects',
  storage:
    'Disposable sender key, separate credential holder key, original encrypted artifact and holder envelope in memory',
  exclusions: [
    'Product activation',
    'Persistent multi-isolate replay storage',
    'PAR',
    'Confidential client authentication',
    'Complete FAPI 2.0 conformance',
    'Independent issuer/wallet applications',
    'DPoP nonce rotation and persistent retry recovery',
    'Device keys, holder transfer and recovery',
    'Real issuer trust/status',
  ],
  environment: { node: process.version, platform: platform(), release: release(), arch: arch() },
  devices: [],
  results,
  passed: results.every((r) => r.passed),
};
await writeFile(
  new URL('./results-2026-09-29.json', import.meta.url),
  `${JSON.stringify(report, null, 2)}\n`,
);
console.log(
  JSON.stringify({
    passed: report.passed,
    scenarios: results.length,
    network: results.filter((r) => r.layer === 'network').length,
  }),
);
if (!report.passed) process.exitCode = 1;
