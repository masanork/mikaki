import { readFile, writeFile } from 'node:fs/promises';
import { arch, platform, release } from 'node:os';
import { scenarios } from './cases.ts';
import { digest, profile } from './probe.ts';

const installedVersions: Record<string, string> = {};
for (const name of ['@openeudi/openid4vp', '@openeudi/dcql', '@sd-jwt/decode', 'jose']) {
  const pkg: { version: string } = JSON.parse(
    await readFile(new URL(`../node_modules/${name}/package.json`, import.meta.url), 'utf8'),
  );
  installedVersions[name] = pkg.version;
}
if (
  installedVersions['@openeudi/openid4vp'] !== profile.verifierVersion ||
  installedVersions.jose !== '6.2.12'
)
  throw new Error('Probe dependencies do not match the pinned profile');
const lockDigest = digest(await readFile(new URL('../package-lock.json', import.meta.url), 'utf8'));

const results: { id: string; layer: string; passed: boolean }[] = [];
for (const scenario of scenarios) {
  try {
    await scenario.run();
    results.push({ id: scenario.id, layer: scenario.layer, passed: true });
  } catch {
    // No exception strings, credential bytes, disclosures, keys, or request values.
    results.push({ id: scenario.id, layer: scenario.layer, passed: false });
  }
}
const report = {
  generated_at: new Date().toISOString(),
  scope: 'synthetic-component-probe',
  protocol: 'OpenID4VP 1.0 Final (2025-07-09)',
  credential_format: 'SD-JWT RFC 9901 / SD-JWT VC draft-19 subset',
  independent_verifier: { package: '@openeudi/openid4vp', version: profile.verifierVersion },
  installed_versions: installedVersions,
  dependency_lock_sha256: lockDigest,
  issuer_wallet: 'Mikaki fixture harness using jose 6.2.12; not an independent wallet',
  profile,
  issuer_trust: 'Pinned synthetic issuer public JWK plus exact iss; no x509/HAIP claim',
  status_policy: 'Synthetic local digest-keyed status service; good required on every presentation',
  holder_key: 'Disposable dedicated ES256, separate AES-GCM envelope; random in-memory unlock key',
  transport:
    'Web Request/Response form serialization in-process; no network/TLS or browser wallet test',
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
