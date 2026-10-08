import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));

export function upstreamPins() {
  const source = (file: string) => readFileSync(resolve(root, file), 'utf8');
  const match = (file: string, pattern: RegExp) => {
    const value = source(file).match(pattern)?.[1];
    if (!value) throw new Error(`Missing upstream pin in ${file}`);
    return value;
  };
  const directory = 'services/android-attestation-verifier';
  const revisions = [
    match(`${directory}/settings.gradle.kts`, /check\(revision == "([a-f0-9]{40})"\)/),
    match(`${directory}/Dockerfile`, /checkout --detach ([a-f0-9]{40})/),
    match(
      `${directory}/src/main/kotlin/app/mikaki/attestation/Policy.kt`,
      /const val REVISION = "([a-f0-9]{40})"/,
    ),
  ];
  if (new Set(revisions).size !== 1)
    throw new Error('Verifier build, container and policy source pins differ');
  const rsa = ['crates/webauthn', 'crates/identity', 'design/probes/jose-custom'].map((directory) =>
    match(`${directory}/Cargo.toml`, /^rsa\s*=\s*\{\s*version\s*=\s*"=([^"]+)"/m),
  );
  if (new Set(rsa).size !== 1) throw new Error('RSA versions differ across verification providers');
  return { keyattestation: revisions[0], rsa: rsa[0] };
}

async function publishedMetadata(url: string, github = false): Promise<unknown> {
  const headers: Record<string, string> = { 'User-Agent': 'mikaki-upstream-pins' };
  if (github && process.env.GH_TOKEN) headers.Authorization = `Bearer ${process.env.GH_TOKEN}`;
  const response = await fetch(url, { headers, signal: AbortSignal.timeout(15000) });
  if (!response.ok) throw new Error(`Upstream metadata request failed: ${response.status} ${url}`);
  return response.json();
}

async function review(pins: ReturnType<typeof upstreamPins>) {
  const commit = (await publishedMetadata(
    'https://api.github.com/repos/android/keyattestation/commits/main',
    true,
  )) as { sha?: unknown };
  const registry = (await publishedMetadata('https://crates.io/api/v1/crates/rsa')) as {
    crate?: { max_stable_version?: unknown };
  };
  if (typeof commit.sha !== 'string' || !/^[a-f0-9]{40}$/.test(commit.sha))
    throw new Error('Invalid upstream verifier revision');
  const latestRsa = registry.crate?.max_stable_version;
  if (typeof latestRsa !== 'string' || !/^\d+\.\d+\.\d+$/.test(latestRsa))
    throw new Error('Invalid published RSA version');
  const release = pins.rsa.match(/^(\d+)\.(\d+)\.(\d+)-/);
  const available = latestRsa.split('.').map(Number);
  const stableAvailable =
    (release &&
      available.some(
        (part, index) =>
          part > Number(release[index + 1]) &&
          available.slice(0, index).every((prefix, i) => prefix === Number(release[i + 1])),
      )) ||
    (release && available.every((part, index) => part === Number(release[index + 1])));
  const report = {
    pinned: pins,
    published: { keyattestation: commit.sha, rsaStable: latestRsa },
    review: {
      keyattestation: commit.sha !== pins.keyattestation,
      rsaStable: Boolean(stableAvailable),
    },
  };
  console.log(JSON.stringify(report, null, 2));
  if (report.review.keyattestation || report.review.rsaStable)
    throw new Error(
      'A new verifier source revision or RSA stable release is available; review and qualify the pin update',
    );
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const arguments_ = process.argv.slice(2);
  if (
    arguments_.length > 1 ||
    arguments_.some((argument) => !['--revision', '--remote'].includes(argument))
  )
    throw new Error('Usage: node scripts/check-upstream-pins.ts [--revision|--remote]');
  const pins = upstreamPins();
  if (arguments_[0] === '--revision') console.log(pins.keyattestation);
  else if (arguments_[0] === '--remote') await review(pins);
  else console.log(JSON.stringify(pins));
}
