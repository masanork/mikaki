/** Validate the design policy and local documentation links. */
import { access, readdir, readFile } from 'node:fs/promises';
import { extname, join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ROOT, flatten, policyPath, readToml, revision, validate } from './policy-design.ts';

function requireValue(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

function setKey(data: Record<string, unknown>, path: string, value: unknown) {
  const keys = path.split('.');
  let node = data;
  for (const key of keys.slice(0, -1)) node = node[key] as Record<string, unknown>;
  node[keys.at(-1)!] = value;
}

async function checkLinks(directory: string) {
  const skipped = new Set([
    '.git',
    'node_modules',
    'target',
    'pkg',
    'pkg-web',
    '.wrangler',
    '__pycache__',
  ]);
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (!skipped.has(entry.name)) await checkLinks(join(directory, entry.name));
      continue;
    }
    if (!entry.isFile() || extname(entry.name) !== '.md') continue;
    const path = join(directory, entry.name);
    const text = await readFile(path, 'utf8');
    for (const match of text.matchAll(/\]\(([^)]+)\)/g)) {
      const target = match[1];
      if (target.includes('://') || target.startsWith('#')) continue;
      try {
        await access(resolve(dirname(path), target.split('#')[0]));
      } catch {
        throw new Error(`broken link: ${path}: ${target}`);
      }
    }
  }
}

export async function checkDesign() {
  const policy = await readToml(policyPath());
  const normalized = validate(policy);
  for (const name of await readdir(join(ROOT, 'config'))) {
    if (!name.endsWith('.toml')) continue;
    const part = await readToml(join(ROOT, 'config', name));
    const original = flatten(policy);
    for (const [key, value] of Object.entries(flatten(part))) {
      requireValue(original[key] === value, `${name}: conflicting historical example ${key}`);
    }
  }
  const invalid: Array<[string, unknown]> = [
    ['schema_version', 2],
    ['schema_version', true],
    ['authentication.ceremony_max_failures', 0],
    ['limits.jwt_bytes', true],
    ['limits.jwt_bytes', -1],
    ['limits.json_depth', 65],
    ['limits.header_bytes', 2048],
    ['session.sso_absolute_ttl', '0s'],
    ['session.sso_absolute_ttl', '1h'],
    ['oidc.access_token.ttl', '2m30s'],
    ['oidc.access_token.ttl', '999999999999999999d'],
    ['oidc.validation.clock_skew', 30],
    ['logout_delivery.lease_ttl', '1s'],
    ['logout_delivery.max_delay', '2d'],
    ['signing.prepublish_duration', '1s'],
    ['jwks_fetch.timeout', '1h'],
    ['rate_limit.window', '30s'],
  ];
  for (const [path, value] of invalid) {
    const candidate = structuredClone(policy);
    setKey(candidate, path, value);
    let rejected = false;
    try {
      validate(candidate);
    } catch {
      rejected = true;
    }
    requireValue(rejected, `accepted invalid setting: ${path}`);
  }
  for (const change of ['unknown', 'missing', 'empty_unknown_table']) {
    const candidate = structuredClone(policy);
    if (change === 'unknown') candidate.unexpected = 1;
    else if (change === 'missing')
      delete ((candidate.oidc as Record<string, unknown>).access_token as Record<string, unknown>)
        .ttl;
    else (candidate.oidc as Record<string, unknown>).unknown = {};
    let rejected = false;
    try {
      validate(candidate);
    } catch {
      rejected = true;
    }
    requireValue(rejected, `accepted ${change} key`);
  }
  const equivalent = structuredClone(policy);
  setKey(equivalent, 'oidc.access_token.ttl', '300s');
  requireValue(
    revision(equivalent) === revision(policy),
    'duration normalization changed revision',
  );
  await checkLinks(ROOT);
  return {
    fields: Object.keys(normalized).length,
    invalid: invalid.length + 3,
    revision: revision(policy),
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const result = await checkDesign();
  console.log(
    `OK: ${result.fields} configuration fields; ${result.invalid} invalid configurations rejected; normalized revision stable; local links valid`,
  );
  console.log(`policy_revision=${result.revision}`);
}
