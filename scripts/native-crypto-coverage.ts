/** Measure the exact boundary on Node's independent native provider, not workerd coverage. */
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';

const boundaries = {
  claim: {
    source: 'crates/userinfo-claim-worker/src/native_crypto.ts',
    test: 'local/conformance/claim-native-crypto-node.test.mjs',
    prefix: 'claim-crypto-coverage',
  },
  oidc: {
    source: 'crates/oidc/src/native_es256.ts',
    test: 'local/conformance/oidc-native-crypto-node.test.mjs',
    prefix: 'oidc-crypto-coverage',
  },
};
const requested = process.argv[2];
assert.ok(process.argv.length <= 3 && (!requested || Object.hasOwn(boundaries, requested)));
const selected = requested
  ? [boundaries[requested as keyof typeof boundaries]]
  : Object.values(boundaries);
await mkdir('artifacts', { recursive: true });
for (const { source, test, prefix } of selected) {
  execFileSync(
    process.execPath,
    [
      '--experimental-test-coverage',
      '--test',
      `--test-coverage-include=**/${source}`,
      '--test-reporter=spec',
      '--test-reporter-destination=stdout',
      '--test-reporter=lcov',
      `--test-reporter-destination=artifacts/${prefix}.lcov`,
      test,
    ],
    { stdio: 'inherit' },
  );
  const lcov = await readFile(`artifacts/${prefix}.lcov`, 'utf8');
  assert.deepEqual(
    [...lcov.matchAll(/^SF:(.+)$/gm)].map((match) => match[1]),
    [source],
  );
  const count = (key: string) => Number(new RegExp(`^${key}:(\\d+)$`, 'm').exec(lcov)?.[1] ?? 0);
  const lines = { found: count('LF'), hit: count('LH') };
  const branches = { found: count('BRF'), hit: count('BRH') };
  assert.ok(lines.found > 0 && lines.hit / lines.found >= 0.95, 'Native boundary line floor: 95%');
  assert.ok(
    branches.found > 0 && branches.hit / branches.found >= 0.9,
    'Native boundary branch floor: 90%',
  );
  await writeFile(
    `artifacts/${prefix}.json`,
    JSON.stringify(
      {
        measuredAt: new Date().toISOString(),
        node: process.version,
        scope:
          'Exact bridge source on Node native Web Crypto; workerd behavior is qualified separately',
        source,
        sha256: createHash('sha256')
          .update(await readFile(source))
          .digest('hex'),
        lines,
        branches,
      },
      null,
      2,
    ) + '\n',
  );
}
