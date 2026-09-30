// Export allow-listed result fields only; raw suite logs are never read here.
import { readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { generated, type ModuleResult } from './suite.ts';

const [basicId, configId, ...followups] = process.argv.slice(2);
if (
  !basicId ||
  !configId ||
  [basicId, configId, ...followups].some((id) => !/^[A-Za-z0-9]+$/.test(id))
)
  throw new Error(
    'Usage: node design/probes/oidf/report.ts BASIC_PLAN CONFIG_PLAN [BASIC_FOLLOWUP_PLANS...]',
  );
async function rows(id: string): Promise<ModuleResult[]> {
  const input = JSON.parse(
    await readFile(new URL(`oidf-passkey-summary-${id}.json`, generated), 'utf8'),
  );
  return input.map((r: ModuleResult) => ({
    name: r.name,
    id: r.id,
    status: r.status,
    result: r.result,
  }));
}
const basicInitial = await rows(basicId);
const runs = [{ planId: basicId, results: basicInitial }];
const effective = new Map(basicInitial.map((row) => [row.name, { ...row, planId: basicId }]));
for (const id of followups) {
  const results = await rows(id);
  if (results.some((row) => !effective.has(row.name)))
    throw new Error('Followup module outside Basic plan');
  runs.push({ planId: id, results });
  for (const row of results) effective.set(row.name, { ...row, planId: id });
}
const count = (results: ModuleResult[]) =>
  results.reduce<Record<string, number>>((counts, row) => {
    const result = row.status === 'FINISHED' ? (row.result ?? 'UNFINISHED') : 'UNFINISHED';
    counts[result] = (counts[result] ?? 0) + 1;
    return counts;
  }, {});
const vci = JSON.parse(
  await readFile(new URL('oidf-vci-metadata-summary.json', generated), 'utf8'),
);
const vp = JSON.parse(await readFile(new URL('oidf-vp-component-summary.json', generated), 'utf8'));
if (vci.suite.revision !== vp.suite.revision) throw new Error('Credential suite revisions differ');
const hash = async (path: string) =>
  createHash('sha256')
    .update(await readFile(new URL(path, import.meta.url)))
    .digest('hex');
const libraries = {} as Record<string, string>;
for (const name of ['@openeudi/openid4vp', '@openid4vc/openid4vci', 'jose']) {
  const pkg = JSON.parse(
    await readFile(new URL(`../node_modules/${name}/package.json`, import.meta.url), 'utf8'),
  );
  libraries[name] = pkg.version;
}
const configResults = await rows(configId);
const report = {
  generatedAt: new Date().toISOString(),
  environment: { node: process.version, platform: process.platform },
  suite: vci.suite,
  libraries,
  fingerprints: {
    workerWasmSha256: await hash('../../../crates/worker/build/index_bg.wasm'),
    workerJsSha256: await hash('../../../crates/worker/build/index.js'),
    probeLockSha256: await hash('../package-lock.json'),
  },
  oidc: {
    scope: 'Current Rust Worker/workerd, ephemeral D1, local HTTPS, Chromium virtual passkey',
    basic: {
      originalPlanId: basicId,
      variant: { server_metadata: 'discovery', client_registration: 'static_client' },
      runs,
      effectiveCounts: count([...effective.values()]),
      effectiveResults: [...effective.values()],
    },
    config: { planId: configId, results: configResults, counts: count(configResults) },
  },
  oid4vci: {
    scope: vci.scope,
    planId: vci.planId,
    exclusions: vci.exclusions,
    results: vci.results.map((r: ModuleResult) => ({
      name: r.name,
      id: r.id,
      status: r.status,
      result: r.result,
    })),
  },
  oid4vp: {
    scope: vp.scope,
    planId: vp.planId,
    profile: vp.profile,
    exclusions: vp.exclusions,
    results: vp.results.map(
      (
        r: ModuleResult & {
          decision: boolean | null;
          expectedAcceptance: boolean;
          expectationMet: boolean;
        },
      ) => ({
        name: r.name,
        id: r.id,
        status: r.status,
        result: r.result,
        decision: r.decision,
        expectedAcceptance: r.expectedAcceptance,
        expectationMet: r.expectationMet,
      }),
    ),
    counts: count(vp.results),
  },
  certification: false,
  reviewPolicy:
    'REVIEW means screenshot uploaded and awaiting human review; WARNING and SKIPPED are not PASSED. Followups do not replace original evidence.',
  externalWalletApplicationTested: false,
};
const file = new URL(`results-${new Date().toISOString().slice(0, 10)}.json`, import.meta.url);
await writeFile(file, `${JSON.stringify(report, null, 2)}\n`);
console.log(
  JSON.stringify(
    {
      basic: report.oidc.basic.effectiveCounts,
      config: report.oidc.config.counts,
      vci: count(report.oid4vci.results),
      vp: report.oid4vp.counts,
    },
    null,
    2,
  ),
);
if (
  [
    ...effective.values(),
    ...configResults,
    ...report.oid4vci.results,
    ...report.oid4vp.results,
  ].some(
    (r) =>
      r.status !== 'FINISHED' ||
      !['PASSED', 'REVIEW', 'WARNING', 'SKIPPED'].includes(r.result ?? ''),
  ) ||
  report.oid4vp.results.some((r: { expectationMet: boolean }) => !r.expectationMet)
)
  process.exitCode = 1;
