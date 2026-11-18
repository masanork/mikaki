import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

const root = new URL('../', import.meta.url);
const readJson = (path) => JSON.parse(readFileSync(new URL(path, root), 'utf8'));
const exceptions = readJson('.github/dependency-advisory-exceptions.json');
const packages = readJson('package-lock.json').packages;
const scan = spawnSync('npm', ['audit', '--package-lock-only', '--audit-level=low', '--json'], {
  cwd: root,
  encoding: 'utf8',
  maxBuffer: 8 * 1024 * 1024,
});
if (scan.error) throw scan.error;
if (![0, 1].includes(scan.status)) throw new Error('npm audit did not complete');

const report = JSON.parse(scan.stdout);
const findings = Object.entries(report.vulnerabilities ?? {});
if (
  report.error ||
  report.auditReportVersion !== 2 ||
  report.metadata?.vulnerabilities?.total !== findings.length ||
  (scan.status === 0) !== (findings.length === 0)
) {
  throw new Error('Invalid or incomplete npm audit report');
}

const accepted = new Set();
const used = new Set();
let changed;
do {
  changed = false;
  for (const [name, { nodes, via }] of findings) {
    if (
      accepted.has(name) ||
      !nodes?.length ||
      !nodes.every((path) => packages[path]?.dev === true) ||
      !via?.length
    )
      continue;

    const scoped = via.every((cause) => {
      if (typeof cause === 'string') return accepted.has(cause);
      const exception = exceptions.find(
        (entry) =>
          entry.lockfile === 'package-lock.json' &&
          entry.package === name &&
          cause.name === name &&
          cause.url === `https://github.com/advisories/${entry.advisory}` &&
          Date.parse(entry.expires) > Date.now() &&
          nodes.every((path) => packages[path].version === entry.version),
      );
      if (exception) used.add(exception);
      return Boolean(exception);
    });
    if (scoped) {
      accepted.add(name);
      changed = true;
    }
  }
} while (changed);

for (const exception of exceptions) {
  if (exception.lockfile === 'package-lock.json' && !used.has(exception)) {
    console.error(`Unused root npm exception: ${exception.advisory}`);
    process.exitCode = 1;
  }
}

for (const [name] of findings) {
  if (accepted.has(name)) console.warn(`Scoped development npm finding: ${name}`);
  else {
    console.error(`Blocking npm finding: ${name}`);
    process.exitCode = 1;
  }
}
